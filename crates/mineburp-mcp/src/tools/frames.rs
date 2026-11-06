//! Working on frames without touching the network: decode, rewrite, lookup.

use std::fmt::Write as _;

use mineburp_core::{Direction, PacketEdit, ProtocolState};
use mineburp_protocol::{
    PacketRegistry, apply_edits, inspect_logical, layout_logical, registry_entry, registry_keys,
};

use super::{
    Args, Ctx, Frame, Tool, ToolResult, blocking, boolean, choice, edits_schema, integer, object,
    set_schema, string,
};
use crate::render::{self, TreeLimits};

const MAX_REGISTRY_SCAN: i64 = 200_000;

pub fn tools() -> Vec<Tool> {
    let frame_properties = || {
        vec![
            (
                "hex_limit",
                super::integer("maximum output bytes, default 512, maximum 65536"),
            ),
            ("hex", string("logical frame hex: packet-id VarInt + body")),
            (
                "packet",
                integer("history id to load the frame (and its state/dir/protocol) from"),
            ),
            (
                "state",
                choice(
                    &[
                        "handshake",
                        "status",
                        "login",
                        "configuration",
                        "play",
                        "opaque",
                    ],
                    "default play",
                ),
            ),
            ("dir", choice(&["c2s", "s2c"], "default c2s")),
            (
                "protocol",
                string("protocol number or release, e.g. 767 or 1.21.1"),
            ),
        ]
    };
    let mut decode_properties = frame_properties();
    decode_properties.extend([
        ("layout", boolean("list editable field spans")),
        ("path", string("dotted path into fields")),
        ("max_lines", integer("default 120")),
    ]);
    let mut rewrite_properties = frame_properties();
    rewrite_properties.extend([
        ("edits", edits_schema()),
        ("set", set_schema()),
        (
            "fields",
            boolean("show the rewritten frame's decoded fields"),
        ),
    ]);
    vec![
        Tool {
            name: "decode",
            description: "Decode an arbitrary frame (hex) or re-decode a stored one under a different state/direction/protocol.",
            schema: object(&decode_properties, &[]),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "rewrite",
            description: "Apply edits to a frame without sending it; returns the new hex and its decode. Field edits re-encode length prefixes. Use before `repeater` send, `intercept` forward, or `rules` add.",
            schema: object(&rewrite_properties, &[]),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "protocol",
            description: "Protocol reference: list versions (optionally matching `query`), a version's packet id table for a state/direction, or registry names (item, block_state, entity_type, sound_event, …) by id or name search.",
            schema: object(
                &[
                    (
                        "query",
                        string(
                            "version or protocol to show, or substring to filter the version list",
                        ),
                    ),
                    (
                        "table",
                        boolean("list packet ids for `state`/`dir` of the version in `query`"),
                    ),
                    (
                        "state",
                        choice(
                            &["handshake", "status", "login", "configuration", "play"],
                            "for table, default play",
                        ),
                    ),
                    (
                        "dir",
                        choice(&["c2s", "s2c"], "for table; both when omitted"),
                    ),
                    (
                        "registry",
                        string("registry key; omit with `query` set to list keys"),
                    ),
                    ("id", integer("registry id to name")),
                    ("name", string("substring to search registry names")),
                ],
                &[],
            ),
            read_only: true,
            destructive: false,
        },
    ]
}

pub async fn decode(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let frame = ctx.frame_from(args).await?;
    let limits = TreeLimits {
        max_lines: args.usize("max_lines").unwrap_or(120).clamp(5, 2_000),
        ..TreeLimits::default()
    };
    let with_layout = args.flag("layout");
    let path = args.str("path").map(str::to_owned);
    blocking(move || Ok(describe(&frame, limits, path.as_deref(), with_layout, true))).await
}

fn describe(
    frame: &Frame,
    limits: TreeLimits,
    path: Option<&str>,
    with_layout: bool,
    with_fields: bool,
) -> String {
    let mut insight = inspect_logical(frame.state, frame.direction, &frame.bytes, frame.protocol);
    if !with_fields {
        insight.fields = None;
    }
    let mut out = format!(
        "{} {} {}B{}",
        render::dir(frame.direction),
        render::state(frame.state),
        frame.bytes.len(),
        frame
            .protocol
            .map(|protocol| format!(" p{protocol}"))
            .unwrap_or_default()
    );
    out.push('\n');
    out.push_str(&render::insight(&insight, limits, path));
    if with_layout {
        let layout = layout_logical(frame.state, frame.direction, &frame.bytes, frame.protocol);
        out.push('\n');
        out.push_str(&render::layout(&layout.fields, layout.complete, limits));
    }
    out
}

/// Applies edits, returning the rewritten frame.
pub fn apply(frame: &Frame, edits: &[PacketEdit]) -> Result<Vec<u8>, String> {
    if edits.is_empty() {
        return Ok(frame.bytes.clone());
    }
    apply_edits(
        frame.state,
        frame.direction,
        frame.protocol,
        &frame.bytes,
        edits,
    )
    .map_err(|error| error.to_string())
}

pub async fn rewrite(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let frame = ctx.frame_from(args).await?;
    let edits = args.edits()?;
    if edits.is_empty() {
        return Err("give `edits` or `set`".into());
    }
    let hex_limit = args.usize("hex_limit").unwrap_or(512).min(65536);
    let with_fields = args.flag("fields");
    blocking(move || {
        let rewritten = apply(&frame, &edits)?;
        let changes = render::changed_ranges(&frame.bytes, &rewritten);
        let before = frame.bytes.len();
        let after = Frame {
            bytes: rewritten,
            ..frame
        };
        let mut out = format!(
            "{} edit(s): {before}B → {}B\nhex: {}\n",
            edits.len(),
            after.bytes.len(),
            render::capped_hex(&after.bytes, hex_limit)
        );
        out.push_str(&changes);
        out.push_str(&describe(
            &after,
            TreeLimits::default(),
            None,
            false,
            with_fields,
        ));
        Ok(out)
    })
    .await
}

pub fn protocol(args: &Args) -> ToolResult {
    let registry = PacketRegistry::bundled();
    let versions = registry.supported_protocols();
    let query = args.str("query");
    let resolved = query.and_then(super::resolve_protocol);

    if let Some(key) = args.str("registry") {
        let protocol = resolved
            .or_else(|| versions.last().map(|version| version.protocol))
            .ok_or("no protocol")?;
        if let Some(id) = args.i64("id") {
            return registry_entry(protocol, key, id, None)
                .map(|entry| format!("p{protocol} {key} {id} = {}", entry.name))
                .ok_or_else(|| format!("p{protocol} has no {key} id {id}"));
        }
        let needle = args.require_str("name")?.to_ascii_lowercase();
        let mut found = Vec::new();
        let mut misses = 0;
        for id in 0..MAX_REGISTRY_SCAN {
            let Some(entry) = registry_entry(protocol, key, id, None) else {
                misses += 1;
                if misses > 256 {
                    break;
                }
                continue;
            };
            misses = 0;
            if entry.name.to_ascii_lowercase().contains(&needle) {
                found.push(format!("{id} {}", entry.name));
                if found.len() >= 40 {
                    found.push("… (first 40)".into());
                    break;
                }
            }
        }
        if found.is_empty() {
            return Err(format!(
                "no {key} name contains `{needle}` in p{protocol} (keys: see `protocol` query={protocol})"
            ));
        }
        return Ok(format!("p{protocol} {key}:\n{}", found.join("\n")));
    }

    if args.flag("table") {
        let protocol = resolved.ok_or("`table` needs `query` set to a version or protocol")?;
        let state = args.state("state")?.unwrap_or(ProtocolState::Play);
        let directions = match args.direction("dir")? {
            Some(direction) => vec![direction],
            None => vec![Direction::ClientToServer, Direction::ServerToClient],
        };
        let mut out = format!("p{protocol} {} packet ids", render::state(state));
        if !PacketRegistry::is_tabulated(state, Some(protocol))
            && matches!(state, ProtocolState::Configuration | ProtocolState::Play)
        {
            out.push_str(
                " (no generated table for this protocol; play/config packets are named by shape)",
            );
        }
        for direction in directions {
            let entries: Vec<String> = (0..=0xff)
                .filter_map(|id| {
                    registry
                        .packet_name(state, direction, id, Some(protocol))
                        .map(|name| format!("{id:02x} {name}"))
                })
                .collect();
            let _ = write!(out, "\n{}: {}", render::dir(direction), entries.join(", "));
        }
        return Ok(out);
    }

    if let Some(protocol) = resolved
        && let Some(version) = versions.iter().find(|version| version.protocol == protocol)
    {
        let mut out = format!(
            "p{} = {} (releases: {})",
            version.protocol,
            version.canonical,
            version.releases.join(", ")
        );
        if let Some(source) = PacketRegistry::table_source(protocol) {
            let _ = write!(out, "\npacket table: {source}");
        }
        let keys = registry_keys(protocol);
        if !keys.is_empty() {
            let _ = write!(out, "\nregistries: {}", keys.join(" "));
        }
        return Ok(out);
    }

    let needle = query.unwrap_or("");
    let list: Vec<String> = versions
        .iter()
        .filter(|version| {
            needle.is_empty()
                || version.canonical.contains(needle)
                || version
                    .releases
                    .iter()
                    .any(|release| release.contains(needle))
        })
        .map(|version| format!("{} {}", version.protocol, version.releases.join("/")))
        .collect();
    if list.is_empty() {
        return Err(format!("no version matches `{needle}`"));
    }
    Ok(list.join("; "))
}
