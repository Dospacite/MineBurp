//! Reading the history: status, packets, connections, stats, annotations.

use std::{collections::HashMap, fmt::Write as _, time::Duration};

use mineburp_core::FilterField;
use mineburp_project::{PacketAnnotation, SavedFilter, StatsOptions};
use mineburp_protocol::{PacketRegistry, inspect_logical, layout_logical};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{
    Args, Ctx, MAX_FRAME, Tool, ToolResult, blocking, boolean, check_packet_arguments, choice,
    filter_map, filter_ref, integer, object, string, strings,
};
use crate::{
    ops,
    render::{self, TreeLimits},
};

const MAX_WAIT_MS: u64 = 60_000;

fn filter_properties() -> Vec<(&'static str, Value)> {
    vec![
        (
            "expr",
            string(
                "`field op value` joined by && / ||. fields: source direction state protocol id name channel loader size disposition connection; ops == != > >= < <= ~(contains). e.g. `state == play && name ~ chat`",
            ),
        ),
        ("search", string("text search over row metadata")),
        ("search_regex", boolean("")),
        ("search_case", boolean("")),
        ("search_not", boolean("exclude matches")),
        (
            "content",
            string("payload search; one term per line; hex terms may be ranges `0c-0f`"),
        ),
        ("content_mode", choice(&["text", "hex", "regex"], "")),
        (
            "content_scope",
            choice(&["contains", "equals", "prefix", "suffix"], ""),
        ),
        ("content_case", boolean("")),
        ("content_not", boolean("exclude matches")),
        ("dir", choice(&["c2s", "s2c"], "")),
        ("states", strings("")),
        ("sources", strings("minecraft|side_channel")),
        ("dispositions", strings("")),
        ("names", strings("name substrings to keep")),
        ("exclude_names", strings("name substrings to drop")),
        ("min_size", integer("")),
        ("max_size", integer("")),
        ("connection", string("id or prefix")),
        ("bookmarked", boolean("")),
        ("saved", string("saved filter name/id as the base")),
    ]
}

pub fn tools() -> Vec<Tool> {
    let mut packets_properties = filter_properties();
    packets_properties.extend([
        ("limit", integer("rows, default 40, max 500")),
        ("before", integer("cursor: rows with id < before (older page)")),
        ("after", integer("cursor: rows with id > after (newer page)")),
        ("wait_ms", integer("with `after` (or alone: from now), wait up to this long for new matching rows; max 60000")),
        ("summaries", boolean("append each packet's one-line decoded summary (slower; ≤100 rows)")),
    ]);
    vec![
        Tool {
            name: "status",
            description: "Overview: mode, open project, capture, decrypt mode, live sessions, intercept queue, rules, network shaping.",
            schema: object(&[], &[]),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "packets",
            description: "Query packet history (database-side filters). One line per packet, oldest→newest: `#id time dir state 0xid name size [disposition] c=conn ch=channel`. Prints paging cursors.",
            schema: object(&packets_properties, &[]),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "packet",
            description: "One packet: metadata, annotation, decoded fields (decoded now, with schema packs), hex. Use `path` to drill into a large decode, `layout` for editable field offsets.",
            schema: object(
                &[
                    ("id", integer("packet row id")),
                    ("hex", choice(&["plain", "dump", "none"], "default plain")),
                    ("hex_offset", integer("first byte shown")),
                    ("hex_limit", integer("bytes shown, default 256, max 65536")),
                    (
                        "layout",
                        boolean("list editable field spans (offset, length, kind)"),
                    ),
                    (
                        "path",
                        string("dotted path into fields, e.g. `entries.0.name`"),
                    ),
                    ("raw", boolean("fields as compact JSON instead of a tree")),
                    ("max_lines", integer("field lines, default 120")),
                    ("max_items", integer("array items shown, default 16")),
                ],
                &["id"],
            ),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "connections",
            description: "Connections in the project plus live decrypted sessions (marked LIVE), busiest first. `close` ends a live session. action=compare with a,b aligns recorded sessions; filter scopes both sides, limit bounds text differences, format=json returns rows and per-name counts.",
            schema: object(
                &[
                    ("action", string("list or compare")),
                    ("a", string("connection A id")),
                    ("b", string("connection B id")),
                    ("filter", filter_ref()),
                    ("limit", integer("default 50")),
                    ("live", boolean("only live sessions")),
                    (
                        "close",
                        string("connection id/prefix of a live session to close"),
                    ),
                ],
                &[],
            ),
            read_only: false,
            destructive: true,
        },
        Tool {
            name: "stats",
            description: "Traffic statistics for a filter: totals per direction, time span, top packet names by count and bytes, top connections, size histogram, optional timeline.",
            schema: object(
                &[
                    ("filter", filter_ref()),
                    ("top", integer("ranking length, default 10")),
                    ("timeline", boolean("include a per-bucket timeline")),
                    ("buckets", integer("timeline buckets, default 24")),
                ],
                &[],
            ),
            read_only: true,
            destructive: false,
        },
        Tool {
            name: "annotate",
            description: "Bookmark, colour, or note packets (action=set, the default when ids are given), or list annotations (action=list). Unset keys keep their current value; note=\"\" clears.",
            schema: object(
                &[
                    ("action", choice(&["set", "list"], "")),
                    ("id", integer("packet id")),
                    (
                        "ids",
                        json!({ "type": "array", "items": { "type": "integer" }, "description": "several packet ids" }),
                    ),
                    ("bookmark", boolean("")),
                    (
                        "color",
                        string("#rrggbb or red|amber|green|blue|purple; \"\" clears"),
                    ),
                    ("note", string("")),
                    ("limit", integer("list size, default 100")),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
        Tool {
            name: "filters",
            description: "Filter language help (action=help), validate an expression, or manage saved filters shared with the UI (list|save|delete).",
            schema: object(
                &[
                    (
                        "action",
                        choice(
                            &["help", "validate", "list", "save", "delete"],
                            "default help",
                        ),
                    ),
                    ("expr", string("expression to validate")),
                    ("name", string("saved filter name (save)")),
                    (
                        "id",
                        string("saved filter id/prefix (save to update, delete)"),
                    ),
                    ("filter", filter_ref()),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
    ]
}

pub async fn status(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let host = ctx.host;
    if args.str("format") == Some("json") {
        return Ok(json!({"mode":host.mode(),"temporary":host.project_is_temporary(),"project":host.project().map(|store| json!({"name":store.info().name,"path":store.info().path})),"sessions":host.proxy().map(|proxy| proxy.sessions())}).to_string());
    }
    let mut out = format!("mode: {}", host.mode());
    match host.project() {
        Some(store) => {
            let info = store.info().clone();
            let _ = write!(
                out,
                "\nproject: {} ({}){}{}{}",
                info.name,
                info.path.display(),
                if host.project_is_temporary() {
                    " TEMPORARY (deleted on exit; `project` action=save_as to keep)"
                } else {
                    ""
                },
                if info.encrypted { " encrypted" } else { "" },
                if store.is_read_only() {
                    " read-only"
                } else {
                    ""
                },
            );
            let newest = blocking(move || {
                store
                    .query_packets_filtered(&mineburp_project::PacketQuery {
                        limit: 1,
                        ..Default::default()
                    })
                    .map_err(|error| error.to_string())
            })
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next());
            match newest {
                Some(packet) => {
                    let _ = write!(
                        out,
                        "\nnewest packet: #{} at {} UTC",
                        packet.id,
                        render::datetime(packet.timestamp_micros)
                    );
                }
                None => out.push_str("\nhistory: empty"),
            }
        }
        None => out.push_str("\nproject: none open"),
    }
    if let Some(capture) = host.capture() {
        let stats = capture.stats().await;
        let _ = write!(
            out,
            "\ncapture: {} — {} frames kept, {} dropped{}",
            if stats.running { "running" } else { "stopped" },
            stats.frames_emitted,
            stats.frames_dropped,
            stats
                .last_error
                .map(|error| format!(", last error: {error}"))
                .unwrap_or_default()
        );
    }
    if let Some(enabled) = host.decrypt_mode() {
        let _ = write!(
            out,
            "\ndecrypt mode: {}",
            if enabled { "on" } else { "off" }
        );
    }
    if let Some(summary) = host.client_assist_summary().await {
        let _ = write!(out, "\nclient assist: {summary}");
    }
    if let Some(proxy) = host.proxy() {
        let scope = proxy.target_scope();
        if !scope.is_empty() {
            let _ = write!(
                out,
                "\ntarget scope: {} ({} out-of-scope routes refused; the agent connected those directly)",
                scope.join(", "),
                proxy.out_of_scope_refusals()
            );
        }
        let sessions = proxy.sessions();
        let _ = write!(out, "\nlive sessions: {}", sessions.len());
        for session in sessions.iter().take(8) {
            let _ = write!(out, "\n  {}", render::connection_line(session, true));
        }
        let settings = proxy.intercept_settings();
        let held = proxy.intercepted().len();
        if settings.enabled || held > 0 {
            let _ = write!(
                out,
                "\nintercept: {} {}{}, {held} held",
                if settings.enabled { "ON" } else { "off" },
                match (settings.client_to_server, settings.server_to_client) {
                    (true, true) => "both directions",
                    (true, false) => "c2s",
                    (false, true) => "s2c",
                    (false, false) => "no direction",
                },
                if settings.expression.is_empty() {
                    String::new()
                } else {
                    format!(" where `{}`", settings.expression)
                },
            );
        } else {
            out.push_str("\nintercept: off");
        }
        let network = proxy.network_conditions();
        if !(network.client_to_server.is_neutral() && network.server_to_client.is_neutral()) {
            let _ = write!(out, "\nnetwork shaping: active (see `network`)");
        }
    }
    if let Some(store) = host.project() {
        let rules = blocking(move || {
            store
                .load_replacement_rules()
                .map_err(|error| error.to_string())
        })
        .await
        .unwrap_or_default();
        let enabled = rules.iter().filter(|rule| rule.enabled).count();
        if !rules.is_empty() {
            let _ = write!(out, "\nreplace rules: {enabled}/{} enabled", rules.len());
        }
    }
    let protocols = PacketRegistry::bundled();
    let supported = protocols.supported_protocols();
    if let (Some(first), Some(last)) = (supported.first(), supported.last()) {
        let _ = write!(
            out,
            "\nprotocols: {} ({}) … {} ({})",
            first.protocol, first.canonical, last.protocol, last.canonical
        );
    }
    Ok(out)
}

pub async fn packets(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let store = ctx.project()?;
    check_packet_arguments(args.raw())?;
    let limit = args.usize("limit").unwrap_or(40).clamp(1, 500);
    let filter = filter_map(args.raw());
    let mut query = ctx.query(&filter, limit).await?;
    query.before_id = args.i64("before");
    query.after_id = args.i64("after");
    let wait_ms = args.u64("wait_ms").unwrap_or(0).min(MAX_WAIT_MS);
    if wait_ms > 0 && query.after_id.is_none() && query.before_id.is_none() {
        // Waiting "from now": anchor on the newest row of the whole history.
        let probe = store.clone();
        let newest = blocking(move || {
            probe
                .query_packets_filtered(&mineburp_project::PacketQuery {
                    limit: 1,
                    ..Default::default()
                })
                .map_err(|error| error.to_string())
        })
        .await?;
        query.after_id = Some(newest.first().map_or(0, |packet| packet.id));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms);
    let rows = loop {
        let page_store = store.clone();
        let page_query = query.clone();
        let rows = blocking(move || {
            page_store
                .query_packets_filtered(&page_query)
                .map_err(|error| error.to_string())
        })
        .await?;
        if !rows.is_empty() || tokio::time::Instant::now() >= deadline {
            break rows;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    if rows.is_empty() {
        return Ok(match (query.after_id, wait_ms) {
            (Some(after), 0) => format!("no packets after #{after}"),
            (Some(after), _) => {
                format!("no new packets after #{after} within {wait_ms}ms (after={after})")
            }
            _ => "no packets match".into(),
        });
    }
    // The store returns newest first; read oldest → newest.
    if args.str("format") == Some("json") {
        return serde_json::to_string(&rows).map_err(|error| error.to_string());
    }
    let mut rows = rows;
    rows.reverse();
    let connections: std::collections::HashSet<Uuid> =
        rows.iter().map(|packet| packet.connection_id).collect();
    let show_connection = connections.len() > 1;
    let summaries = if args.flag("summaries") {
        let ids: Vec<(
            i64,
            mineburp_core::ProtocolState,
            mineburp_core::Direction,
            Option<i32>,
        )> = rows
            .iter()
            .take(100)
            .map(|packet| {
                (
                    packet.id,
                    packet.state,
                    packet.direction,
                    packet.protocol_version,
                )
            })
            .collect();
        let summary_store = store.clone();
        blocking(move || {
            let mut map = HashMap::new();
            for (id, state, direction, protocol) in ids {
                if let Ok(Some(window)) = summary_store.packet_window(id, 0, 64 * 1024) {
                    let insight = inspect_logical(state, direction, &window.bytes, protocol);
                    if let Some(summary) = insight.summary {
                        map.insert(id, summary);
                    }
                }
            }
            Ok(map)
        })
        .await?
    } else {
        HashMap::new()
    };
    let first = rows.first().map_or(0, |packet| packet.id);
    let last = rows.last().map_or(0, |packet| packet.id);
    let mut out = format!("{} packet(s)", rows.len());
    if !show_connection && let Some(id) = connections.iter().next() {
        let _ = write!(out, " on c={}", render::short_id(*id));
    }
    if let Some(packet) = rows.first() {
        let _ = write!(
            out,
            ", from {} UTC",
            render::datetime(packet.timestamp_micros)
        );
    }
    for packet in &rows {
        out.push('\n');
        out.push_str(&render::packet_line(packet, show_connection));
        if let Some(summary) = summaries.get(&packet.id) {
            let _ = write!(out, " — {}", render::truncate(summary, 160));
        }
    }
    let _ = write!(out, "\ncursors: older before={first} | newer after={last}");
    if rows.len() == limit {
        out.push_str(" (page full; more may exist)");
    }
    Ok(out)
}

pub async fn packet(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let store = ctx.project()?;
    let id = args.require_i64("id")?;
    let hex_mode = args.str("hex").unwrap_or("plain").to_owned();
    let hex_offset = args.usize("hex_offset").unwrap_or(0);
    let hex_limit = args.usize("hex_limit").unwrap_or(256).clamp(1, 65_536);
    let limits = TreeLimits {
        max_lines: args.usize("max_lines").unwrap_or(120).clamp(5, 2_000),
        max_items: args.usize("max_items").unwrap_or(16).clamp(1, 500),
        ..TreeLimits::default()
    };
    let packs = ctx.host.schema_packs();
    let annotation_store = store.clone();
    let (window, annotation) = blocking(move || {
        let window = annotation_store
            .packet_window(id, 0, MAX_FRAME)
            .map_err(|error| error.to_string())?;
        let annotation = annotation_store
            .annotations(&[id])
            .map_err(|error| error.to_string())?
            .into_iter()
            .next();
        Ok((window, annotation))
    })
    .await?;
    let window = window.ok_or_else(|| format!("packet #{id} does not exist"))?;
    if args.str("format") == Some("json") {
        return Ok(json!({"summary":window.summary,"annotation":annotation,"hex":hex::encode(&window.bytes),"offset":window.offset,"total_bytes":window.total_bytes}).to_string());
    }
    let summary = &window.summary;
    let mut out = render::packet_line(summary, true);
    let _ = write!(
        out,
        "\nat {} UTC | seq {} | {}",
        render::datetime(summary.timestamp_micros),
        summary.sequence,
        render::enum_name(&summary.source)
    );
    if let Some(protocol) = summary.protocol_version {
        let _ = write!(out, " | protocol {protocol}");
    }
    if let Some(loader) = &summary.loader {
        let _ = write!(out, " | loader {loader}");
    }
    let wire = &window.wire;
    if wire.frame_length > 0 {
        let _ = write!(out, " | wire {}B", wire.frame_length);
    }
    let _ = write!(
        out,
        "{}{}{}",
        if wire.compressed { " compressed" } else { "" },
        if wire.encrypted { " encrypted" } else { "" },
        if wire.truncated { " TRUNCATED" } else { "" }
    );
    if let Some(flow) = &summary.flow {
        let _ = write!(
            out,
            "\nflow: {} {} → {}{}",
            flow.transport,
            flow.local_address,
            flow.remote_address,
            flow.process_id
                .map(|pid| format!(" pid {pid}"))
                .unwrap_or_default()
        );
    }
    if let Some(annotation) = annotation {
        out.push('\n');
        out.push_str(&annotation_line(&annotation));
    }
    let partial = window.total_bytes > window.bytes.len();
    if partial {
        let _ = write!(
            out,
            "\nnote: decoded from the first {} of {} bytes",
            window.bytes.len(),
            window.total_bytes
        );
    }
    let bytes = window.bytes.clone();
    let (state, direction, protocol) = (summary.state, summary.direction, summary.protocol_version);
    let path = args.str("path").map(str::to_owned);
    let raw = args.flag("raw");
    let with_layout = args.flag("layout");
    let schema_summary = summary.clone();
    let decoded = blocking(move || {
        let insight = inspect_logical(state, direction, &bytes, protocol);
        let (schema, schema_error) = ops::decode_with_schema_packs(&packs, &schema_summary, &bytes);
        let layout = with_layout.then(|| layout_logical(state, direction, &bytes, protocol));
        Ok((insight, schema, schema_error, layout))
    })
    .await?;
    let (mut insight, schema, schema_error, layout) = decoded;
    if raw {
        let fields = insight.fields.take();
        out.push('\n');
        out.push_str(&render::insight(&insight, limits, None));
        if let Some(fields) = fields {
            let selected = path
                .as_deref()
                .map_or(Some(&fields), |path| render::select(&fields, path));
            let _ = write!(
                out,
                "\nfields: {}",
                selected.map_or_else(|| "null".to_owned(), Value::to_string)
            );
        }
    } else {
        out.push('\n');
        out.push_str(&render::insight(&insight, limits, path.as_deref()));
    }
    // Only a schema pack's decode belongs here. The decode stored with the row
    // is the built-in one already rendered above.
    if let Some(schema) = schema {
        let _ = write!(out, "\nschema decode:\n{}", render::tree(&schema, limits));
    }
    if let Some(error) = schema_error {
        let _ = write!(out, "\nschema error: {error}");
    }
    if let Some(layout) = layout {
        out.push('\n');
        out.push_str(&render::layout(&layout.fields, layout.complete, limits));
    }
    if hex_mode != "none" {
        let total = window.total_bytes;
        let start = hex_offset.min(total);
        let end = start.saturating_add(hex_limit).min(total);
        let slice = if end <= window.bytes.len() {
            window.bytes[start..end].to_vec()
        } else {
            let hex_store = store.clone();
            blocking(move || {
                Ok(hex_store
                    .packet_window(id, start, end - start)
                    .map_err(|error| error.to_string())?
                    .map(|window| window.bytes.to_vec())
                    .unwrap_or_default())
            })
            .await?
        };
        let _ = write!(
            out,
            "\nhex [{start}..{end} of {total}]:\n{}",
            render::hex(&slice, start, hex_mode == "dump")
        );
        if end < total {
            let _ = write!(out, "\n… hex_offset={end} for more");
        }
    }
    Ok(out)
}

pub fn annotation_line(annotation: &PacketAnnotation) -> String {
    let mut line = format!("#{}", annotation.packet_id);
    if annotation.bookmarked {
        line.push_str(" ★");
    }
    if let Some(color) = &annotation.color {
        let _ = write!(line, " [{color}]");
    }
    if let Some(note) = &annotation.note {
        let _ = write!(line, " {}", render::truncate(note, 300));
    }
    line
}

pub async fn connections(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    if args.str("action") == Some("compare") {
        let a = ctx
            .resolve_connection(args.str("a").ok_or("a is required")?)
            .await?;
        let b = ctx
            .resolve_connection(args.str("b").ok_or("b is required")?)
            .await?;
        let filter = args
            .0
            .get("filter")
            .map(|v| v.as_object().ok_or("filter must be an object"))
            .transpose()?
            .cloned()
            .unwrap_or_default();
        let query = ctx.query(&filter, 500).await?;
        let store = ctx.project()?;
        let result =
            super::blocking(move || crate::ops::compare_connections(&store, a, b, &query)).await?;
        if args.str("format") == Some("json") {
            return serde_json::to_string(&result).map_err(|e| e.to_string());
        }
        let mut out = format!(
            "{} aligned rows, {} differences",
            result.rows.len(),
            result.rows.iter().filter(|r| r.kind != "identical").count()
        );
        for row in result
            .rows
            .iter()
            .filter(|r| r.kind != "identical")
            .take(args.usize("limit").unwrap_or(20).min(100))
        {
            use std::fmt::Write as _;
            let _ = write!(
                out,
                "\n{} A={:?} B={:?} delta={} offset={:?}",
                row.kind,
                row.a.as_ref().map(|p| p.id),
                row.b.as_ref().map(|p| p.id),
                row.size_delta,
                row.first_difference
            );
        }
        return Ok(out);
    }

    if let Some(close) = args.str("close") {
        let id = ctx.resolve_connection(close).await?;
        ctx.proxy()?
            .stop_session(id)
            .map_err(|error| error.to_string())?;
        return Ok(format!("closed c={}", render::short_id(id)));
    }
    let limit = args.usize("limit").unwrap_or(50).clamp(1, 1_000);
    let live_only = args.flag("live");
    let rows: Vec<_> = ctx
        .connections()
        .await?
        .into_iter()
        .filter(|(_, live)| !live_only || *live)
        .collect();
    if args.str("format") == Some("json") {
        return serde_json::to_string(&rows[..rows.len().min(limit)])
            .map_err(|error| error.to_string());
    }
    if rows.is_empty() {
        return Ok(if live_only {
            "no live sessions".into()
        } else {
            "no connections".into()
        });
    }
    let mut out = format!(
        "{} connection(s) (id target status state version … packets bytes)",
        rows.len()
    );
    for (connection, live) in rows.iter().take(limit) {
        out.push('\n');
        out.push_str(&render::connection_line(connection, *live));
    }
    if rows.len() > limit {
        let _ = write!(out, "\n…+{} more (raise limit)", rows.len() - limit);
    }
    Ok(out)
}

pub async fn stats(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let store = ctx.project()?;
    let filter = args
        .get("filter")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let query = ctx.query(&filter, 500).await?;
    let top = args.usize("top").unwrap_or(10).clamp(1, 100);
    let timeline = args.flag("timeline");
    let options = StatsOptions {
        bucket_micros: None,
        max_buckets: args.usize("buckets").unwrap_or(24).clamp(1, 500),
        top,
    };
    let stats = blocking(move || {
        store
            .traffic_stats(&query, options)
            .map_err(|error| error.to_string())
    })
    .await?;
    if args.str("format") == Some("json") {
        return serde_json::to_string(&stats).map_err(|error| error.to_string());
    }
    if stats.total_packets == 0 {
        return Ok("no packets match".into());
    }
    let mut out = format!(
        "{} packets, {} | C>S {} pk {} | S>C {} pk {}",
        stats.total_packets,
        render::bytes(stats.total_bytes),
        stats.client_to_server_packets,
        render::bytes(stats.client_to_server_bytes),
        stats.server_to_client_packets,
        render::bytes(stats.server_to_client_bytes),
    );
    if let (Some(first), Some(last)) = (stats.first_timestamp_micros, stats.last_timestamp_micros) {
        #[allow(clippy::cast_precision_loss)]
        let seconds = (last - first) as f64 / 1_000_000.0;
        let _ = write!(
            out,
            "\nspan: {} → {} UTC ({seconds:.1}s)",
            render::datetime(first),
            render::time(last)
        );
    }
    out.push_str("\ntop by count:");
    for name in &stats.top_by_count {
        let _ = write!(
            out,
            "\n  {} {} ({})",
            name.packets,
            name.name.as_deref().unwrap_or("?"),
            render::bytes(name.bytes)
        );
    }
    out.push_str("\ntop by bytes:");
    for name in &stats.top_by_bytes {
        let _ = write!(
            out,
            "\n  {} {} ({} pk)",
            render::bytes(name.bytes),
            name.name.as_deref().unwrap_or("?"),
            name.packets
        );
    }
    if stats.top_connections.len() > 1 {
        out.push_str("\ntop connections:");
        for connection in &stats.top_connections {
            let _ = write!(
                out,
                "\n  c={} {} pk {}",
                render::short_id(connection.connection_id),
                connection.packets,
                render::bytes(connection.bytes)
            );
        }
    }
    out.push_str("\nsizes:");
    for bucket in stats
        .size_histogram
        .iter()
        .filter(|bucket| bucket.packets > 0)
    {
        let _ = write!(
            out,
            " [{}-{}):{}",
            bucket.min,
            bucket
                .max
                .map_or_else(|| "∞".to_owned(), |max| max.to_string()),
            bucket.packets
        );
    }
    if timeline {
        let _ = write!(
            out,
            "\ntimeline (bucket {}ms; start C>S pk/bytes S>C pk/bytes):",
            stats.bucket_micros / 1_000
        );
        for bucket in &stats.buckets {
            let _ = write!(
                out,
                "\n  {} {}/{} {}/{}",
                render::time(bucket.start_micros),
                bucket.client_to_server_packets,
                render::bytes(bucket.client_to_server_bytes),
                bucket.server_to_client_packets,
                render::bytes(bucket.server_to_client_bytes)
            );
        }
    }
    Ok(out)
}

pub async fn annotate(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let store = ctx.project()?;
    let mut ids: Vec<i64> = args.parse("ids")?.unwrap_or_default();
    if let Some(id) = args.i64("id") {
        ids.push(id);
    }
    let default_action = if ids.is_empty() { "list" } else { "set" };
    match args.action(default_action).as_str() {
        "list" => {
            let limit = args.usize("limit").unwrap_or(100).clamp(1, 10_000);
            let annotations = blocking(move || {
                store
                    .list_annotations(limit)
                    .map_err(|error| error.to_string())
            })
            .await?;
            if annotations.is_empty() {
                return Ok("no annotations".into());
            }
            Ok(annotations
                .iter()
                .map(annotation_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "set" => {
            if ids.is_empty() {
                return Err("give `id` or `ids`".into());
            }
            if ids.len() > 2_000 {
                return Err("at most 2000 packets per call".into());
            }
            let bookmark = args.bool("bookmark");
            let color = args.get("color").and_then(Value::as_str).map(str::to_owned);
            let note = args.get("note").and_then(Value::as_str).map(str::to_owned);
            let changed = blocking(move || {
                let existing: HashMap<i64, PacketAnnotation> = store
                    .annotations(&ids)
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .map(|annotation| (annotation.packet_id, annotation))
                    .collect();
                let mut lines = Vec::new();
                for id in ids {
                    let current = existing.get(&id);
                    let bookmarked = bookmark
                        .or_else(|| current.map(|annotation| annotation.bookmarked))
                        .unwrap_or(color.is_none() && note.is_none());
                    let pick = |given: &Option<String>, current: Option<&String>| match given {
                        Some(text) if text.is_empty() => None,
                        Some(text) => Some(text.clone()),
                        None => current.cloned(),
                    };
                    let next_color = pick(&color, current.and_then(|a| a.color.as_ref()));
                    let next_note = pick(&note, current.and_then(|a| a.note.as_ref()));
                    let stored = store
                        .set_annotation(id, bookmarked, next_color, next_note)
                        .map_err(|error| error.to_string())?;
                    lines.push(
                        stored.map_or_else(|| format!("#{id} cleared"), |a| annotation_line(&a)),
                    );
                }
                Ok(lines)
            })
            .await?;
            ctx.host.notify("annotations");
            Ok(changed.join("\n"))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

pub async fn filters(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    match args.action("help").as_str() {
        "help" => Ok(format!(
            "expr grammar: `field op value` joined by && (binds tighter) and ||; `*` matches all; quote values with spaces.\n\
             fields: {}\n\
             ops: == != > >= < <= ~ (contains). numeric: size protocol id. optional fields (absent never match): name channel loader id protocol.\n\
             values: state=handshake|status|login|configuration|play|opaque|closed; direction=client_to_server|server_to_client; source=minecraft|side_channel; disposition=forwarded|dropped|edited|replayed|observed|failed.\n\
             other filter keys: search (+_regex/_case/_not), content (+_mode text|hex|regex, _scope contains|equals|prefix|suffix, _case, _not), dir, states, names, exclude_names, min_size, max_size, connection, bookmarked, saved.\n\
             e.g. expr=`direction == client_to_server && name ~ chat`, content=`0c-0f` content_mode=hex content_scope=equals content_not=true",
            FilterField::NAMES.join(" ")
        )),
        "validate" => {
            let expression = args.require_str("expr")?;
            mineburp_core::FilterExpression::parse(expression)
                .map(|_| "valid".to_owned())
                .map_err(|error| error.to_string())
        }
        "list" => {
            let store = ctx.project()?;
            let saved = blocking(move || {
                store
                    .load_saved_filters()
                    .map_err(|error| error.to_string())
            })
            .await?;
            if saved.is_empty() {
                return Ok("no saved filters".into());
            }
            Ok(saved
                .iter()
                .map(|filter| {
                    format!(
                        "{} {} {}",
                        &filter.id.simple().to_string()[..8],
                        filter.name,
                        compact_json(&filter.filter)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "save" => {
            let store = ctx.project()?;
            let name = args.require_str("name")?.to_owned();
            let filter = args
                .get("filter")
                .and_then(Value::as_object)
                .cloned()
                .ok_or("`filter` is required")?;
            let mut shape = ctx.ui_shape(&filter).await?;
            // Validate exactly as the history would before storing it.
            ctx.query(&filter, 1).await?;
            shape.retain(|_, value| !value.is_null());
            let existing_id = match args.str("id") {
                Some(prefix) => Some(find_saved(ctx, prefix).await?.id),
                None => None,
            };
            let saved = SavedFilter {
                id: existing_id.unwrap_or_else(Uuid::new_v4),
                name,
                filter: Value::Object(shape),
                created_at_micros: 0,
                updated_at_micros: 0,
            };
            let saved =
                blocking(move || store.save_filter(&saved).map_err(|error| error.to_string()))
                    .await?;
            ctx.host.notify("filters");
            Ok(format!(
                "saved {} {}",
                &saved.id.simple().to_string()[..8],
                saved.name
            ))
        }
        "delete" => {
            let store = ctx.project()?;
            let target = find_saved(ctx, args.require_str("id")?).await?;
            let id = target.id;
            blocking(move || {
                store
                    .delete_saved_filter(id)
                    .map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.notify("filters");
            Ok(format!("deleted {}", target.name))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

async fn find_saved(ctx: &Ctx<'_>, needle: &str) -> Result<SavedFilter, String> {
    let store = ctx.project()?;
    let saved = blocking(move || {
        store
            .load_saved_filters()
            .map_err(|error| error.to_string())
    })
    .await?;
    let needle = needle.to_ascii_lowercase();
    saved
        .into_iter()
        .find(|filter| {
            filter.id.simple().to_string().starts_with(&needle)
                || filter.name.to_ascii_lowercase() == needle
        })
        .ok_or_else(|| format!("no saved filter `{needle}`"))
}

/// JSON without the empty and default-valued keys the UI stores.
fn compact_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let kept: Map<String, Value> = map
                .iter()
                .filter(|(key, value)| {
                    !matches!(value, Value::Null | Value::Bool(false))
                        && !matches!(value, Value::String(text) if text.is_empty())
                        && !matches!(value, Value::Array(items) if items.is_empty())
                        && !matches!(key.as_str(), "limit" | "offset")
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Value::Object(kept).to_string()
        }
        other => other.to_string(),
    }
}
