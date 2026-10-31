//! Project files, replacement rules, and schema packs.

use std::{fmt::Write as _, path::PathBuf};

use mineburp_capture::ImportOptions;
use mineburp_core::{FilterExpression, ReplacementRule};
use mineburp_project::{ProjectOptions, ProjectStore};
use mineburp_protocol::SchemaPack;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Args, Ctx, Tool, ToolResult, blocking, boolean, choice, edits_ref, filter_ref, frames, integer,
    object, set_schema, string,
};
use crate::{
    ops::{self, PathPurpose, validate_path},
    render,
};

pub fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "project",
            description: "Project file operations. actions: info (default), open, create, save_as, checkpoint, compact, export (path .json or .pcapng, filter), import (pcap/pcapng into the project), delete_packets (filter; empty filter needs confirm=true). Paths must be absolute.",
            schema: object(
                &[
                    (
                        "action",
                        choice(
                            &[
                                "info",
                                "open",
                                "create",
                                "save_as",
                                "checkpoint",
                                "compact",
                                "export",
                                "import",
                                "delete_packets",
                            ],
                            "",
                        ),
                    ),
                    ("path", string("absolute path")),
                    ("name", string("project name (create, save_as)")),
                    ("passphrase", string("SQLCipher passphrase")),
                    (
                        "passphrase_env",
                        string(
                            "read the passphrase from this environment variable of the server process",
                        ),
                    ),
                    ("read_only", boolean("open read-only")),
                    ("filter", filter_ref()),
                    (
                        "ports",
                        json!({ "type": "array", "items": { "type": "integer" }, "description": "import: server ports, default [25565]; [] = all flows" }),
                    ),
                    (
                        "protocol",
                        string("import: protocol to assume when the handshake is missing"),
                    ),
                    (
                        "raw",
                        boolean("import: keep TCP chunks raw instead of splitting packets"),
                    ),
                    (
                        "keep_connections",
                        boolean("delete_packets: keep emptied connection rows"),
                    ),
                    (
                        "confirm",
                        boolean("delete_packets with an empty filter deletes ALL history"),
                    ),
                ],
                &[],
            ),
            read_only: false,
            destructive: true,
        },
        Tool {
            name: "rules",
            description: "Replace rules that rewrite matching live packets automatically (stored in the project). actions: list (default), add (name, expr, edits/set, enabled), update (id + changed keys), remove (id), preview (rule id or edits, against packet or hex).",
            schema: object(
                &[
                    (
                        "action",
                        choice(&["list", "add", "update", "remove", "preview"], ""),
                    ),
                    ("id", string("rule id/prefix")),
                    ("name", string("")),
                    (
                        "expr",
                        string("filter expression selecting packets; \"\" = all"),
                    ),
                    ("enabled", boolean("default true on add")),
                    (
                        "behavior",
                        choice(&["rewrite", "drop"], "rule action; default rewrite"),
                    ),
                    ("edits", edits_ref()),
                    ("set", set_schema()),
                    ("packet", integer("preview: history id")),
                    ("hex", string("preview: frame hex")),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
        Tool {
            name: "schemas",
            description: "Declarative schema packs that decode plugin/mod payloads (never execute code). actions: list (default), install (pack JSON; validated, stored in the project, used for decoding).",
            schema: object(
                &[
                    ("action", choice(&["list", "install"], "")),
                    (
                        "pack",
                        json!({ "description": "schema pack as a JSON object or string (see docs/SCHEMAS.md)" }),
                    ),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
    ]
}

fn passphrase(args: &Args) -> Result<Option<String>, String> {
    if let Some(variable) = args.str("passphrase_env") {
        return std::env::var(variable)
            .map(Some)
            .map_err(|_| format!("environment variable `{variable}` is not set"));
    }
    Ok(args.str("passphrase").map(str::to_owned))
}

fn info_text(ctx: &Ctx<'_>, store: &ProjectStore) -> String {
    let info = store.info();
    format!(
        "{} | {} | schema v{}{}{}{}",
        info.name,
        info.path.display(),
        info.schema_version,
        if info.encrypted { " | encrypted" } else { "" },
        if store.is_read_only() {
            " | read-only"
        } else {
            ""
        },
        if ctx.host.project_is_temporary() {
            " | TEMPORARY"
        } else {
            ""
        }
    )
}

pub async fn project(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    match args.action("info").as_str() {
        "info" => Ok(info_text(ctx, &ctx.project()?)),
        "open" => {
            let path = validate_path(
                &PathBuf::from(args.require_str("path")?),
                PathPurpose::ExistingProject,
                &[],
            )?;
            let options = ProjectOptions {
                passphrase: passphrase(args)?,
                read_only: args.flag("read_only"),
            };
            let store = blocking(move || {
                ProjectStore::open(path, options).map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.install_project(store.clone()).await?;
            ctx.host.notify("project");
            Ok(format!("opened {}", info_text(ctx, &store)))
        }
        "create" | "save_as" => {
            let action = args.action("info");
            let path = validate_path(
                &PathBuf::from(args.require_str("path")?),
                PathPurpose::NewProject,
                &[],
            )?;
            let name = args
                .str("name")
                .map(str::to_owned)
                .or_else(|| {
                    path.file_stem()
                        .map(|stem| stem.to_string_lossy().into_owned())
                })
                .unwrap_or_else(|| "MineBurp project".into());
            let options = ProjectOptions {
                passphrase: passphrase(args)?,
                read_only: false,
            };
            let source = if action == "save_as" {
                Some(ctx.project()?)
            } else {
                None
            };
            let store = blocking(move || {
                match source {
                    Some(source) => source.save_as(path, &name, options),
                    None => ProjectStore::create(path, &name, options),
                }
                .map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.install_project(store.clone()).await?;
            ctx.host.notify("project");
            Ok(format!(
                "{} {}",
                if action == "save_as" {
                    "saved as"
                } else {
                    "created"
                },
                info_text(ctx, &store)
            ))
        }
        "checkpoint" => {
            let store = ctx.project()?;
            blocking(move || store.checkpoint().map_err(|error| error.to_string())).await?;
            Ok("checkpointed".into())
        }
        "compact" => {
            let store = ctx.project()?;
            let summary =
                blocking(move || store.compact().map_err(|error| error.to_string())).await?;
            Ok(format!(
                "compacted {} → {}",
                render::bytes(summary.bytes_before),
                render::bytes(summary.bytes_after)
            ))
        }
        "export" => {
            let store = ctx.project()?;
            let raw_path = PathBuf::from(args.require_str("path")?);
            let pcap = raw_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pcapng"));
            let purpose = if pcap {
                PathPurpose::ExportPcap
            } else {
                PathPurpose::ExportJson
            };
            let path = validate_path(&raw_path, purpose, &[&store.info().path])?;
            let filter = args
                .get("filter")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let query = ctx.query(&filter, 500).await?;
            if pcap {
                let summary = blocking(move || ops::export_pcapng(&store, &query, &path)).await?;
                Ok(format!(
                    "wrote {} packets from {} connection(s) as pcapng (dissector: tools/wireshark/mineburp.lua)",
                    summary.packets, summary.connections
                ))
            } else {
                let written = blocking(move || ops::export_json(&store, &query, &path)).await?;
                Ok(format!("wrote {written} packets as JSON"))
            }
        }
        "import" => {
            let store = ctx.project()?;
            let path = validate_path(
                &PathBuf::from(args.require_str("path")?),
                PathPurpose::ImportCapture,
                &[],
            )?;
            let mut options = ImportOptions::default();
            if let Some(ports) = args.parse::<Vec<u16>>("ports")? {
                options.server_ports = ports;
            }
            options.protocol_version = args.protocol("protocol")?;
            options.split_packets = !args.flag("raw");
            let summary =
                blocking(move || ops::import_capture_file(&store, &path, &options)).await?;
            ctx.host.notify("packets");
            let mut out = format!(
                "imported {} rows ({}) from {} records: {} packets decoded, {} raw, {} connection(s)",
                summary.frames_imported,
                render::bytes(summary.bytes_imported),
                summary.records_read,
                summary.packets_decoded,
                summary.raw_rows,
                summary.connections
            );
            if summary.encrypted_connections > 0 {
                let _ = write!(
                    out,
                    "\n{} connection(s) switched to encryption; later traffic is raw",
                    summary.encrypted_connections
                );
            }
            if summary.midstream_connections > 0 || summary.desyncs > 0 {
                let _ = write!(
                    out,
                    "\nmid-stream joins {}, desyncs {}, resyncs {} (pass `protocol` if names look wrong)",
                    summary.midstream_connections, summary.desyncs, summary.resyncs
                );
            }
            if let Some(error) = summary.error {
                let _ = write!(out, "\nstopped: {error}");
            }
            Ok(out)
        }
        "delete_packets" => {
            let store = ctx.project()?;
            let filter = args
                .get("filter")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if filter.values().all(Value::is_null) && !args.flag("confirm") {
                return Err(
                    "an empty filter deletes the whole history; pass confirm=true to do that"
                        .into(),
                );
            }
            let query = ctx.query(&filter, 500).await?;
            let prune = !args.flag("keep_connections");
            let summary = blocking(move || {
                store
                    .delete_packets(&query, prune)
                    .map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.notify("packets");
            Ok(format!(
                "deleted {} packets and {} empty connection(s); `project` action=compact frees the space",
                summary.packets, summary.connections
            ))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

fn rule_line(rule: &ReplacementRule) -> String {
    let edits: Vec<String> = rule
        .edits
        .iter()
        .map(|edit| {
            let value = serde_json::to_value(edit).unwrap_or_default();
            render::truncate(&value.to_string(), 120)
        })
        .collect();
    format!(
        "{} [{}] {} | {} | {}",
        &rule.id.simple().to_string()[..8],
        if rule.enabled { "on" } else { "off" },
        rule.name,
        if rule.expression.is_empty() {
            "*"
        } else {
            &rule.expression
        },
        if rule.action == mineburp_core::ReplacementAction::Drop {
            "DROP".into()
        } else {
            edits.join(" ; ")
        }
    )
}

fn find_rule(rules: &[ReplacementRule], needle: &str) -> Result<usize, String> {
    let needle = needle.to_ascii_lowercase();
    let matches: Vec<usize> = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            rule.id.simple().to_string().starts_with(&needle)
                || rule.name.to_ascii_lowercase() == needle
        })
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => Err(format!("no rule `{needle}`")),
        _ => Err(format!("rule `{needle}` is ambiguous")),
    }
}

async fn save_rules(ctx: &Ctx<'_>, rules: Vec<ReplacementRule>) -> Result<(), String> {
    for rule in &rules {
        if !rule.expression.trim().is_empty() {
            FilterExpression::parse(&rule.expression)
                .map_err(|error| format!("rule `{}`: {error}", rule.name))?;
        }
    }
    if let Some(proxy) = ctx.host.proxy() {
        proxy
            .set_replacement_rules(rules.clone())
            .map_err(|error| error.to_string())?;
    }
    let store = ctx.project()?;
    blocking(move || {
        store
            .save_replacement_rules(&rules)
            .map_err(|error| error.to_string())
    })
    .await?;
    ctx.host.notify("rules");
    Ok(())
}

pub async fn rules(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let store = ctx.project()?;
    let mut rules = blocking(move || {
        store
            .load_replacement_rules()
            .map_err(|error| error.to_string())
    })
    .await?;
    match args.action("list").as_str() {
        "list" => {
            if rules.is_empty() {
                return Ok("no rules".into());
            }
            Ok(format!(
                "id [state] name | expr | edits (applied in order)\n{}",
                rules.iter().map(rule_line).collect::<Vec<_>>().join("\n")
            ))
        }
        "add" => {
            let edits = args.edits()?;
            let behavior = match args.str("behavior").unwrap_or("rewrite") {
                "rewrite" => mineburp_core::ReplacementAction::Rewrite,
                "drop" => mineburp_core::ReplacementAction::Drop,
                _ => return Err("behavior must be rewrite or drop".into()),
            };
            if edits.is_empty() && behavior == mineburp_core::ReplacementAction::Rewrite {
                return Err("a rewrite rule needs `edits` or `set`".into());
            }
            let rule = ReplacementRule {
                action: behavior,
                id: Uuid::new_v4(),
                name: args.str("name").unwrap_or("rule").to_owned(),
                enabled: args.bool("enabled").unwrap_or(true),
                expression: args
                    .get("expr")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned(),
                edits,
            };
            let line = rule_line(&rule);
            rules.push(rule);
            save_rules(ctx, rules).await?;
            Ok(format!("added {line}"))
        }
        "update" => {
            let index = find_rule(&rules, args.require_str("id")?)?;
            let edits = args.edits()?;
            let rule = &mut rules[index];
            if let Some(behavior) = args.str("behavior") {
                rule.action = match behavior {
                    "rewrite" => mineburp_core::ReplacementAction::Rewrite,
                    "drop" => mineburp_core::ReplacementAction::Drop,
                    _ => return Err("behavior must be rewrite or drop".into()),
                };
            }
            if let Some(name) = args.str("name") {
                rule.name = name.to_owned();
            }
            if let Some(expression) = args.get("expr").and_then(Value::as_str) {
                rule.expression = expression.trim().to_owned();
            }
            if let Some(enabled) = args.bool("enabled") {
                rule.enabled = enabled;
            }
            if !edits.is_empty() {
                rule.edits = edits;
            }
            let line = rule_line(rule);
            save_rules(ctx, rules).await?;
            Ok(format!("updated {line}"))
        }
        "remove" => {
            let index = find_rule(&rules, args.require_str("id")?)?;
            let removed = rules.remove(index);
            save_rules(ctx, rules).await?;
            Ok(format!("removed {}", removed.name))
        }
        "preview" => {
            let edits = match args.str("id") {
                Some(id) => rules[find_rule(&rules, id)?].edits.clone(),
                None => args.edits()?,
            };
            let drops = args
                .str("id")
                .map(|id| find_rule(&rules, id))
                .transpose()?
                .is_some_and(|i| rules[i].action == mineburp_core::ReplacementAction::Drop);
            if edits.is_empty() && !drops {
                return Err("give a rule `id` or `edits`".into());
            }
            let frame = ctx.frame_from(args).await?;
            let matched = match (args.str("id"), args.i64("packet")) {
                (Some(id), Some(packet)) => {
                    let rule = rules[find_rule(&rules, id)?].clone();
                    let store = ctx.project()?;
                    let summary = blocking(move || {
                        store
                            .packet_window(packet, 0, 0)
                            .map_err(|error| error.to_string())
                    })
                    .await?
                    .map(|window| window.summary);
                    summary.map(|summary| {
                        rule.expression.trim().is_empty()
                            || FilterExpression::parse(&rule.expression)
                                .is_ok_and(|expression| expression.matches(&summary))
                    })
                }
                _ => None,
            };
            if drops {
                return Ok(match matched {
                    Some(true) => "rule matches: packet would be DROPPED".into(),
                    Some(false) => "rule does not match: packet would be forwarded".into(),
                    None => "Drop rule: provide packet=<history id> to verify its selector".into(),
                });
            }
            let before = frame.bytes.len();
            let rewritten = frames::apply(&frame, &edits)?;
            let mut out = String::new();
            if let Some(matched) = matched {
                let _ = writeln!(
                    out,
                    "rule expression {} this packet",
                    if matched { "matches" } else { "does NOT match" }
                );
            }
            let _ = write!(
                out,
                "{before}B → {}B\nhex: {}",
                rewritten.len(),
                render::hex(&rewritten, 0, false)
            );
            let insight = mineburp_protocol::inspect_logical(
                frame.state,
                frame.direction,
                &rewritten,
                frame.protocol,
            );
            if let Some(summary) = insight.summary {
                let _ = write!(out, "\nsummary: {}", render::truncate(&summary, 300));
            }
            Ok(out)
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

pub async fn schemas(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    match args.action("list").as_str() {
        "list" => {
            let store = ctx.project()?;
            let packs =
                blocking(move || store.load_schema_packs().map_err(|error| error.to_string()))
                    .await?;
            if packs.is_empty() {
                return Ok("no schema packs (docs/SCHEMAS.md describes the format)".into());
            }
            Ok(packs
                .iter()
                .map(|pack| {
                    format!(
                        "{} {} v{}: {}",
                        pack.manifest.id,
                        pack.manifest.name,
                        pack.manifest.version,
                        pack.schemas
                            .iter()
                            .map(|schema| schema.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "install" => {
            let pack: SchemaPack = match args.get("pack") {
                Some(Value::String(text)) => serde_json::from_str(text),
                Some(value) => serde_json::from_value(value.clone()),
                None => return Err("`pack` is required".into()),
            }
            .map_err(|error| format!("schema pack: {error}"))?;
            pack.validate().map_err(|error| error.to_string())?;
            let store = ctx.project()?;
            let saved = pack.clone();
            let packs = blocking(move || {
                store
                    .save_schema_pack(&saved)
                    .and_then(|()| store.load_schema_packs())
                    .map_err(|error| error.to_string())
            })
            .await?;
            if let Some(proxy) = ctx.host.proxy() {
                proxy
                    .set_schema_packs(packs)
                    .map_err(|error| error.to_string())?;
            }
            ctx.host.notify("schemas");
            Ok(format!(
                "installed {} v{} ({} schemas)",
                pack.manifest.id,
                pack.manifest.version,
                pack.schemas.len()
            ))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}
