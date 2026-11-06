//! Live traffic control: intercept, network shaping, repeater, capture, launchers.
//!
//! These act on decrypted connections the operator's own client opened through
//! the desktop app; offline they report that the app is needed.

use std::{fmt::Write as _, time::Duration};

use bytes::Bytes;
use mineburp_core::RepeaterTab;
use mineburp_launcher::{InstanceDescriptor, LaunchRequest};
use mineburp_protocol::inspect_logical;
use mineburp_proxy::{InterceptDecision, InterceptSettings, InterceptedPacket, LinkConditions};
use serde_json::Value;
use uuid::Uuid;

use super::{
    Args, Ctx, Frame, Tool, ToolResult, blocking, boolean, choice, edits_ref, frames, integer,
    object, parse_hex, set_schema, string,
};
use crate::render::{self, TreeLimits};

const MAX_WAIT_MS: u64 = 60_000;

pub fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "route",
            description: "Create a one-use loopback proxy listener for an authorized test client. Connect within 15 seconds. Offline-mode servers need no Java agent; online-mode servers require client assistance. Returns connection id and listener address.",
            schema: object(
                &[
                    ("host", string("upstream host")),
                    ("port", integer("upstream port, default 25565")),
                ],
                &["host"],
            ),
            read_only: false,
            destructive: false,
        },
        Tool {
            name: "intercept",
            description: "Hold live decoded handshake, status, login, configuration, and play packets before forwarding. actions: status (default; settings + held queue), set (enabled, c2s, s2c, expr, forward_keep_alive, auto_forward_ms), show (one held frame decoded), forward (optionally with hex/edits/set), drop, forward_all, wait (until something is held).",
            schema: object(
                &[
                    (
                        "action",
                        choice(
                            &[
                                "status",
                                "set",
                                "show",
                                "forward",
                                "drop",
                                "forward_all",
                                "wait",
                            ],
                            "",
                        ),
                    ),
                    ("id", integer("held frame id ([n] in status)")),
                    ("enabled", boolean("")),
                    ("c2s", boolean("hold client→server")),
                    ("s2c", boolean("hold server→client")),
                    (
                        "expr",
                        string("filter expression selecting what to hold; \"\" holds all"),
                    ),
                    (
                        "forward_keep_alive",
                        boolean("let keep-alives/pings pass (default true)"),
                    ),
                    (
                        "auto_forward_ms",
                        integer("forward held frames after this long; 0 = never"),
                    ),
                    (
                        "hex_limit",
                        super::integer("maximum output bytes, default 512, maximum 65536"),
                    ),
                    ("hex", string("forward: replacement frame")),
                    ("edits", edits_ref()),
                    ("set", set_schema()),
                    ("wait_ms", integer("wait: max 60000")),
                ],
                &[],
            ),
            read_only: false,
            destructive: true,
        },
        Tool {
            name: "network",
            description: "Show or change network shaping on live decrypted connections. Unset keys keep their value; bandwidth 0 = unlimited; reset=true clears all.",
            schema: object(
                &[
                    ("c2s_delay_ms", integer("")),
                    ("c2s_jitter_ms", integer("")),
                    ("c2s_bandwidth", integer("bytes/s")),
                    ("s2c_delay_ms", integer("")),
                    ("s2c_jitter_ms", integer("")),
                    ("s2c_bandwidth", integer("bytes/s")),
                    ("reset", boolean("")),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
        Tool {
            name: "repeater",
            description: "Send one frame into a live decrypted connection (action=send; frame from hex, packet id, or tab, edits applied first), or manage saved Repeater tabs (list|save|delete).",
            schema: object(
                &[
                    (
                        "action",
                        choice(&["send", "list", "save", "delete"], "default list"),
                    ),
                    (
                        "connection",
                        string("live connection id/prefix; defaults to the only live one"),
                    ),
                    (
                        "dir",
                        choice(&["c2s", "s2c"], "default: the source packet's, else c2s"),
                    ),
                    (
                        "hex_limit",
                        super::integer("maximum output bytes, default 512, maximum 65536"),
                    ),
                    ("hex", string("logical frame hex")),
                    ("packet", integer("history id to resend/edit")),
                    ("tab", string("tab id/prefix as the frame source")),
                    ("edits", edits_ref()),
                    ("set", set_schema()),
                    ("name", string("tab name (save)")),
                    ("id", string("tab id/prefix (save to update, delete)")),
                    (
                        "state",
                        choice(&["configuration", "play"], "tab state (save), default play"),
                    ),
                ],
                &[],
            ),
            read_only: false,
            destructive: true,
        },
        Tool {
            name: "capture",
            description: "Passive capture and decrypt mode. actions: status (default), start, stop, decrypt (enabled=true|false: route configured clients through the decrypting proxy).",
            schema: object(
                &[
                    (
                        "action",
                        choice(&["status", "start", "stop", "decrypt"], ""),
                    ),
                    ("enabled", boolean("for decrypt")),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
        Tool {
            name: "launcher",
            description: "Minecraft launcher instances. actions: instances (default), launch (instance), assist (instance, enabled: add/remove MineBurp's Java agent argument).",
            schema: object(
                &[
                    ("action", choice(&["instances", "launch", "assist"], "")),
                    ("instance", string("instance id or name substring")),
                    ("enabled", boolean("for assist")),
                    (
                        "profile",
                        string("launch profile name, where the launcher supports it"),
                    ),
                ],
                &[],
            ),
            read_only: false,
            destructive: false,
        },
    ]
}

fn held_line(held: &InterceptedPacket, now_micros: i64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let seconds = |micros: i64| micros as f64 / 1_000_000.0;
    let mut line = format!(
        "[{}] {} {} {} {} {} held {:.1}s c={}",
        held.id,
        render::dir(held.summary.direction),
        render::state(held.summary.state),
        held.summary
            .packet_id
            .map_or_else(|| "--".to_owned(), |id| format!("0x{id:02x}")),
        held.summary.name.as_deref().unwrap_or("?"),
        render::bytes(held.logical_bytes.len() as u64),
        seconds(now_micros - held.held_at_micros),
        render::short_id(held.summary.connection_id),
    );
    if let Some(deadline) = held.deadline_micros {
        let _ = write!(
            line,
            " auto-forward in {:.1}s",
            seconds(deadline - now_micros).max(0.0)
        );
    }
    let insight = inspect_logical(
        held.summary.state,
        held.summary.direction,
        &held.logical_bytes,
        held.summary.protocol_version,
    );
    if let Some(summary) = insight.summary {
        let _ = write!(line, " — {}", render::truncate(&summary, 160));
    }
    line
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
        })
}

fn intercept_status(proxy: &mineburp_proxy::ProxyService) -> String {
    let settings = proxy.intercept_settings();
    let mut out = format!(
        "intercept {} | c2s={} s2c={} | expr={} | keep-alives {} | auto-forward {}",
        if settings.enabled { "ON" } else { "off" },
        settings.client_to_server,
        settings.server_to_client,
        if settings.expression.is_empty() {
            "(all)".to_owned()
        } else {
            format!("`{}`", settings.expression)
        },
        if settings.forward_keep_alive {
            "pass"
        } else {
            "held"
        },
        settings
            .auto_forward_after_ms
            .map_or_else(|| "never".to_owned(), |ms| format!("{ms}ms")),
    );
    let held = proxy.intercepted();
    let now = now_micros();
    if held.is_empty() {
        out.push_str("\nheld: none");
    } else {
        let _ = write!(out, "\nheld: {}", held.len());
        for packet in held.iter().take(50) {
            out.push('\n');
            out.push_str(&held_line(packet, now));
        }
        if held.len() > 50 {
            let _ = write!(out, "\n…+{} more", held.len() - 50);
        }
    }
    out
}

fn find_held(proxy: &mineburp_proxy::ProxyService, id: u64) -> Result<InterceptedPacket, String> {
    proxy
        .intercepted()
        .into_iter()
        .find(|held| held.id == id)
        .ok_or_else(|| format!("frame [{id}] is no longer held"))
}

fn held_frame(held: &InterceptedPacket) -> Frame {
    Frame {
        bytes: held.logical_bytes.to_vec(),
        state: held.summary.state,
        direction: held.summary.direction,
        protocol: held.summary.protocol_version,
        connection: Some(held.summary.connection_id),
        name: held.summary.name.clone(),
    }
}

pub async fn intercept(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let proxy = ctx.proxy()?;
    match args.action("status").as_str() {
        "status" => Ok(intercept_status(&proxy)),
        "set" => {
            let current = proxy.intercept_settings();
            let expression = match args.get("expr").and_then(Value::as_str) {
                Some(text) => {
                    let text = text.trim().to_owned();
                    if !text.is_empty() {
                        mineburp_core::FilterExpression::parse(&text)
                            .map_err(|error| error.to_string())?;
                    }
                    text
                }
                None => current.expression.clone(),
            };
            let settings = InterceptSettings {
                enabled: args.bool("enabled").unwrap_or(current.enabled),
                client_to_server: args.bool("c2s").unwrap_or(current.client_to_server),
                server_to_client: args.bool("s2c").unwrap_or(current.server_to_client),
                expression,
                forward_keep_alive: args
                    .bool("forward_keep_alive")
                    .unwrap_or(current.forward_keep_alive),
                auto_forward_after_ms: match args.u64("auto_forward_ms") {
                    Some(0) => None,
                    Some(ms) => Some(ms),
                    None => current.auto_forward_after_ms,
                },
            };
            proxy
                .set_intercept_settings(settings)
                .map_err(|error| error.to_string())?;
            ctx.host.notify("intercept");
            Ok(intercept_status(&proxy))
        }
        "show" => {
            let held = find_held(&proxy, args.u64("id").ok_or("`id` is required")?)?;
            let frame = held_frame(&held);
            let mut out = held_line(&held, now_micros());
            let hex_limit = args.usize("hex_limit").unwrap_or(512).min(65536);
            let decoded = blocking(move || {
                let insight =
                    inspect_logical(frame.state, frame.direction, &frame.bytes, frame.protocol);
                Ok(format!(
                    "{}\nhex: {}",
                    render::insight(&insight, TreeLimits::default(), None),
                    render::capped_hex(&frame.bytes, hex_limit)
                ))
            })
            .await?;
            out.push('\n');
            out.push_str(&decoded);
            Ok(out)
        }
        "forward" => {
            let id = args.u64("id").ok_or("`id` is required")?;
            let edits = args.edits()?;
            let decision = if let Some(text) = args.str("hex") {
                InterceptDecision::Replace(Bytes::from(parse_hex(text)?))
            } else if edits.is_empty() {
                InterceptDecision::Forward
            } else {
                let frame = held_frame(&find_held(&proxy, id)?);
                InterceptDecision::Replace(Bytes::from(frames::apply(&frame, &edits)?))
            };
            let edited = matches!(decision, InterceptDecision::Replace(_));
            proxy
                .resolve_intercept(id, decision)
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "[{id}] forwarded{}",
                if edited { " (edited)" } else { "" }
            ))
        }
        "drop" => {
            let id = args.u64("id").ok_or("`id` is required")?;
            proxy
                .resolve_intercept(id, InterceptDecision::Drop)
                .map_err(|error| error.to_string())?;
            Ok(format!("[{id}] dropped"))
        }
        "forward_all" => Ok(format!("forwarded {}", proxy.forward_all_intercepted())),
        "wait" => {
            let wait = args.u64("wait_ms").unwrap_or(10_000).min(MAX_WAIT_MS);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(wait);
            while proxy.intercepted().is_empty() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(intercept_status(&proxy))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

pub fn network(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let proxy = ctx.proxy()?;
    let mut conditions = if args.flag("reset") {
        mineburp_proxy::NetworkConditions::default()
    } else {
        proxy.network_conditions()
    };
    let mut changed = args.flag("reset");
    let update = |link: &mut LinkConditions, prefix: &str, changed: &mut bool| {
        let read = |key: &str| args.u64(&format!("{prefix}_{key}"));
        if let Some(delay) = read("delay_ms") {
            link.delay_ms = u32::try_from(delay).unwrap_or(u32::MAX);
            *changed = true;
        }
        if let Some(jitter) = read("jitter_ms") {
            link.jitter_ms = u32::try_from(jitter).unwrap_or(u32::MAX);
            *changed = true;
        }
        if let Some(bandwidth) = read("bandwidth") {
            link.bandwidth_bytes_per_second = (bandwidth > 0).then_some(bandwidth);
            *changed = true;
        }
    };
    update(&mut conditions.client_to_server, "c2s", &mut changed);
    update(&mut conditions.server_to_client, "s2c", &mut changed);
    if changed {
        proxy
            .set_network_conditions(conditions)
            .map_err(|error| error.to_string())?;
        ctx.host.notify("network");
    }
    let describe = |link: &LinkConditions| {
        if link.is_neutral() {
            "none".to_owned()
        } else {
            format!(
                "delay {}ms jitter {}ms bandwidth {}",
                link.delay_ms,
                link.jitter_ms,
                link.bandwidth_bytes_per_second.map_or_else(
                    || "unlimited".to_owned(),
                    |rate| format!("{}/s", render::bytes(rate))
                )
            )
        }
    };
    let current = proxy.network_conditions();
    Ok(format!(
        "C>S: {}\nS>C: {}",
        describe(&current.client_to_server),
        describe(&current.server_to_client)
    ))
}

async fn find_tab(ctx: &Ctx<'_>, needle: &str) -> Result<RepeaterTab, String> {
    let store = ctx.project()?;
    let tabs = blocking(move || {
        store
            .load_repeater_tabs()
            .map_err(|error| error.to_string())
    })
    .await?;
    let needle = needle.to_ascii_lowercase();
    let mut matches = tabs.into_iter().filter(|tab| {
        tab.id.simple().to_string().starts_with(&needle) || tab.name.to_ascii_lowercase() == needle
    });
    match (matches.next(), matches.next()) {
        (Some(tab), None) => Ok(tab),
        (None, _) => Err(format!("no Repeater tab `{needle}`")),
        (Some(_), Some(_)) => Err(format!("tab `{needle}` is ambiguous")),
    }
}

pub async fn repeater(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    match args.action("list").as_str() {
        "list" => {
            let store = ctx.project()?;
            let tabs = blocking(move || {
                store
                    .load_repeater_tabs()
                    .map_err(|error| error.to_string())
            })
            .await?;
            if tabs.is_empty() {
                return Ok("no Repeater tabs".into());
            }
            Ok(tabs
                .iter()
                .map(|tab| {
                    let insight = inspect_logical(
                        tab.state,
                        tab.direction,
                        &tab.logical_bytes,
                        tab.protocol_version,
                    );
                    format!(
                        "{} {} c={} {} {} {}B {}",
                        &tab.id.simple().to_string()[..8],
                        tab.name,
                        render::short_id(tab.connection_id),
                        render::dir(tab.direction),
                        render::state(tab.state),
                        tab.logical_bytes.len(),
                        insight.name.as_deref().unwrap_or("?")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "save" => {
            let store = ctx.project()?;
            let existing = match args.str("id") {
                Some(id) => Some(find_tab(ctx, id).await?),
                None => None,
            };
            let mut frame = if args.str("hex").is_some() || args.i64("packet").is_some() {
                Some(ctx.frame_from(args).await?)
            } else {
                None
            };
            if let Some(frame) = frame.as_mut() {
                let edits = args.edits()?;
                frame.bytes = frames::apply(frame, &edits)?;
            }
            let connection = match args.str("connection") {
                Some(text) => Some(ctx.resolve_connection(text).await?),
                None => frame.as_ref().and_then(|frame| frame.connection),
            };
            let tab = match (existing, frame) {
                (Some(mut tab), frame) => {
                    if let Some(name) = args.str("name") {
                        name.clone_into(&mut tab.name);
                    }
                    if let Some(connection) = connection {
                        tab.connection_id = connection;
                    }
                    if let Some(frame) = frame {
                        tab.logical_bytes = Bytes::from(frame.bytes);
                        tab.direction = frame.direction;
                        tab.state = frame.state;
                        tab.protocol_version = frame.protocol.or(tab.protocol_version);
                    }
                    tab
                }
                (None, Some(frame)) => RepeaterTab {
                    edit_history: None,
                    id: Uuid::new_v4(),
                    name: args
                        .str("name")
                        .map(str::to_owned)
                        .or_else(|| frame.name.clone())
                        .unwrap_or_else(|| "tab".into()),
                    connection_id: connection
                        .ok_or("`connection` is required for a frame given as hex")?,
                    direction: frame.direction,
                    state: frame.state,
                    protocol_version: frame.protocol,
                    logical_bytes: Bytes::from(frame.bytes),
                    decoded: None,
                },
                (None, None) => return Err("give `hex` or `packet` for a new tab".into()),
            };
            let saved = tab.clone();
            blocking(move || {
                store
                    .save_repeater_tab(&saved)
                    .map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.notify("repeater");
            Ok(format!(
                "saved tab {} {}",
                &tab.id.simple().to_string()[..8],
                tab.name
            ))
        }
        "delete" => {
            let store = ctx.project()?;
            let tab = find_tab(ctx, args.require_str("id")?).await?;
            let id = tab.id;
            blocking(move || {
                store
                    .delete_repeater_tab(id)
                    .map_err(|error| error.to_string())
            })
            .await?;
            ctx.host.notify("repeater");
            Ok(format!("deleted tab {}", tab.name))
        }
        "send" => {
            let proxy = ctx.proxy()?;
            let mut frame = if let Some(tab) = args.str("tab") {
                let tab = find_tab(ctx, tab).await?;
                Frame {
                    bytes: tab.logical_bytes.to_vec(),
                    state: tab.state,
                    direction: tab.direction,
                    protocol: tab.protocol_version,
                    connection: Some(tab.connection_id),
                    name: None,
                }
            } else {
                ctx.frame_from(args).await?
            };
            if let Some(direction) = args.direction("dir")? {
                frame.direction = direction;
            }
            let edits = args.edits()?;
            let bytes = frames::apply(&frame, &edits)?;
            let live: Vec<Uuid> = proxy.sessions().iter().map(|session| session.id).collect();
            let connection = match args.str("connection") {
                Some(text) => ctx.resolve_connection(text).await?,
                None => match frame.connection.filter(|id| live.contains(id)) {
                    Some(id) => id,
                    None => ctx.only_live_session()?,
                },
            };
            let direction = frame.direction;
            let length = bytes.len();
            let name = inspect_logical(frame.state, direction, &bytes, frame.protocol).name;
            proxy
                .repeater_send(connection, direction, Bytes::from(bytes))
                .await
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "sent {} {length}B {} on c={}",
                render::dir(direction),
                name.as_deref().unwrap_or("frame"),
                render::short_id(connection)
            ))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

pub async fn capture(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let host = ctx.host;
    match args.action("status").as_str() {
        "status" => {
            let capture = host.capture().ok_or(crate::DESKTOP_ONLY)?;
            let probe = capture.clone();
            let capabilities = tokio::task::spawn_blocking(move || probe.capabilities())
                .await
                .map_err(|error| error.to_string())?;
            let stats = capture.stats().await;
            let mut out = format!(
                "backend {}: {}{}{}",
                capabilities.backend,
                if capabilities.available {
                    "available"
                } else {
                    "unavailable"
                },
                if capabilities.process_attribution {
                    ", process attribution"
                } else {
                    ""
                },
                capabilities
                    .reason
                    .map(|reason| format!(" ({reason})"))
                    .unwrap_or_default()
            );
            let _ = write!(
                out,
                "\n{} | seen {} frames {} | kept {} {} | dropped {} | held {} | retrans {} | reordered {} | gaps {} | errors {}",
                if stats.running { "running" } else { "stopped" },
                stats.frames_seen,
                render::bytes(stats.bytes_seen),
                stats.frames_emitted,
                render::bytes(stats.bytes_emitted),
                stats.frames_dropped,
                stats.frames_held,
                stats.retransmissions,
                stats.reordered,
                stats.gaps,
                stats.errors
            );
            if let Some(error) = stats.last_error {
                let _ = write!(out, "\nlast error: {error}");
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
            Ok(out)
        }
        "start" => {
            host.capture()
                .ok_or(crate::DESKTOP_ONLY)?
                .start()
                .await
                .map_err(|error| error.to_string())?;
            host.notify("capture");
            Ok("capture started".into())
        }
        "stop" => {
            host.capture()
                .ok_or(crate::DESKTOP_ONLY)?
                .stop()
                .await
                .map_err(|error| error.to_string())?;
            host.notify("capture");
            Ok("capture stopped".into())
        }
        "decrypt" => {
            let enabled = args.bool("enabled").ok_or("`enabled` is required")?;
            host.set_decrypt_mode(enabled)?;
            host.notify("decrypt");
            Ok(format!(
                "decrypt mode {}{}",
                if enabled { "on" } else { "off" },
                if enabled {
                    "; clients launched with client assistance now route through the proxy"
                } else {
                    ""
                }
            ))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

async fn find_instance(ctx: &Ctx<'_>, needle: &str) -> Result<InstanceDescriptor, String> {
    let instances = ctx.host.launcher_instances().await?;
    let lower = needle.to_ascii_lowercase();
    if let Some(exact) = instances.iter().find(|instance| instance.id == needle) {
        return Ok(exact.clone());
    }
    let matches: Vec<&InstanceDescriptor> = instances
        .iter()
        .filter(|instance| instance.name.to_ascii_lowercase().contains(&lower))
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("no instance matches `{needle}`")),
        many => Err(format!(
            "`{needle}` matches {} instances: {}",
            many.len(),
            many.iter()
                .map(|instance| instance.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub async fn launcher(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    match args.action("instances").as_str() {
        "instances" => {
            let instances = ctx.host.launcher_instances().await?;
            if instances.is_empty() {
                return Ok("no launcher instances found".into());
            }
            Ok(instances
                .iter()
                .map(|instance| {
                    format!(
                        "{} | {} | {} | {} {} | assist: {}",
                        instance.id,
                        render::enum_name(&instance.launcher),
                        instance.name,
                        instance.minecraft_version.as_deref().unwrap_or("?"),
                        render::enum_name(&instance.loader),
                        if instance.client_assist_configured {
                            "on"
                        } else if instance.supports_agent_configuration {
                            "off"
                        } else {
                            "manual"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "launch" => {
            let instance = find_instance(ctx, args.require_str("instance")?).await?;
            let name = instance.name.clone();
            let outcome = ctx
                .host
                .launch(LaunchRequest {
                    instance,
                    profile_name: args.str("profile").map(str::to_owned),
                })
                .await?;
            Ok(format!("launched {name} (pid {})", outcome.process_id))
        }
        "assist" => {
            let instance = find_instance(ctx, args.require_str("instance")?).await?;
            let enabled = args.bool("enabled").ok_or("`enabled` is required")?;
            let outcome = ctx.host.configure_client_assist(instance, enabled).await?;
            Ok(format!(
                "{} — {}{}",
                render::enum_name(&outcome.kind),
                outcome.message,
                if outcome.configured {
                    String::new()
                } else {
                    format!("\nadd manually: {}", outcome.jvm_argument)
                }
            ))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

/// Explicit routes let small protocol test clients use the live workbench.
pub async fn route(ctx: &Ctx<'_>, args: &Args) -> ToolResult {
    let proxy = ctx.proxy()?;
    let host = args
        .str("host")
        .filter(|host| !host.trim().is_empty())
        .ok_or("host is required")?;
    let port = match args.raw().get("port") {
        Some(value) => value
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("port must be an integer in 1..65535")?,
        None => 25565,
    };
    if proxy
        .sessions()
        .iter()
        .filter(|session| session.status == mineburp_core::ConnectionStatus::Listening)
        .count()
        >= 16
    {
        return Err("too many pending routes; connect or wait for expiry".into());
    }
    let session = proxy
        .start_session(mineburp_proxy::SessionOptions::new(mineburp_core::Target {
            host: host.into(),
            port,
        }))
        .await
        .map_err(|error| error.to_string())?;
    ctx.host.notify("connections");
    Ok(format!(
        "c={} listen={} target={} expires in 15s",
        session.id,
        session.listener_address,
        session.target.authority()
    ))
}
