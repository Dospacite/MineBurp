//! Turns a decoded field tree into something an analyst can read.
//!
//! The data-driven decoder reports exactly what is on the wire, which is not
//! always what a person wants to look at: a chat line is an NBT compound, a
//! skin is base64-encoded JSON inside a profile property, and a command tree is
//! a flat array of nodes pointing at each other by index. This module adds
//! readable companions next to those values without removing anything, so the
//! raw decode is still there for anyone who needs it.
//!
//! It also surfaces what a security review cares about most in server-sent
//! content: every *interactive* element — click actions that run or suggest a
//! command, open a URL, copy to the clipboard, or open a dialog — is collected
//! into one `interactive_events` list with the path it was found at, so a
//! hostile `run_command` cannot hide three levels deep in a hover tooltip.

use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::nbt::component_to_text;

const MAX_DEPTH: usize = 48;
const MAX_EVENTS: usize = 128;
const MAX_COMMANDS: usize = 2_000;
const MAX_COMMAND_DEPTH: usize = 24;
/// Nodes visited while walking a command graph. A graph is a server's to
/// shape, and one whose children loop back on themselves multiplies the paths
/// at every level; this bounds the walk however the graph is drawn.
const MAX_COMMAND_VISITS: usize = 20_000;
const MAX_TEXT: usize = 4_096;

/// Click actions a component or dialog can carry, in their JSON (camel) and
/// NBT (snake) spellings.
const CLICK_ACTIONS: &[&str] = &[
    "run_command",
    "suggest_command",
    "open_url",
    "open_file",
    "copy_to_clipboard",
    "change_page",
    "show_dialog",
    "custom",
];

/// Adds readable companions to a decoded packet's fields.
#[must_use]
pub fn present(name: &str, fields: Value) -> Value {
    let mut fields = enrich(fields, 0);
    let events = interactive_events(&fields);
    if let Value::Object(object) = &mut fields {
        if (name == "declare_commands" || name == "commands")
            && let Some(commands) = command_paths(object)
        {
            object.insert("commands".into(), commands);
        }
        if !events.is_empty() {
            object.insert("interactive_events".into(), Value::Array(events));
        }
    }
    fields
}

/// The interactive elements found anywhere inside one value, for decoders that
/// build their own fields.
#[must_use]
pub fn interactive_events(value: &Value) -> Vec<Value> {
    let mut events = Vec::new();
    collect_events(value, "", &mut events, 0);
    events
}

fn enrich(value: Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return value;
    }
    match value {
        Value::Object(map) => {
            let mut output = Map::new();
            for (key, value) in map {
                let companion = companion_for(&key, &value);
                let value = match (key.as_str(), &value) {
                    ("timestamp", Value::Number(number)) => number
                        .as_i64()
                        .filter(|millis| plausible_timestamp(*millis))
                        .map_or(value.clone(), |millis| Value::String(format_millis(millis))),
                    _ => enrich(value, depth + 1),
                };
                output.insert(key.clone(), value);
                if let Some((suffix, companion)) = companion {
                    output.insert(format!("{key}{suffix}"), companion);
                }
            }
            if let Some(decoded) = decode_textures(&output) {
                output.insert("decoded".into(), decoded);
            }
            Value::Object(output)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| enrich(item, depth + 1))
                .collect(),
        ),
        other => other,
    }
}

/// A rendered-text companion for a field holding a text component — an NBT
/// compound, or (before 1.20.3) a JSON string.
fn companion_for(key: &str, value: &Value) -> Option<(&'static str, Value)> {
    let suffix = if key.ends_with("text") {
        "_rendered"
    } else {
        "_text"
    };
    match value {
        Value::Object(map) if looks_like_component(map) => {
            let text = component_to_text(value);
            (!text.is_empty()).then(|| (suffix, Value::String(clip(&text))))
        }
        Value::String(raw) => {
            let trimmed = raw.trim_start();
            if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
                return None;
            }
            let parsed: Value = serde_json::from_str(raw).ok()?;
            let is_component = match &parsed {
                Value::Object(map) => looks_like_component(map),
                Value::Array(items) => items.iter().any(|item| {
                    item.as_object().is_some_and(looks_like_component) || item.is_string()
                }),
                _ => false,
            };
            if !is_component {
                return None;
            }
            let text = component_to_text(&parsed);
            (!text.is_empty()).then(|| (suffix, Value::String(clip(&text))))
        }
        _ => None,
    }
}

fn looks_like_component(map: &Map<String, Value>) -> bool {
    ["text", "translate", "keybind", "selector", "score", "extra"]
        .iter()
        .any(|key| match map.get(*key) {
            Some(Value::String(_)) => true,
            Some(Value::Array(_)) => *key == "extra",
            Some(Value::Object(_)) => *key == "score",
            _ => false,
        })
}

/// Collects click actions (and the hover text that disguises them) from a
/// component or dialog tree.
fn collect_events(value: &Value, path: &str, events: &mut Vec<Value>, depth: usize) {
    if depth > MAX_DEPTH || events.len() >= MAX_EVENTS {
        return;
    }
    match value {
        Value::Object(map) => {
            for key in ["clickEvent", "click_event"] {
                if let Some(event) = map.get(key).and_then(Value::as_object)
                    && let Some(found) = click_event(event, &join(path, key))
                {
                    events.push(found);
                }
            }
            // Dialog actions (1.21.6+) carry the action under `type`.
            if let Some(kind) = map.get("type").and_then(Value::as_str)
                && CLICK_ACTIONS.contains(&strip_namespace(kind))
                && let Some(found) = click_event(map, path)
            {
                events.push(found);
            }
            if let Some(insertion) = map.get("insertion").and_then(Value::as_str) {
                events.push(json!({
                    "path": join(path, "insertion"),
                    "action": "insertion",
                    "value": clip(insertion),
                }));
            }
            for (key, child) in map {
                if key == "clickEvent" || key == "click_event" {
                    continue;
                }
                collect_events(child, &join(path, key), events, depth + 1);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_events(item, &format!("{path}[{index}]"), events, depth + 1);
            }
        }
        Value::String(raw) if raw.trim_start().starts_with('{') && raw.len() < 262_144 => {
            if let Ok(parsed) = serde_json::from_str::<Value>(raw)
                && parsed.is_object()
            {
                collect_events(&parsed, path, events, depth + 1);
            }
        }
        _ => {}
    }
}

fn click_event(event: &Map<String, Value>, path: &str) -> Option<Value> {
    let action = event
        .get("action")
        .or_else(|| event.get("type"))
        .and_then(Value::as_str)?;
    let action = strip_namespace(action);
    if !CLICK_ACTIONS.contains(&action) {
        return None;
    }
    let value = [
        "value", "command", "url", "path", "page", "dialog", "id", "payload",
    ]
    .iter()
    .find_map(|key| event.get(*key))
    .map_or(Value::Null, |value| match value {
        Value::String(text) => Value::String(clip(text)),
        other => other.clone(),
    });
    Some(json!({ "path": path, "action": action, "value": value }))
}

/// Decodes a `textures` profile property: base64 JSON naming the skin and cape
/// URLs a client will fetch.
fn decode_textures(map: &Map<String, Value>) -> Option<Value> {
    if map.get("name").and_then(Value::as_str) != Some("textures") {
        return None;
    }
    let encoded = map.get("value").and_then(Value::as_str)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let parsed: Value = serde_json::from_slice(&bytes).ok()?;
    let mut decoded = Map::new();
    for key in ["profileName", "profileId", "timestamp"] {
        if let Some(value) = parsed.get(key) {
            decoded.insert(key.into(), value.clone());
        }
    }
    if let Some(textures) = parsed.get("textures").and_then(Value::as_object) {
        for (kind, texture) in textures {
            if let Some(url) = texture.get("url") {
                decoded.insert(format!("{}_url", kind.to_ascii_lowercase()), url.clone());
            }
        }
    }
    Some(Value::Object(decoded))
}

/// Reconstructs the command syntax a server declares from its node graph:
/// every path from the root to an executable node, literals as written and
/// arguments in angle brackets with their parser.
fn command_paths(fields: &Map<String, Value>) -> Option<Value> {
    let nodes = fields.get("nodes")?.as_array()?;
    let root = usize::try_from(fields.get("root_index")?.as_u64()?).ok()?;
    let mut output = Vec::new();
    let mut stack: Vec<(usize, Vec<String>, usize)> = vec![(root, Vec::new(), 0)];
    let mut visits = 0usize;
    while let Some((index, words, depth)) = stack.pop() {
        visits += 1;
        if output.len() >= MAX_COMMANDS || visits > MAX_COMMAND_VISITS {
            output.push(Value::String("…".into()));
            break;
        }
        let Some(node) = nodes.get(index) else {
            continue;
        };
        let flags = node.get("flags");
        let executable = flags
            .and_then(|flags| flags.get("has_command"))
            .and_then(Value::as_u64)
            == Some(1);
        let data = node.get("extra_node_data");
        let name = data
            .and_then(|data| data.get("name"))
            .and_then(Value::as_str);
        let kind = flags
            .and_then(|flags| flags.get("command_node_type"))
            .and_then(Value::as_u64);
        let mut words = words;
        match (kind, name) {
            (Some(1), Some(name)) => words.push(name.to_owned()),
            (Some(2), Some(name)) => {
                let parser = data
                    .and_then(|data| data.get("parser"))
                    .and_then(Value::as_str)
                    .map_or("argument", strip_namespace);
                words.push(format!("<{name}:{parser}>"));
            }
            _ => {}
        }
        if executable && !words.is_empty() {
            output.push(Value::String(format!("/{}", words.join(" "))));
        }
        if depth >= MAX_COMMAND_DEPTH {
            continue;
        }
        if let Some(children) = node.get("children").and_then(Value::as_array) {
            for child in children.iter().rev() {
                if let Some(child) = child.as_u64().and_then(|child| usize::try_from(child).ok()) {
                    stack.push((child, words.clone(), depth + 1));
                }
            }
        }
    }
    Some(Value::Array(output))
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn strip_namespace(value: &str) -> &str {
    value.strip_prefix("minecraft:").unwrap_or(value)
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_TEXT {
        return text.to_owned();
    }
    let clipped: String = text.chars().take(MAX_TEXT).collect();
    format!("{clipped}…")
}

pub(crate) fn plausible_timestamp(value: i64) -> bool {
    const YEAR_2015: i64 = 1_420_070_400_000;
    const YEAR_2100: i64 = 4_102_444_800_000;
    (YEAR_2015..YEAR_2100).contains(&value)
}

pub(crate) fn format_millis(value: i64) -> String {
    let seconds = value.div_euclid(1_000);
    time::OffsetDateTime::from_unix_timestamp(seconds).map_or_else(
        |_| value.to_string(),
        |moment| {
            moment
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| value.to_string())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_components_and_surfaces_click_actions_wherever_they_hide() {
        let fields = json!({
            "content": {
                "text": "Click ",
                "extra": [{
                    "text": "here",
                    "hover_event": { "action": "show_text", "value": "a free gift" },
                    "click_event": { "action": "run_command", "command": "/op attacker" }
                }]
            },
            "overlay": false
        });
        let presented = present("system_chat", fields);
        assert_eq!(presented["content_text"], "Click here");
        let events = presented["interactive_events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], "run_command");
        assert_eq!(events[0]["value"], "/op attacker");
        assert_eq!(events[0]["path"], "content.extra[0].click_event");
    }

    #[test]
    fn json_components_from_older_releases_are_read_too() {
        let fields = json!({
            "message": r#"{"text":"hi","clickEvent":{"action":"open_url","value":"https://example.invalid"}}"#
        });
        let presented = present("chat", fields);
        assert_eq!(presented["message_text"], "hi");
        assert_eq!(presented["interactive_events"][0]["action"], "open_url");
    }

    #[test]
    fn dialog_actions_are_interactive_events() {
        let fields = json!({ "dialog": { "actions": [
            { "label": { "text": "Yes" }, "action": { "type": "minecraft:run_command", "command": "/pay x 1" } }
        ] } });
        let presented = present("show_dialog", fields);
        assert_eq!(presented["interactive_events"][0]["value"], "/pay x 1");
    }

    #[test]
    fn decodes_skin_textures_inside_profile_properties() {
        let texture = base64::engine::general_purpose::STANDARD.encode(
            r#"{"profileName":"Notch","textures":{"SKIN":{"url":"http://textures.minecraft.net/texture/abc"}}}"#,
        );
        let fields =
            json!({ "properties": [{ "name": "textures", "value": texture, "signature": null }] });
        let presented = present("login_success", fields);
        assert_eq!(
            presented["properties"][0]["decoded"]["skin_url"],
            "http://textures.minecraft.net/texture/abc"
        );
        assert_eq!(
            presented["properties"][0]["decoded"]["profileName"],
            "Notch"
        );
    }

    #[test]
    fn reconstructs_command_syntax_from_the_node_graph() {
        let node = |kind: u64, executable: u64, children: Value, data: Value| {
            json!({
                "flags": { "command_node_type": kind, "has_command": executable },
                "children": children,
                "extra_node_data": data,
            })
        };
        let fields = json!({
            "nodes": [
                node(0, 0, json!([1]), Value::Null),
                node(1, 0, json!([2]), json!({ "name": "give" })),
                node(2, 1, json!([]), json!({ "name": "targets", "parser": "minecraft:entity" })),
            ],
            "root_index": 0,
        });
        let presented = present("declare_commands", fields);
        assert_eq!(presented["commands"], json!(["/give <targets:entity>"]));
    }

    #[test]
    fn a_command_graph_that_loops_on_itself_is_walked_in_bounded_time() {
        // Every node points at every node: the path count is exponential in
        // the depth, the walk must not be.
        let children: Vec<usize> = (0..8).collect();
        let nodes: Vec<Value> = (0..8)
            .map(|index| {
                json!({
                    "flags": { "command_node_type": 1, "has_command": 1 },
                    "children": children,
                    "extra_node_data": { "name": format!("n{index}") },
                })
            })
            .collect();
        let started = std::time::Instant::now();
        let presented = present("commands", json!({ "nodes": nodes, "root_index": 0 }));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(presented["commands"].as_array().unwrap().len() <= MAX_COMMANDS + 1);
    }

    #[test]
    fn plausible_timestamps_are_formatted() {
        let presented = present(
            "player_chat",
            json!({ "timestamp": 1_700_000_000_000_i64, "salt": 5 }),
        );
        assert_eq!(presented["timestamp"], "2023-11-14T22:13:20Z");
        assert_eq!(presented["salt"], 5);
    }
}
