//! Tool definitions and the helpers they share.
//!
//! Related actions share one tool with an `action` argument: a short tool
//! list costs every session less context than one tool per command.

#![allow(
    clippy::too_many_lines,
    reason = "a tool is one flat match over its actions; splitting it scatters the action list"
)]

mod frames;
mod history;
mod live;
mod project;

use mineburp_core::{ConnectionSnapshot, Direction, PacketEdit, ProtocolState};
use mineburp_project::{PacketQuery, ProjectStore};
use mineburp_protocol::PacketRegistry;
use mineburp_proxy::ProxyService;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{DESKTOP_ONLY, Host, ops::PacketFilterInput};

pub type ToolResult = Result<String, String>;

#[derive(Debug)]
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
    pub read_only: bool,
    pub destructive: bool,
}

pub fn catalog() -> Vec<Tool> {
    let mut tools = Vec::new();
    tools.extend(history::tools());
    tools.extend(frames::tools());
    tools.extend(live::tools());
    tools.extend(project::tools());
    tools
}

pub async fn dispatch(host: &dyn Host, name: &str, arguments: Value) -> ToolResult {
    let args = Args::new(arguments)?;
    let ctx = Ctx { host };
    match name {
        "status" => history::status(&ctx).await,
        "packets" => history::packets(&ctx, &args).await,
        "packet" => history::packet(&ctx, &args).await,
        "connections" => history::connections(&ctx, &args).await,
        "stats" => history::stats(&ctx, &args).await,
        "annotate" => history::annotate(&ctx, &args).await,
        "filters" => history::filters(&ctx, &args).await,
        "decode" => frames::decode(&ctx, &args).await,
        "rewrite" => frames::rewrite(&ctx, &args).await,
        "protocol" => frames::protocol(&args),
        "intercept" => live::intercept(&ctx, &args).await,
        "route" => live::route(&ctx, &args).await,
        "network" => live::network(&ctx, &args),
        "repeater" => live::repeater(&ctx, &args).await,
        "capture" => live::capture(&ctx, &args).await,
        "launcher" => live::launcher(&ctx, &args).await,
        "project" => project::project(&ctx, &args).await,
        "rules" => project::rules(&ctx, &args).await,
        "schemas" => project::schemas(&ctx, &args).await,
        _ => Err(format!("unknown tool `{name}`")),
    }
}

/// Builds a JSON schema object from `(name, schema)` pairs.
pub fn object(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let properties: Map<String, Value> = properties
        .iter()
        .map(|(name, schema)| ((*name).to_owned(), schema.clone()))
        .collect();
    let mut schema = json!({ "type": "object", "properties": properties });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

/// A schema with a description only when there is something to say: every
/// byte of the tool list is paid for by every session.
fn described(mut schema: Value, description: &str) -> Value {
    if !description.is_empty() {
        schema["description"] = json!(description);
    }
    schema
}

pub fn string(description: &str) -> Value {
    described(json!({ "type": "string" }), description)
}

pub fn integer(description: &str) -> Value {
    described(json!({ "type": "integer" }), description)
}

pub fn boolean(description: &str) -> Value {
    described(json!({ "type": "boolean" }), description)
}

pub fn choice(values: &[&str], description: &str) -> Value {
    described(json!({ "type": "string", "enum": values }), description)
}

pub fn strings(description: &str) -> Value {
    described(
        json!({ "type": "array", "items": { "type": "string" } }),
        description,
    )
}

/// The `filter` argument of tools other than `packets`.
pub fn filter_ref() -> Value {
    json!({ "type": "object", "description": "History filter; same keys as `packets` (expr, search, content, dir, states, names, connection, saved, …)" })
}

/// Edits shared by rewrite, rules, repeater, and intercept.
pub fn edits_schema() -> Value {
    json!({
        "type": "array",
        "description": "Applied in order. kinds: field{name,value} | field_replace{name,find,replace,regex?} | text{find,replace,all?,case_insensitive?} | bytes{find,replace,all?} (hex) | regex{pattern,replace,all?} | range{offset,length,bytes} | frame{bytes}",
        "items": { "type": "object", "properties": { "kind": { "type": "string" } }, "required": ["kind"] }
    })
}

/// `edits` for tools other than `rewrite`, which documents the format.
pub fn edits_ref() -> Value {
    json!({ "type": "array", "items": { "type": "object" }, "description": "edit list; format as in `rewrite`" })
}

pub fn set_schema() -> Value {
    json!({ "type": "object", "description": "Shorthand for field edits: {\"field_name\": value}" })
}

/// Arguments of one call.
#[derive(Debug)]
pub struct Args(Map<String, Value>);

impl Args {
    fn new(value: Value) -> Result<Self, String> {
        match value {
            Value::Object(map) => Ok(Self(map)),
            Value::Null => Ok(Self(Map::new())),
            _ => Err("arguments must be an object".into()),
        }
    }

    pub fn raw(&self) -> &Map<String, Value> {
        &self.0
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key).filter(|value| !value.is_null())
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    }

    pub fn require_str(&self, key: &str) -> Result<&str, String> {
        self.str(key).ok_or_else(|| format!("`{key}` is required"))
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|value| match value {
            Value::Bool(flag) => Some(*flag),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
    }

    pub fn flag(&self, key: &str) -> bool {
        self.bool(key).unwrap_or(false)
    }

    pub fn i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|value| match value {
            Value::Number(number) => number.as_i64(),
            Value::String(text) => text.trim().trim_start_matches('#').parse().ok(),
            _ => None,
        })
    }

    pub fn require_i64(&self, key: &str) -> Result<i64, String> {
        self.i64(key).ok_or_else(|| format!("`{key}` is required"))
    }

    pub fn usize(&self, key: &str) -> Option<usize> {
        self.i64(key).and_then(|value| usize::try_from(value).ok())
    }

    pub fn u64(&self, key: &str) -> Option<u64> {
        self.i64(key).and_then(|value| u64::try_from(value).ok())
    }

    pub fn action(&self, default: &'static str) -> String {
        self.str("action").unwrap_or(default).to_ascii_lowercase()
    }

    pub fn parse<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        self.get(key)
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|error| format!("`{key}`: {error}"))
            })
            .transpose()
    }

    pub fn direction(&self, key: &str) -> Result<Option<Direction>, String> {
        self.str(key).map(parse_direction).transpose()
    }

    pub fn state(&self, key: &str) -> Result<Option<ProtocolState>, String> {
        self.str(key).map(parse_state).transpose()
    }

    pub fn protocol(&self, key: &str) -> Result<Option<i32>, String> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Number(number)) => number
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(Some)
                .ok_or_else(|| format!("`{key}` is not a protocol number")),
            Some(Value::String(text)) => resolve_protocol(text)
                .map(Some)
                .ok_or_else(|| format!("unknown protocol or version `{text}`")),
            Some(_) => Err(format!("`{key}` must be a number or version string")),
        }
    }

    /// `edits` plus the `set` shorthand, as one edit list.
    pub fn edits(&self) -> Result<Vec<PacketEdit>, String> {
        let mut edits: Vec<PacketEdit> = self.parse("edits")?.unwrap_or_default();
        if let Some(Value::Object(set)) = self.get("set") {
            for (name, value) in set {
                let value = match value {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                };
                edits.push(PacketEdit::Field {
                    name: name.clone(),
                    value,
                });
            }
        }
        Ok(edits)
    }
}

pub fn parse_direction(text: &str) -> Result<Direction, String> {
    match text.to_ascii_lowercase().as_str() {
        "c2s" | "c>s" | "client_to_server" | "serverbound" | "client" => {
            Ok(Direction::ClientToServer)
        }
        "s2c" | "s>c" | "server_to_client" | "clientbound" | "server" => {
            Ok(Direction::ServerToClient)
        }
        _ => Err(format!("direction `{text}` is not c2s or s2c")),
    }
}

pub fn parse_state(text: &str) -> Result<ProtocolState, String> {
    serde_json::from_value(Value::String(text.to_ascii_lowercase())).map_err(|_| {
        format!("state `{text}` is not handshake|status|login|configuration|play|opaque")
    })
}

/// A protocol number from `767` or a release name like `1.21.1`.
pub fn resolve_protocol(text: &str) -> Option<i32> {
    let text = text.trim();
    if let Ok(number) = text.trim_start_matches('p').parse::<i32>() {
        return Some(number);
    }
    PacketRegistry::bundled()
        .supported_protocols()
        .into_iter()
        .find(|version| {
            version.canonical == text || version.releases.iter().any(|release| release == text)
        })
        .map(|version| version.protocol)
}

/// Parses hex the way people paste it: whitespace, `:`, `,` and `0x` allowed.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let compact: String = text
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ':' | ';'))
        .map(|token| {
            token
                .trim_start_matches("0x")
                .trim_start_matches("0X")
                .replace("\\x", "")
        })
        .collect();
    hex::decode(&compact).map_err(|error| format!("bad hex: {error}"))
}

/// Runs blocking project work off the async runtime.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| error.to_string())?
}

/// Largest frame loaded whole for decoding or editing.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Every key a history filter object accepts.
///
/// Kept separate from `history::filter_properties` because that list also
/// carries the members of the `packets` tool that are not filters. A typo in a
/// filter key used to be ignored, which silently widened a query to the whole
/// history; callers now get an error naming the key.
const FILTER_KEYS: &[&str] = &[
    "expr",
    "search",
    "search_regex",
    "search_case",
    "search_not",
    "content",
    "content_mode",
    "content_scope",
    "content_case",
    "content_not",
    "dir",
    "states",
    "sources",
    "dispositions",
    "names",
    "exclude_names",
    "min_size",
    "max_size",
    "connection",
    "bookmarked",
    "saved",
];

/// The members of the `packets` tool that are not part of the filter itself.
const PACKETS_EXTRA_KEYS: &[&str] = &["limit", "before", "after", "wait_ms", "summaries"];

fn reject_unknown_keys(
    arguments: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(key) = arguments
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
    {
        return Err(format!(
            "unknown {context} `{key}`; accepted: {}",
            allowed.join(", ")
        ));
    }
    Ok(())
}

/// The subset of the `packets` arguments that is a filter.
#[must_use]
pub fn filter_map(arguments: &Map<String, Value>) -> Map<String, Value> {
    arguments
        .iter()
        .filter(|(key, _)| FILTER_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Rejects a `packets` call with a key the tool does not understand.
pub fn check_packet_arguments(arguments: &Map<String, Value>) -> Result<(), String> {
    let mut allowed = FILTER_KEYS.to_vec();
    allowed.extend_from_slice(PACKETS_EXTRA_KEYS);
    reject_unknown_keys(arguments, &allowed, "packets argument")
}

/// A frame plus what is known about it.
#[derive(Debug, Clone)]
pub struct Frame {
    pub bytes: Vec<u8>,
    pub state: ProtocolState,
    pub direction: Direction,
    pub protocol: Option<i32>,
    pub connection: Option<Uuid>,
    pub name: Option<String>,
}

pub struct Ctx<'a> {
    pub host: &'a dyn Host,
}

impl Ctx<'_> {
    pub fn project(&self) -> Result<ProjectStore, String> {
        self.host.project().ok_or_else(|| {
            "no project is open; use `project` action=open path=/abs/file.mineburp".into()
        })
    }

    pub fn proxy(&self) -> Result<ProxyService, String> {
        self.host.proxy().ok_or_else(|| DESKTOP_ONLY.into())
    }

    /// Every connection: the project's rows overlaid with live sessions.
    pub async fn connections(&self) -> Result<Vec<(ConnectionSnapshot, bool)>, String> {
        let stored = match self.host.project() {
            Some(store) => {
                blocking(move || {
                    store
                        .list_connections(1_000)
                        .map_err(|error| error.to_string())
                })
                .await?
            }
            None => Vec::new(),
        };
        let live = self
            .host
            .proxy()
            .map(|proxy| proxy.sessions())
            .unwrap_or_default();
        let mut merged: Vec<(ConnectionSnapshot, bool)> = stored
            .into_iter()
            .filter(|row| !live.iter().any(|session| session.id == row.id))
            .map(|row| (row, false))
            .collect();
        merged.extend(live.into_iter().map(|session| (session, true)));
        merged.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then(right.0.packet_count.cmp(&left.0.packet_count))
        });
        Ok(merged)
    }

    /// Resolves a full id or a unique prefix to a connection id.
    pub async fn resolve_connection(&self, text: &str) -> Result<Uuid, String> {
        if let Ok(id) = Uuid::parse_str(text) {
            return Ok(id);
        }
        let needle = text
            .trim()
            .trim_start_matches("c=")
            .replace('-', "")
            .to_ascii_lowercase();
        if needle.is_empty() {
            return Err("empty connection id".into());
        }
        let matches: Vec<Uuid> = self
            .connections()
            .await?
            .into_iter()
            .map(|(connection, _)| connection.id)
            .filter(|id| id.simple().to_string().starts_with(&needle))
            .collect();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => Err(format!("no connection matches `{text}`; see `connections`")),
            _ => Err(format!("connection prefix `{text}` is ambiguous")),
        }
    }

    /// The single live session, when there is exactly one.
    pub fn only_live_session(&self) -> Result<Uuid, String> {
        let sessions = self.proxy()?.sessions();
        match sessions.as_slice() {
            [session] => Ok(session.id),
            [] => Err("no live decrypted connection; enable decrypt mode and join a server".into()),
            _ => Err("several live connections; pass `connection`".into()),
        }
    }

    /// Builds a history query from compact filter keys.
    ///
    /// The compact keys are translated into the UI's filter shape and parsed by
    /// the same code as the history view, so a filter means one thing
    /// everywhere. A `saved` filter is the base and explicit keys override it.
    pub async fn query(
        &self,
        filter: &Map<String, Value>,
        limit: usize,
    ) -> Result<PacketQuery, String> {
        reject_unknown_keys(filter, FILTER_KEYS, "filter key")?;
        let mut shape = match filter.get("saved").and_then(Value::as_str) {
            Some(saved) => self.saved_filter_shape(saved).await?,
            None => Map::new(),
        };
        for (key, value) in self.ui_shape(filter).await? {
            shape.insert(key, value);
        }
        shape.insert("limit".into(), json!(limit.clamp(1, 500)));
        // Paging is by id cursor; a saved filter's UI offset must not skip rows.
        shape.insert("offset".into(), json!(0));
        let input: PacketFilterInput = serde_json::from_value(Value::Object(shape))
            .map_err(|error| format!("filter: {error}"))?;
        input.into_query()
    }

    async fn saved_filter_shape(&self, saved: &str) -> Result<Map<String, Value>, String> {
        let store = self.project()?;
        let filters = blocking(move || {
            store
                .load_saved_filters()
                .map_err(|error| error.to_string())
        })
        .await?;
        let needle = saved.to_ascii_lowercase();
        let found = filters
            .iter()
            .find(|filter| filter.name.to_ascii_lowercase() == needle)
            .or_else(|| {
                filters
                    .iter()
                    .find(|filter| filter.id.simple().to_string().starts_with(&needle))
            })
            .ok_or_else(|| format!("no saved filter `{saved}`; see `filters` action=list"))?;
        match &found.filter {
            Value::Object(map) => Ok(map.clone()),
            _ => Ok(Map::new()),
        }
    }

    /// Translates compact filter keys into the UI's camelCase filter shape.
    pub async fn ui_shape(
        &self,
        filter: &Map<String, Value>,
    ) -> Result<Map<String, Value>, String> {
        let mut shape = Map::new();
        let rename = [
            ("expr", "expression"),
            ("search", "search"),
            ("search_regex", "searchRegex"),
            ("search_case", "searchCaseSensitive"),
            ("search_not", "searchNegate"),
            ("content", "content"),
            ("content_mode", "contentMode"),
            ("content_scope", "contentScope"),
            ("content_case", "contentCaseSensitive"),
            ("content_not", "contentNegate"),
            ("names", "includeNames"),
            ("exclude_names", "excludeNames"),
            ("min_size", "minSize"),
            ("max_size", "maxSize"),
            ("bookmarked", "bookmarked"),
            ("states", "states"),
            ("sources", "sources"),
            ("dispositions", "dispositions"),
        ];
        for (compact, ui) in rename {
            if let Some(value) = filter.get(compact).filter(|value| !value.is_null()) {
                let value = match (compact, value) {
                    (
                        "states" | "sources" | "dispositions" | "names" | "exclude_names",
                        Value::String(one),
                    ) => {
                        json!([one])
                    }
                    _ => value.clone(),
                };
                shape.insert(ui.into(), value);
            }
        }
        if let Some(dir) = filter.get("dir").and_then(Value::as_str) {
            shape.insert(
                "directions".into(),
                serde_json::to_value([parse_direction(dir)?]).unwrap_or_default(),
            );
        }
        if let Some(connection) = filter.get("connection").and_then(Value::as_str) {
            let id = self.resolve_connection(connection).await?;
            shape.insert("connectionId".into(), json!(id));
        }
        Ok(shape)
    }

    /// Loads a stored packet's whole frame.
    pub async fn stored_frame(&self, id: i64) -> Result<Frame, String> {
        let store = self.project()?;
        let window = blocking(move || {
            store
                .packet_window(id, 0, MAX_FRAME)
                .map_err(|error| error.to_string())
        })
        .await?
        .ok_or_else(|| format!("packet #{id} does not exist"))?;
        if window.total_bytes > MAX_FRAME {
            return Err(format!(
                "packet #{id} is {} bytes; frames over {MAX_FRAME} bytes cannot be edited here",
                window.total_bytes
            ));
        }
        Ok(Frame {
            bytes: window.bytes.to_vec(),
            state: window.summary.state,
            direction: window.summary.direction,
            protocol: window.summary.protocol_version,
            connection: Some(window.summary.connection_id),
            name: window.summary.name,
        })
    }

    /// A frame from `hex` or `packet`, with `state`/`dir`/`protocol`
    /// overriding what the stored packet says.
    pub async fn frame_from(&self, args: &Args) -> Result<Frame, String> {
        let mut frame = if let Some(id) = args.i64("packet") {
            self.stored_frame(id).await?
        } else if let Some(text) = args.str("hex") {
            Frame {
                bytes: parse_hex(text)?,
                state: ProtocolState::Play,
                direction: Direction::ClientToServer,
                protocol: None,
                connection: None,
                name: None,
            }
        } else {
            return Err("give `hex` (logical frame) or `packet` (history id)".into());
        };
        if let Some(state) = args.state("state")? {
            frame.state = state;
        }
        if let Some(direction) = args.direction("dir")? {
            frame.direction = direction;
        }
        if let Some(protocol) = args.protocol("protocol")? {
            frame.protocol = Some(protocol);
        }
        if frame.protocol.is_none()
            && let Some(connection) = frame.connection
        {
            frame.protocol = self
                .connections()
                .await?
                .into_iter()
                .find(|(row, _)| row.id == connection)
                .and_then(|(row, _)| row.protocol_version);
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_names_parse_leniently() {
        assert_eq!(
            parse_hex("0x01 02:ff,\\x10").unwrap(),
            vec![1, 2, 0xff, 0x10]
        );
        assert!(parse_hex("zz").is_err());
        assert_eq!(parse_direction("S>C").unwrap(), Direction::ServerToClient);
        assert_eq!(parse_state("PLAY").unwrap(), ProtocolState::Play);
        assert_eq!(resolve_protocol("767"), Some(767));
        assert_eq!(resolve_protocol("1.21.1"), Some(767));
    }

    #[test]
    fn unknown_filter_keys_are_rejected() {
        let mut filter = Map::new();
        filter.insert("channel".into(), json!("mineburp:batch"));
        let error = reject_unknown_keys(&filter, FILTER_KEYS, "filter key").unwrap_err();
        assert!(error.contains("unknown filter key `channel`"), "{error}");

        let mut arguments = Map::new();
        arguments.insert("expr".into(), json!("name == chat"));
        arguments.insert("limit".into(), json!(10));
        arguments.insert("wait_ms".into(), json!(5));
        check_packet_arguments(&arguments).unwrap();
        assert_eq!(
            filter_map(&arguments),
            Map::from_iter([("expr".into(), json!("name == chat"))])
        );

        arguments.insert("names_".into(), json!(["chat"]));
        assert!(check_packet_arguments(&arguments).is_err());
    }

    #[test]
    fn every_tool_has_a_handler() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let host = crate::OfflineHost::default();
        for tool in catalog() {
            let result = runtime.block_on(dispatch(&host, tool.name, json!({})));
            if let Err(error) = result {
                assert!(!error.starts_with("unknown tool"), "{}", tool.name);
            }
        }
    }
}
