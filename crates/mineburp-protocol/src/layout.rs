//! Byte-accurate field layouts.
//!
//! [`crate::inspect`] answers *what a packet says*; this module answers *where
//! each value lives*. Every field carries the byte range it occupies, so the
//! Repeater can re-encode one value and splice it back into the frame instead of
//! making the operator count nibbles in a hex editor.
//!
//! Identification is not repeated here: the layout walker is chosen by the name
//! the inspector already settled on, so a packet can never be laid out as
//! something it was not identified as.

use mineburp_core::{Direction, ProtocolState};
use serde_json::Value;

use crate::{
    inspect::{inspect_logical, resolve_name},
    protodef,
    reader::Reader,
    varint::{encode_var_i32, encode_var_i64},
};

/// How a field's bytes are written back.
///
/// The set is deliberately small: these are the primitives the protocol builds
/// everything else out of, and each one has a single unambiguous encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    VarInt,
    VarLong,
    /// A `VarInt` length prefix followed by UTF-8 bytes.
    String,
    Bool,
    U8,
    I8,
    /// The low seven bits of a byte whose top bit says another array element
    /// follows (`topBitSetTerminatedArray`, e.g. an equipment slot). Editing
    /// sets the seven bits and keeps the flag the byte had.
    FlaggedU7,
    I16,
    U16,
    I32,
    I64,
    F32,
    F64,
    /// Bytes shown as hex, edited as hex.
    Bytes,
    /// Hex bytes written back with a `VarInt` length prefix, so editing one
    /// rewrites its own prefix rather than leaving a lie in front of it.
    PrefixedBytes,
    /// Network NBT (no root name), shown and edited as JSON text. Empty text
    /// is an absent optional value (`TAG_End`).
    Nbt,
    /// Pre-1.20.2 NBT with a named root, edited as JSON; a non-empty root
    /// name is shown as a `"name": value` prefix.
    NamedNbt,
    /// Network NBT behind a `VarInt` byte length, edited as JSON. The span
    /// covers the length too, so an edit that resizes the NBT rewrites it.
    PrefixedNbt,
}

/// One value inside a frame, with the bytes it occupies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FieldSpan {
    pub name: String,
    pub kind: FieldKind,
    /// Byte offset from the start of the logical frame.
    pub offset: usize,
    /// Bytes the field currently occupies. Re-encoding may change this.
    pub length: usize,
    /// The decoded value: a number, string, or boolean.
    pub value: Value,
}

/// The editable view of a frame.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PacketLayout {
    /// The packet the inspector identified, when it identified one.
    pub name: Option<String>,
    pub fields: Vec<FieldSpan>,
    /// True when the fields cover the whole frame. A partial layout means the
    /// tail is shown as raw bytes and editing earlier fields is still exact.
    pub complete: bool,
}

/// Walks a logical frame into editable spans.
///
/// Two walkers can answer. The hand-written one below knows a few dozen
/// packets and names their fields the way replacement rules have always
/// referred to them, so it is used whenever it accounts for the whole frame.
/// Otherwise the bundled `minecraft-data` description for the protocol walks
/// it — every packet of every described release — and its spans are used if
/// they account for every byte. Only when neither does is the tail left as raw
/// bytes after whatever the hand walker managed.
#[must_use]
pub fn layout_logical(
    state: ProtocolState,
    direction: Direction,
    logical: &[u8],
    protocol_version: Option<i32>,
) -> PacketLayout {
    let mut layout = walk_logical(state, direction, logical, protocol_version);
    for field in &mut layout.fields {
        exact_in_javascript(field);
    }
    layout
}

/// Looks up a rule field without running the complete display layout.
pub(crate) fn lookup_field(
    state: ProtocolState,
    direction: Direction,
    logical: &[u8],
    protocol: Option<i32>,
    target: &str,
) -> PacketLayout {
    let mut builder = Builder::new(logical);
    builder.target = Some(target.to_owned());
    let Some(id) = builder.var_int("packet id") else {
        return builder.finish(None);
    };
    let prefix = builder.reader.position();
    let body = &logical[prefix..];
    let name = resolve_name(state, direction, id, body, protocol);
    if let Some(name) = &name {
        walk(&mut builder, name, state, direction, protocol);
    }
    builder
        .fields
        .retain(|field| crate::rewrite::normalise(&field.name) == target);
    if builder.fields.is_empty()
        && let Some(decoded) =
            protodef::decode_packet_until(state, direction, id, body, protocol, Some(target))
    {
        builder.fields = decoded
            .spans
            .into_iter()
            .map(|mut span| {
                span.offset += prefix;
                span
            })
            .collect();
    }
    for field in &mut builder.fields {
        let bytes = &logical[field.offset..field.offset + field.length];
        field.value = match field.kind {
            FieldKind::Bytes => Value::String(to_hex(bytes)),
            FieldKind::PrefixedNbt => {
                let mut reader = Reader::new(bytes);
                Value::String(
                    reader
                        .byte_array()
                        .and_then(|nbt| crate::nbt_text::to_text(nbt, false))
                        .unwrap_or_default(),
                )
            }
            FieldKind::Nbt | FieldKind::NamedNbt => {
                if let Some(text) =
                    crate::nbt_text::to_text(bytes, field.kind == FieldKind::NamedNbt)
                {
                    Value::String(text)
                } else {
                    field.kind = FieldKind::Bytes;
                    Value::String(to_hex(bytes))
                }
            }
            _ => field.value.clone(),
        };
        exact_in_javascript(field);
    }
    builder.finish(name)
}

/// The largest integer a JavaScript number holds exactly (2^53 - 1).
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Sends a 64-bit value JavaScript would round (a timestamp, a salt, a seed)
/// as its decimal text instead, so the Repeater shows and keeps the real
/// value. [`encode_field_over`] reads either form.
fn exact_in_javascript(field: &mut FieldSpan) {
    if !matches!(field.kind, FieldKind::I64 | FieldKind::VarLong) {
        return;
    }
    if let Value::Number(number) = &field.value
        && let Some(value) = number.as_i64()
        && value.unsigned_abs() > MAX_SAFE_INTEGER.unsigned_abs()
    {
        field.value = Value::String(value.to_string());
    }
}

fn walk_logical(
    state: ProtocolState,
    direction: Direction,
    logical: &[u8],
    protocol_version: Option<i32>,
) -> PacketLayout {
    let mut builder = Builder::new(logical);

    if matches!(state, ProtocolState::Opaque | ProtocolState::Closed) {
        let name = inspect_logical(state, direction, logical, protocol_version).name;
        builder.bytes("payload");
        return builder.finish(name);
    }

    let Some(packet_id) = builder.var_int("packet id") else {
        builder.bytes("frame");
        return builder.finish(None);
    };
    let prefix = builder.reader.position();
    let body = logical.get(prefix..).unwrap_or_default();
    let name = resolve_name(state, direction, packet_id, body, protocol_version);

    if let Some(name) = name.as_deref() {
        walk(&mut builder, name, state, direction, protocol_version);
    }
    let hand_complete = !builder.stopped
        && builder.remaining() == 0
        && (builder.fields.len() > 1 || body.is_empty());
    if hand_complete {
        return builder.finish(name);
    }
    let definition = protodef::decode_packet(state, direction, packet_id, body, protocol_version);
    if let Some(definition) = &definition
        && definition.is_complete()
    {
        return definition_layout(
            name,
            builder.fields.swap_remove(0),
            &definition.spans,
            prefix,
            true,
        );
    }
    // Neither walker reached the end. Keep whichever accounted for more of
    // the frame and show only the rest as hex, so an edit that breaks the
    // tail (a count, a type tag) does not turn every field into one blob.
    let hand_end = builder.reader.position();
    if let Some(definition) = definition {
        let spans = contiguous(&definition.spans);
        let end = spans.last().map_or(0, |span| span.offset + span.length) + prefix;
        if end > hand_end {
            let mut layout =
                definition_layout(name, builder.fields.swap_remove(0), spans, prefix, false);
            if end < logical.len() {
                layout.fields.push(FieldSpan {
                    name: "rest".into(),
                    kind: FieldKind::Bytes,
                    offset: end,
                    length: logical.len() - end,
                    value: Value::String(to_hex(&logical[end..])),
                });
            }
            return layout;
        }
    }
    let rest_name = if builder.fields.len() > 1 {
        "rest"
    } else {
        "body"
    };
    builder.bytes(rest_name);
    builder.finish(name)
}

/// The leading run of spans that tile the body without gaps or overlaps.
fn contiguous(spans: &[FieldSpan]) -> &[FieldSpan] {
    let mut cursor = 0;
    let count = spans
        .iter()
        .take_while(|span| {
            let next = span.offset == cursor;
            cursor = span.offset + span.length;
            next
        })
        .count();
    &spans[..count]
}

fn definition_layout(
    name: Option<String>,
    packet_id: FieldSpan,
    spans: &[FieldSpan],
    prefix: usize,
    complete: bool,
) -> PacketLayout {
    let mut fields = Vec::with_capacity(spans.len() + 2);
    fields.push(packet_id);
    fields.extend(spans.iter().map(|span| FieldSpan {
        offset: span.offset + prefix,
        ..span.clone()
    }));
    PacketLayout {
        name,
        fields,
        complete,
    }
}

/// Encodes one field value back into bytes.
///
/// The Repeater sends the edited value here rather than encoding it itself, so
/// the wire format lives in exactly one place. Without the bytes being
/// replaced, NBT types are inferred; see [`encode_field_over`].
pub fn encode_field(kind: FieldKind, value: &Value) -> Result<Vec<u8>, String> {
    encode_field_over(kind, value, None)
}

/// Encodes a field value that replaces `original`, the bytes the field
/// occupies now. NBT edited as JSON keeps the tag types those bytes had, so
/// `1` under a byte stays a byte.
pub fn encode_field_over(
    kind: FieldKind,
    value: &Value,
    original: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Preserve noncanonical VarInt prefixes and NBT list element tags when
    // an operator re-encodes the value without changing it.
    if let Some(bytes) = original {
        let unchanged = unchanged_field(kind, value, bytes);
        if unchanged {
            return Ok(bytes.to_vec());
        }
    }
    let integer = |bits: u32, signed: bool| -> Result<i64, String> {
        let number = match value {
            Value::Number(number) => number.as_i64().ok_or("value is not a whole number")?,
            Value::String(text) => parse_integer(text)?,
            Value::Bool(flag) => i64::from(*flag),
            _ => return Err("value is not a number".into()),
        };
        let (low, high) = if signed {
            (-(1_i64 << (bits - 1)), (1_i64 << (bits - 1)) - 1)
        } else {
            (0, (1_i64 << bits) - 1)
        };
        if !(low..=high).contains(&number) {
            return Err(format!("value must be between {low} and {high}"));
        }
        Ok(number)
    };

    Ok(match kind {
        FieldKind::VarInt => {
            encode_var_i32(i32::try_from(integer(32, true)?).map_err(|_| "value is out of range")?)
                .to_vec()
        }
        FieldKind::VarLong => encode_var_i64(parse_i64(value)?).to_vec(),
        FieldKind::String => {
            let text = match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            let mut bytes =
                encode_var_i32(i32::try_from(text.len()).map_err(|_| "string is too long")?)
                    .to_vec();
            bytes.extend_from_slice(text.as_bytes());
            bytes
        }
        FieldKind::Bool => vec![u8::from(match value {
            Value::Bool(flag) => *flag,
            Value::String(text) => matches!(text.trim(), "true" | "1"),
            Value::Number(number) => number.as_i64().is_some_and(|value| value != 0),
            _ => return Err("value is not a boolean".into()),
        })],
        FieldKind::U8 => vec![u8::try_from(integer(8, false)?).map_err(|_| "out of range")?],
        FieldKind::FlaggedU7 => {
            let low = u8::try_from(integer(7, false)?).map_err(|_| "out of range")?;
            vec![
                low | original
                    .and_then(|bytes| bytes.first())
                    .map_or(0, |byte| byte & 0x80),
            ]
        }
        FieldKind::I8 => vec![
            i8::try_from(integer(8, true)?)
                .map_err(|_| "out of range")?
                .cast_unsigned(),
        ],
        FieldKind::I16 => i16::try_from(integer(16, true)?)
            .map_err(|_| "out of range")?
            .to_be_bytes()
            .to_vec(),
        FieldKind::U16 => u16::try_from(integer(16, false)?)
            .map_err(|_| "out of range")?
            .to_be_bytes()
            .to_vec(),
        FieldKind::I32 => i32::try_from(integer(32, true)?)
            .map_err(|_| "out of range")?
            .to_be_bytes()
            .to_vec(),
        FieldKind::I64 => parse_i64(value)?.to_be_bytes().to_vec(),
        FieldKind::F32 => {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a 32-bit field is being written; narrowing is the point"
            )]
            let narrowed = parse_f64(value)? as f32;
            narrowed.to_be_bytes().to_vec()
        }
        FieldKind::F64 => parse_f64(value)?.to_be_bytes().to_vec(),
        FieldKind::Bytes => parse_hex(value)?,
        FieldKind::PrefixedBytes => {
            let payload = parse_hex(value)?;
            let mut bytes =
                encode_var_i32(i32::try_from(payload.len()).map_err(|_| "byte array is too long")?)
                    .to_vec();
            bytes.extend_from_slice(&payload);
            bytes
        }
        FieldKind::Nbt | FieldKind::NamedNbt | FieldKind::PrefixedNbt => {
            encode_nbt(kind, value, original)?
        }
    })
}

fn unchanged_field(kind: FieldKind, value: &Value, bytes: &[u8]) -> bool {
    let mut reader = Reader::new(bytes);
    match kind {
        FieldKind::VarInt => {
            reader
                .var_i32()
                .is_some_and(|old| parse_i64(value).ok() == Some(i64::from(old)))
                && reader.remaining() == 0
        }
        FieldKind::VarLong => {
            reader
                .var_i64()
                .is_some_and(|old| parse_i64(value).ok() == Some(old))
                && reader.remaining() == 0
        }
        FieldKind::String => {
            if reader
                .string(262_144)
                .is_some_and(|old| value.as_str() == Some(old.as_str()))
                && reader.remaining() == 0
            {
                return true;
            }
            // The declarative walker displays malformed UTF-8 with replacement
            // characters instead of refusing it. An unchanged field must keep
            // the bytes it had, or re-saving a packet would silently rewrite a
            // hostile string.
            let mut reader = Reader::new(bytes);
            let Some(length) = reader
                .var_i32()
                .and_then(|length| usize::try_from(length).ok())
            else {
                return false;
            };
            reader.take(length).is_some_and(|payload| {
                value.as_str() == Some(String::from_utf8_lossy(payload).as_ref())
            }) && reader.remaining() == 0
        }
        FieldKind::PrefixedBytes => {
            reader
                .byte_array()
                .is_some_and(|old| parse_hex(value).is_ok_and(|new| new == old))
                && reader.remaining() == 0
        }
        FieldKind::Nbt | FieldKind::NamedNbt => {
            crate::nbt_text::to_text(bytes, kind == FieldKind::NamedNbt)
                .is_some_and(|old| value.as_str() == Some(old.as_str()))
        }
        FieldKind::PrefixedNbt => {
            reader
                .byte_array()
                .and_then(|nbt| crate::nbt_text::to_text(nbt, false))
                .is_some_and(|old| value.as_str() == Some(old.as_str()))
                && reader.remaining() == 0
        }
        _ => false,
    }
}

/// The three NBT kinds: JSON text written back with the replaced bytes as
/// the type template, behind a fresh length prefix for `PrefixedNbt`.
fn encode_nbt(kind: FieldKind, value: &Value, original: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if kind != FieldKind::PrefixedNbt {
        return crate::nbt_text::from_text(nbt_text(value)?, kind == FieldKind::NamedNbt, original);
    }
    // The template is the NBT after the old length prefix.
    let template = original.and_then(|bytes| {
        let mut reader = Reader::new(bytes);
        reader.var_i32()?;
        Some(&bytes[reader.position()..])
    });
    let nbt = crate::nbt_text::from_text(nbt_text(value)?, false, template)?;
    if nbt.len() > MAX_PREFIXED_NBT {
        return Err(format!(
            "NBT is {} bytes; the game reads at most {MAX_PREFIXED_NBT}",
            nbt.len()
        ));
    }
    let mut bytes =
        encode_var_i32(i32::try_from(nbt.len()).map_err(|_| "NBT is too long")?).to_vec();
    bytes.extend_from_slice(&nbt);
    Ok(bytes)
}

/// Vanilla's limit for length-prefixed NBT (`ByteBufCodecs.lengthPrefixed`).
const MAX_PREFIXED_NBT: usize = 65_536;
/// NBT larger than this is laid out as hex rather than text.
pub(crate) const MAX_NBT_TEXT_BYTES: usize = 256 * 1024;

fn nbt_text(value: &Value) -> Result<&str, String> {
    match value {
        Value::String(text) => Ok(text),
        _ => Err("NBT is edited as JSON text".into()),
    }
}

fn parse_integer(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        i64::from_str_radix(hex, 16)
    } else {
        text.parse::<i64>()
    };
    parsed.map_err(|_| format!("`{text}` is not a whole number"))
}

fn parse_i64(value: &Value) -> Result<i64, String> {
    match value {
        Value::Number(number) => number.as_i64().ok_or_else(|| "value is too large".into()),
        Value::String(text) => parse_integer(text),
        _ => Err("value is not a number".into()),
    }
}

fn parse_f64(value: &Value) -> Result<f64, String> {
    match value {
        Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| "value is not a number".into()),
        Value::String(text) => text
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("`{text}` is not a number")),
        _ => Err("value is not a number".into()),
    }
}

fn parse_hex(value: &Value) -> Result<Vec<u8>, String> {
    let Value::String(text) = value else {
        return Err("value is not hex".into());
    };
    crate::rewrite::parse_hex(text).map_err(|error| error.to_string())
}

// --- walkers ---

/// Reads the fields of a packet the inspector has already named.
///
/// Each walker stops at the first field that does not parse; whatever is left is
/// reported as raw bytes, so a version that added a trailing field still gives
/// the operator exact control over everything before it.
#[allow(clippy::too_many_lines, reason = "a flat table of packet shapes")]
fn walk(
    builder: &mut Builder<'_>,
    name: &str,
    state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
) {
    let serverbound = direction == Direction::ClientToServer;
    match name {
        "handshake" => {
            builder.var_int("protocol version");
            builder.string("server address");
            builder.u16("server port");
            builder.var_int("next state");
        }
        "status_response" => {
            builder.string("response");
        }
        "ping_request" | "pong_response" => {
            builder.i64("payload");
        }
        "login_start" => {
            builder.string("username");
            builder.bytes_named("uuid", 16);
        }
        "login_success" => {
            builder.bytes_named("uuid", 16);
            builder.string("username");
        }
        "login_disconnect" | "text_component" | "system_chat" => {
            // Components are NBT or JSON; the JSON form is a plain string and
            // the NBT form is left as bytes.
            if protocol_version.is_some_and(|version| version >= 765) {
                builder.component_nbt("component");
            } else if builder
                .peek_string()
                .is_some_and(|text| serde_json::from_str::<Value>(&text).is_ok())
            {
                builder.string("component");
            }
        }
        "set_compression" => {
            builder.var_int("threshold");
        }
        "encryption_request" => {
            builder.string("server id");
            builder.length_prefixed("public key");
            builder.length_prefixed("verify token");
        }
        "encryption_response" => {
            builder.length_prefixed("shared secret");
            builder.length_prefixed("verify token");
        }
        "login_plugin_request" => {
            builder.var_int("message id");
            builder.string("channel");
        }
        "login_plugin_response" => {
            builder.var_int("message id");
            builder.bool("successful");
        }
        "keep_alive" => {
            if state == ProtocolState::Configuration && builder.remaining() == 4 {
                builder.i32("id");
            } else {
                builder.i64("id");
            }
        }
        "ping" | "pong" => {
            builder.i32("id");
        }
        "custom_payload" | "plugin_message" => {
            builder.string("channel");
        }
        "chat_message" => {
            builder.string("message");
            builder.i64("timestamp");
            builder.i64("salt");
            builder.bool("signed");
        }
        "chat_command" => {
            builder.string("command");
        }
        "string_payload" => {
            builder.string("value");
        }
        "custom_click_action" => {
            // The payload is length-prefixed NBT; the bundled description
            // calls the length an option flag, so an edit that resized the
            // NBT would leave the old length in front of it.
            builder.string("id");
            builder.prefixed_nbt("payload");
        }
        "client_information" => {
            builder.string("locale");
            builder.i8("view distance");
            builder.var_int("chat mode");
            builder.bool("chat colours");
            builder.u8("skin parts");
            builder.var_int("main hand");
            builder.bool("text filtering");
            builder.bool("server listing");
        }
        "set_player_position" => {
            builder.f64("x");
            builder.f64("y");
            builder.f64("z");
            builder.u8("flags");
        }
        "set_player_position_and_rotation" => {
            builder.f64("x");
            builder.f64("y");
            builder.f64("z");
            builder.f32("yaw");
            builder.f32("pitch");
            builder.u8("flags");
        }
        "set_player_rotation" => {
            builder.f32("yaw");
            builder.f32("pitch");
            builder.u8("flags");
        }
        "set_held_item" if serverbound => {
            builder.i16("slot");
        }
        "player_action" => {
            builder.var_int("status");
            builder.i64("position");
            builder.u8("face");
            builder.var_int("sequence");
        }
        "use_item_on" => {
            builder.var_int("hand");
            builder.i64("position");
            builder.var_int("face");
            builder.f32("cursor x");
            builder.f32("cursor y");
            builder.f32("cursor z");
            builder.bool("inside block");
            // 1.21.2 put a world-border flag in front of the sequence number.
            if protocol_version.is_some_and(|version| version >= 768) {
                builder.bool("hit world border");
            }
            builder.var_int("sequence");
        }
        "use_item" => {
            builder.var_int("hand");
            builder.var_int("sequence");
            // 1.21.3 appended the facing the click was made with.
            if builder.remaining() >= 8 {
                builder.f32("yaw");
                builder.f32("pitch");
            }
        }
        "interact" => {
            builder.var_int("entity id");
            let kind = builder.var_int("type");
            if kind == Some(2) {
                builder.f32("target x");
                builder.f32("target y");
                builder.f32("target z");
            }
            if kind != Some(1) {
                builder.var_int("hand");
            }
            builder.bool("sneaking");
        }
        "player_command" => {
            builder.var_int("entity id");
            builder.var_int("action");
            builder.var_int("jump boost");
        }
        "move_vehicle" => {
            builder.f64("x");
            builder.f64("y");
            builder.f64("z");
            builder.f32("yaw");
            builder.f32("pitch");
        }
        "command_suggestion" => {
            builder.var_int("transaction");
            builder.string("text");
        }
        "sign_update" => {
            builder.i64("position");
            // 1.20.5 added the front/back flag; a bool is indistinguishable from
            // a short line's length prefix, so only a known version claims one.
            if protocol_version.is_some_and(|version| version >= 766) {
                builder.bool("front");
            }
            for line in 1..=4 {
                builder.string(&format!("line {line}"));
            }
        }
        "block_destruction" => {
            builder.var_int("entity id");
            builder.i64("position");
            builder.u8("stage");
        }
        "block_event" => {
            builder.i64("position");
            builder.u8("action");
            builder.u8("parameter");
            builder.var_int("block type");
        }
        "level_event" => {
            builder.i32("event");
            builder.i64("position");
            builder.i32("data");
            builder.bool("global");
        }
        "open_screen" => {
            builder.var_int("window id");
            builder.var_int("type");
        }
        "set_entity_motion" => {
            builder.var_int("entity id");
            builder.i16("velocity x");
            builder.i16("velocity y");
            builder.i16("velocity z");
        }
        "move_entity_pos" | "move_entity_pos_rot" | "move_entity_rot" => {
            builder.var_int("entity id");
            if name != "move_entity_rot" {
                builder.i16("delta x");
                builder.i16("delta y");
                builder.i16("delta z");
            }
            if name != "move_entity_pos" {
                builder.u8("yaw");
                builder.u8("pitch");
            }
            builder.bool("on ground");
        }
        "teleport_entity" => {
            builder.var_int("entity id");
            builder.f64("x");
            builder.f64("y");
            builder.f64("z");
            // 1.21.2 grew the packet with velocity and float angles.
            if builder.remaining() > 3 {
                builder.f64("velocity x");
                builder.f64("velocity y");
                builder.f64("velocity z");
                builder.f32("yaw");
                builder.f32("pitch");
                builder.i32("relative flags");
            } else {
                builder.u8("yaw");
                builder.u8("pitch");
            }
            builder.bool("on ground");
        }
        "remove_entities" => {
            let Some(count) = builder.var_int("entity count") else {
                return;
            };
            for index in 0..count.clamp(0, 256) {
                builder.var_int(&format!("entity {index}"));
            }
        }
        "player_info_remove" => {
            let Some(count) = builder.var_int("player count") else {
                return;
            };
            for index in 0..count.clamp(0, 128) {
                builder.bytes_named(&format!("player {index}"), 16);
            }
        }
        "block_update" => {
            builder.i64("position");
            builder.var_int("block state");
        }
        "set_default_spawn_position" => {
            builder.i64("position");
            builder.f32("angle");
        }
        "set_health" => {
            builder.f32("health");
            builder.var_int("food");
            builder.f32("saturation");
        }
        "set_experience" => {
            builder.f32("progress");
            builder.var_int("level");
            builder.var_int("total");
        }
        "player_abilities" if !serverbound => {
            builder.u8("flags");
            builder.f32("flying speed");
            builder.f32("field of view");
        }
        "game_event" => {
            builder.u8("event");
            builder.f32("value");
        }
        "update_time" => {
            builder.i64("world age");
            builder.i64("time of day");
        }
        "synchronize_player_position" => {
            builder.f64("x");
            builder.f64("y");
            builder.f64("z");
            builder.f32("yaw");
            builder.f32("pitch");
            builder.u8("relative flags");
            builder.var_int("teleport id");
        }
        "add_resource_pack" => {
            if protocol_version.is_some_and(|version| version >= 765) {
                builder.bytes_named("uuid", 16);
            }
            builder.string("url");
            builder.string("hash");
            builder.bool("forced");
        }
        "transfer" => {
            builder.string("host");
            builder.var_int("port");
        }
        "cookie_request" | "store_cookie" | "cookie_response" | "remove_resource_pack" => {
            builder.string("key");
        }
        "resource_pack_response" => {
            if builder.remaining() == 17 {
                builder.bytes_named("uuid", 16);
            }
            builder.var_int("result");
        }
        "known_packs" | "select_known_packs" => {
            let Some(count) = builder.var_int("pack count") else {
                return;
            };
            for index in 0..count.clamp(0, 256) {
                builder.string(&format!("pack {index} namespace"));
                builder.string(&format!("pack {index} id"));
                builder.string(&format!("pack {index} version"));
            }
        }
        _ => {}
    }
}

// --- span construction ---

struct Builder<'a> {
    reader: Reader<'a>,
    target: Option<String>,
    fields: Vec<FieldSpan>,
    /// Set once a read fails: everything after it is raw bytes.
    stopped: bool,
}

impl<'a> Builder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(input),
            target: None,
            fields: Vec::new(),
            stopped: false,
        }
    }

    fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    fn peek_string(&self) -> Option<String> {
        self.reader.clone().string(262_144)
    }

    /// Records one field from a read that may fail.
    fn push<T>(
        &mut self,
        name: &str,
        kind: FieldKind,
        read: impl FnOnce(&mut Reader<'a>) -> Option<T>,
        to_value: impl FnOnce(T) -> Value,
    ) -> Option<T>
    where
        T: Clone,
    {
        if self.stopped {
            return None;
        }
        let offset = self.reader.position();
        // A failed read must not move the cursor: a rejected byte (a bool that
        // is neither 0 nor 1) belongs to the raw tail, or the tail would start
        // past it and the frame rebuilt from the spans would lose it.
        let mut probe = self.reader.clone();
        let Some(value) = read(&mut probe) else {
            self.stopped = true;
            return None;
        };
        self.reader = probe;
        let wanted = self
            .target
            .as_ref()
            .is_none_or(|target| crate::rewrite::normalise(name) == *target);
        if !wanted {
            return Some(value);
        }
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind,
            offset,
            length: self.reader.position() - offset,
            value: to_value(value.clone()),
        });
        if self.target.is_some() {
            self.stopped = true;
        }
        Some(value)
    }

    fn var_int(&mut self, name: &str) -> Option<i32> {
        self.push(name, FieldKind::VarInt, Reader::var_i32, Value::from)
    }

    fn u8(&mut self, name: &str) -> Option<u8> {
        self.push(name, FieldKind::U8, Reader::u8, Value::from)
    }

    fn i8(&mut self, name: &str) -> Option<i8> {
        self.push(name, FieldKind::I8, Reader::i8, Value::from)
    }

    fn i16(&mut self, name: &str) -> Option<i16> {
        self.push(name, FieldKind::I16, Reader::i16, Value::from)
    }

    fn u16(&mut self, name: &str) -> Option<u16> {
        self.push(name, FieldKind::U16, Reader::u16, Value::from)
    }

    fn i32(&mut self, name: &str) -> Option<i32> {
        self.push(name, FieldKind::I32, Reader::i32, Value::from)
    }

    fn i64(&mut self, name: &str) -> Option<i64> {
        self.push(name, FieldKind::I64, Reader::i64, Value::from)
    }

    fn f32(&mut self, name: &str) -> Option<f32> {
        self.push(name, FieldKind::F32, Reader::f32, Value::from)
    }

    fn f64(&mut self, name: &str) -> Option<f64> {
        self.push(name, FieldKind::F64, Reader::f64, Value::from)
    }

    fn bool(&mut self, name: &str) -> Option<bool> {
        self.push(name, FieldKind::Bool, Reader::bool, Value::from)
    }

    fn string(&mut self, name: &str) -> Option<String> {
        self.push(
            name,
            FieldKind::String,
            |reader| reader.string(262_144),
            Value::from,
        )
    }

    /// A fixed run of bytes, such as a UUID.
    fn bytes_named(&mut self, name: &str, count: usize) {
        self.push(
            name,
            FieldKind::Bytes,
            |reader| reader.take(count).map(<[u8]>::to_vec),
            |bytes| Value::String(to_hex(&bytes)),
        );
    }

    fn component_nbt(&mut self, name: &str) {
        if self.stopped {
            return;
        }
        let offset = self.reader.position();
        let Some(length) = crate::nbt::skip_nbt(self.reader.rest(), false) else {
            self.stopped = true;
            return;
        };
        let Some(bytes) = self.reader.take(length) else {
            return;
        };
        if self
            .target
            .as_ref()
            .is_some_and(|target| crate::rewrite::normalise(name) != *target)
        {
            return;
        }
        let text = crate::nbt_text::to_text(bytes, false);
        self.fields.push(FieldSpan {
            name: name.into(),
            offset,
            length,
            kind: if text.is_some() {
                FieldKind::Nbt
            } else {
                FieldKind::Bytes
            },
            value: Value::String(text.unwrap_or_else(|| to_hex(bytes))),
        });
        if self.target.is_some() {
            self.stopped = true;
        }
    }

    /// A `VarInt`-prefixed byte array. The span covers the prefix as well as the
    /// payload, so an edit that changes the length rewrites both.
    fn length_prefixed(&mut self, name: &str) {
        if self.stopped {
            return;
        }
        let offset = self.reader.position();
        let mut probe = self.reader.clone();
        let Some(bytes) = probe.byte_array().map(<[u8]>::to_vec) else {
            self.stopped = true;
            return;
        };
        self.reader = probe;
        if self
            .target
            .as_ref()
            .is_some_and(|target| crate::rewrite::normalise(name) != *target)
        {
            return;
        }
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind: FieldKind::PrefixedBytes,
            offset,
            length: self.reader.position() - offset,
            value: Value::String(to_hex(&bytes)),
        });
    }

    /// A `VarInt` byte length followed by exactly that much NBT. Anything
    /// else stops the walk, so the definition gets a chance instead.
    fn prefixed_nbt(&mut self, name: &str) {
        if self.stopped {
            return;
        }
        let offset = self.reader.position();
        let mut probe = self.reader.clone();
        if self.target.is_some() {
            let Some(bytes) = probe.byte_array() else {
                self.stopped = true;
                return;
            };
            let _ = bytes;
            self.reader = probe;
            if self
                .target
                .as_ref()
                .is_some_and(|target| crate::rewrite::normalise(name) == *target)
            {
                self.fields.push(FieldSpan {
                    name: name.into(),
                    kind: FieldKind::PrefixedNbt,
                    offset,
                    length: self.reader.position() - offset,
                    value: Value::Null,
                });
                self.stopped = true;
            }
            return;
        }
        let text = probe
            .byte_array()
            .filter(|nbt| nbt.len() <= MAX_NBT_TEXT_BYTES)
            .and_then(|nbt| crate::nbt_text::to_text(nbt, false));
        let Some(text) = text else {
            self.stopped = true;
            return;
        };
        let length = probe.position() - offset;
        let _ = self.reader.take(length);
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind: FieldKind::PrefixedNbt,
            offset,
            length,
            value: Value::String(text),
        });
    }

    /// Whatever is left, as one hex field.
    fn bytes(&mut self, name: &str) {
        if self.stopped {
            return;
        }
        let rest = self.reader.rest();
        if self
            .target
            .as_ref()
            .is_some_and(|target| crate::rewrite::normalise(name) != *target)
        {
            let _ = self.reader.take(rest.len());
            return;
        }
        if rest.is_empty() {
            return;
        }
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind: FieldKind::Bytes,
            offset: self.reader.position(),
            length: rest.len(),
            value: Value::String(to_hex(rest)),
        });
        let _ = self.reader.take(rest.len());
    }

    fn finish(self, name: Option<String>) -> PacketLayout {
        PacketLayout {
            name,
            complete: !self.stopped,
            fields: self.fields,
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::varint::encode_var_i32;

    fn push_string(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&encode_var_i32(i32::try_from(value.len()).unwrap()));
        output.extend_from_slice(value.as_bytes());
    }

    fn tiles(layout: &PacketLayout, logical: &[u8]) {
        let mut cursor = 0;
        for field in &layout.fields {
            assert_eq!(field.offset, cursor, "gap before `{}`", field.name);
            let original = &logical[field.offset..field.offset + field.length];
            let encoded = encode_field_over(field.kind, &field.value, Some(original)).unwrap();
            assert_eq!(
                encoded, original,
                "`{}` does not re-encode to its bytes",
                field.name
            );
            cursor += field.length;
        }
        assert_eq!(cursor, logical.len(), "spans stop short of the frame's end");
    }

    #[test]
    fn entity_metadata_keeps_its_terminator() {
        // set_entity_data from a 1.21.10 capture: entity, one VarInt entry, 0xff.
        let logical = [0x61, 0xc8, 0x9a, 0xac, 0x01, 0x1b, 0x00, 0x06, 0xff];
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &logical,
            Some(774),
        );
        assert!(layout.complete);
        tiles(&layout, &logical);
        assert_eq!(layout.fields.last().unwrap().name, "metadata.end");
    }

    #[test]
    fn equipment_slots_keep_their_continuation_flag() {
        // Two entries: slot 0 with the "more follow" bit, then slot 5; both empty.
        let logical = [0x64, 0x01, 0x80, 0x00, 0x05, 0x00];
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &logical,
            Some(774),
        );
        assert!(layout.complete);
        tiles(&layout, &logical);
        let slot = layout
            .fields
            .iter()
            .find(|field| field.offset == 2)
            .unwrap();
        assert_eq!(slot.kind, FieldKind::FlaggedU7);
        assert_eq!(slot.value, json!(0));
        // Editing the slot keeps the flag, so the array still has two entries.
        let edited = encode_field_over(slot.kind, &json!("2"), Some(&logical[2..3])).unwrap();
        assert_eq!(edited, vec![0x82]);
        assert!(encode_field_over(slot.kind, &json!(128), Some(&[0x80])).is_err());
    }

    #[test]
    fn a_rejected_byte_starts_the_raw_tail() {
        // chat_message whose "signed" byte is neither 0 nor 1: the walk stops
        // there, and that byte must be the first of the tail, not skipped.
        let mut logical = encode_var_i32(0x08).to_vec();
        push_string(&mut logical, "hi");
        logical.extend_from_slice(&[0; 16]);
        logical.extend_from_slice(&[0x3b, 0xaa, 0xbb]);
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ClientToServer,
            &logical,
            Some(774),
        );
        assert!(!layout.complete);
        tiles(&layout, &logical);
    }

    #[test]
    fn malformed_utf8_strings_keep_their_bytes() {
        // status_response whose JSON text is one invalid UTF-8 byte. The
        // decoder shows it with a replacement character, but re-encoding an
        // unchanged field must not rewrite the wire bytes.
        let logical = [0x00, 0x01, 0xb6];
        let layout = layout_logical(
            ProtocolState::Status,
            Direction::ServerToClient,
            &logical,
            Some(774),
        );
        assert_eq!(layout.name.as_deref(), Some("status_response"));
        assert!(layout.complete);
        let response = layout
            .fields
            .iter()
            .find(|field| field.name == "response")
            .unwrap();
        assert_eq!(response.kind, FieldKind::String);
        assert_eq!(response.value, json!("\u{FFFD}"));
        tiles(&layout, &logical);
    }

    #[test]
    fn wide_integers_reach_javascript_as_text() {
        // chat_message: a salt past 2^53 would be rounded by a JS number.
        let mut logical = encode_var_i32(0x08).to_vec();
        push_string(&mut logical, "hi");
        logical.extend_from_slice(&5_i64.to_be_bytes());
        logical.extend_from_slice(&8_320_241_373_684_957_192_i64.to_be_bytes());
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ClientToServer,
            &logical,
            Some(774),
        );
        let value = |name: &str| {
            layout
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap()
                .value
                .clone()
        };
        assert_eq!(value("timestamp"), json!(5));
        assert_eq!(value("salt"), json!("8320241373684957192"));
        tiles(&layout, &logical);
    }

    #[test]
    fn a_handshake_lays_out_every_field() {
        let mut logical = encode_var_i32(0).to_vec();
        logical.extend_from_slice(&encode_var_i32(767));
        push_string(&mut logical, "play.example.net");
        logical.extend_from_slice(&25_565_u16.to_be_bytes());
        logical.extend_from_slice(&encode_var_i32(2));

        let layout = layout_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &logical,
            None,
        );
        assert_eq!(layout.name.as_deref(), Some("handshake"));
        assert!(layout.complete, "the walk must reach the end of the frame");
        let names: Vec<_> = layout
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect();
        assert_eq!(
            names,
            vec![
                "packet id",
                "protocol version",
                "server address",
                "server port",
                "next state"
            ]
        );
        let address = &layout.fields[2];
        assert_eq!(address.value, "play.example.net");
        assert_eq!(
            &logical[address.offset..address.offset + address.length],
            &logical[address.offset..address.offset + address.length]
        );
    }

    #[test]
    fn editing_a_field_splices_back_into_the_frame() {
        let mut logical = encode_var_i32(0).to_vec();
        logical.extend_from_slice(&encode_var_i32(767));
        push_string(&mut logical, "old.example.net");
        logical.extend_from_slice(&25_565_u16.to_be_bytes());
        logical.extend_from_slice(&encode_var_i32(2));

        let layout = layout_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &logical,
            None,
        );
        let field = layout
            .fields
            .iter()
            .find(|field| field.name == "server address")
            .expect("the address field");
        let replacement =
            encode_field(field.kind, &json!("a-much-longer.example.net")).expect("encodes");

        let mut edited = logical[..field.offset].to_vec();
        edited.extend_from_slice(&replacement);
        edited.extend_from_slice(&logical[field.offset + field.length..]);

        let round_trip = layout_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &edited,
            None,
        );
        assert_eq!(
            round_trip.fields[2].value, "a-much-longer.example.net",
            "the edit must survive as a decodable field"
        );
        assert_eq!(
            round_trip.fields[4].value, 2,
            "later fields keep their value"
        );
    }

    #[test]
    fn an_unknown_packet_is_still_editable_as_bytes() {
        let logical = vec![0x7f, 0xde, 0xad, 0xbe, 0xef];
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &logical,
            Some(767),
        );
        assert_eq!(layout.fields.len(), 2);
        assert_eq!(layout.fields[0].name, "packet id");
        assert_eq!(layout.fields[1].value, "deadbeef");
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn splice(logical: &[u8], field: &FieldSpan, value: &str) -> Vec<u8> {
        let original = &logical[field.offset..field.offset + field.length];
        let encoded = encode_field_over(field.kind, &json!(value), Some(original)).unwrap();
        let mut edited = logical[..field.offset].to_vec();
        edited.extend_from_slice(&encoded);
        edited.extend_from_slice(&logical[field.offset + field.length..]);
        edited
    }

    /// A captured `AuthMe` form submission (1.21.11).
    const CLICK_ACTION: &str = "081e617574686d653a7072656a6f696e2d72656769737465722f7375626d69741b0a080007636f6e6669726d000008000870617373776f7264000000";

    #[test]
    fn custom_click_action_nbt_rewrites_its_length() {
        let logical = from_hex(CLICK_ACTION);
        let layout = layout_logical(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            &logical,
            Some(774),
        );
        assert!(layout.complete);
        let payload = layout
            .fields
            .iter()
            .find(|field| field.name == "payload")
            .unwrap();
        assert_eq!(payload.kind, FieldKind::PrefixedNbt);
        assert_eq!(payload.value, r#"{"confirm": "", "password": ""}"#);

        let edited = splice(
            &logical,
            payload,
            r#"{"confirm": "hunter22", "password": "hunter22"}"#,
        );
        let prefix = payload.offset;
        assert_eq!(
            usize::from(edited[prefix]),
            edited.len() - prefix - 1,
            "the length must cover the new NBT"
        );
        let round_trip = layout_logical(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            &edited,
            Some(774),
        );
        assert!(round_trip.complete);
        assert_eq!(
            round_trip.fields.last().unwrap().value,
            r#"{"confirm": "hunter22", "password": "hunter22"}"#
        );
    }

    #[test]
    fn a_broken_tail_keeps_the_fields_before_it() {
        let logical = from_hex(CLICK_ACTION);
        // Cut the NBT short: the id still decodes, the rest is shown as hex.
        let cut = &logical[..logical.len() - 4];
        let layout = layout_logical(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            cut,
            Some(774),
        );
        assert!(!layout.complete);
        let names: Vec<_> = layout
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert_eq!(names[..2], ["packet id", "id"]);
        assert_eq!(layout.fields.last().unwrap().name, "rest");
        let covered: usize = layout.fields.iter().map(|field| field.length).sum();
        assert_eq!(covered, cut.len(), "every byte stays editable");
    }

    #[test]
    fn numbers_are_range_checked_before_they_reach_the_wire() {
        assert!(encode_field(FieldKind::U8, &json!(300)).is_err());
        assert_eq!(
            encode_field(FieldKind::U8, &json!("0x2a")).unwrap(),
            vec![0x2a]
        );
        assert_eq!(
            encode_field(FieldKind::F32, &json!("1.5")).unwrap(),
            1.5_f32.to_be_bytes().to_vec()
        );
    }
}

#[cfg(test)]
mod component_regression {
    use super::*;
    #[test]
    fn table_only_modern_components_are_nbt() {
        let id = crate::PacketRegistry::packet_id(
            ProtocolState::Play,
            Direction::ServerToClient,
            "system_chat",
            Some(776),
        )
        .unwrap();
        let mut logical = crate::encode_var_i32(id);
        logical.extend_from_slice(&[10, 8, 0, 4, b't', b'e', b'x', b't', 0, 1, b'x', 0, 0]);
        let layout = layout_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &logical,
            Some(776),
        );
        let component = layout
            .fields
            .iter()
            .find(|f| f.name == "component")
            .unwrap();
        assert_eq!(component.kind, FieldKind::Nbt);
    }

    #[test]
    fn field_lookup_stops_before_a_large_tail() {
        let mut logical = crate::encode_var_i32(0);
        logical.extend(crate::encode_var_i32(767));
        logical.extend(crate::encode_var_i32(9));
        logical.extend_from_slice(b"localhost");
        logical.extend_from_slice(&25565_u16.to_be_bytes());
        logical.extend(crate::encode_var_i32(2));
        logical.resize(1_000_000, 0xff);
        let layout = lookup_field(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &logical,
            Some(767),
            "server_address",
        );
        assert_eq!(layout.fields.len(), 1);
        assert_eq!(layout.fields[0].value, "localhost");
        let missing = lookup_field(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &logical,
            Some(767),
            "absent",
        );
        assert!(missing.fields.is_empty());
    }

    #[test]
    fn hex_edits_reject_garbage() {
        assert!(encode_field(FieldKind::Bytes, &Value::String("ab!cd".into())).is_err());
        assert_eq!(
            encode_field(FieldKind::Bytes, &Value::String("0xAB cd".into())).unwrap(),
            [0xab, 0xcd]
        );
    }
}
