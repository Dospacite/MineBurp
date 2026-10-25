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
    if !hand_complete
        && let Some(definition) =
            protodef::decode_packet(state, direction, packet_id, body, protocol_version)
        && definition.is_complete()
    {
        let mut fields = Vec::with_capacity(definition.spans.len() + 1);
        fields.push(builder.fields.swap_remove(0));
        fields.extend(definition.spans.into_iter().map(|span| FieldSpan {
            offset: span.offset + prefix,
            ..span
        }));
        return PacketLayout {
            name,
            fields,
            complete: true,
        };
    }
    builder.bytes("body");
    builder.finish(name)
}

/// Encodes one field value back into bytes.
///
/// The Repeater sends the edited value here rather than encoding it itself, so
/// the wire format lives in exactly one place.
pub fn encode_field(kind: FieldKind, value: &Value) -> Result<Vec<u8>, String> {
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
    })
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
    let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    if !digits.len().is_multiple_of(2) {
        return Err("hex needs complete byte pairs".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
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
            if builder.peek_string().is_some() {
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
    fields: Vec<FieldSpan>,
    /// Set once a read fails: everything after it is raw bytes.
    stopped: bool,
}

impl<'a> Builder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(input),
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
        let Some(value) = read(&mut self.reader) else {
            self.stopped = true;
            return None;
        };
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind,
            offset,
            length: self.reader.position() - offset,
            value: to_value(value.clone()),
        });
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

    /// A `VarInt`-prefixed byte array. The span covers the prefix as well as the
    /// payload, so an edit that changes the length rewrites both.
    fn length_prefixed(&mut self, name: &str) {
        if self.stopped {
            return;
        }
        let offset = self.reader.position();
        let Some(bytes) = self.reader.byte_array().map(<[u8]>::to_vec) else {
            self.stopped = true;
            return;
        };
        self.fields.push(FieldSpan {
            name: name.to_owned(),
            kind: FieldKind::PrefixedBytes,
            offset,
            length: self.reader.position() - offset,
            value: Value::String(to_hex(&bytes)),
        });
    }

    /// Whatever is left, as one hex field.
    fn bytes(&mut self, name: &str) {
        let rest = self.reader.rest();
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
