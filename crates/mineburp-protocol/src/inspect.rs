//! On-demand packet inspection.
//!
//! Decoding is deliberately *not* done while capturing: at Minecraft packet
//! rates that work is wasted on rows nobody opens. The desktop app calls into
//! this module only when an operator selects a packet.
//!
//! Play-state packet ids are renumbered nearly every Minecraft release, so this
//! module does not pretend to own a per-version id table. Instead each decoder
//! carries a strict validator and a packet is only *named* when its body
//! actually parses as that packet and consumes the bytes it should. A decoder
//! that half-matches reports nothing rather than a plausible lie, and every
//! packet still gets a generic structural read so the row is never empty.

use mineburp_core::{Direction, ProtocolState};
use serde_json::{Map, Value, json};

use crate::{
    common::decode_common_packet,
    nbt::{component_to_text, read_nbt},
    varint::decode_var_i32,
};

/// Bodies past this size are summarised structurally instead of walked field by
/// field, so opening a chunk or registry packet stays instant.
pub const LARGE_BODY_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 1 << 20;
const MAX_TEXT_SUMMARY: usize = 240;
const MAX_STREAM_PACKETS: usize = 512;
const SIGNATURE_BYTES: usize = 256;

/// How confident the inspector is about the name it reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identification {
    /// The state and packet id identify the packet unambiguously in every
    /// protocol version (handshake, status, and login).
    Registry,
    /// The body parsed cleanly as a known packet shape. Play-state ids move
    /// between versions, so shape is the evidence here, not the id.
    Structure,
    /// Nothing matched; only the generic structural read is available.
    #[default]
    Unidentified,
}

/// One packet found inside a raw transport payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StreamPacket {
    pub offset: usize,
    pub length: usize,
    pub packet_id: Option<i32>,
    pub name: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PacketInsight {
    /// Protocol name, e.g. `chat_message`.
    pub name: Option<String>,
    /// Human title for the inspector header.
    pub label: Option<String>,
    /// One line describing what this packet actually says.
    pub summary: Option<String>,
    /// Ordered decoded fields.
    pub fields: Option<Value>,
    pub channel: Option<String>,
    pub loader: Option<String>,
    pub identification: Identification,
    pub error: Option<String>,
    /// Operator-facing notes (signing, size, truncation).
    pub notes: Vec<String>,
    /// Packets recovered from a raw transport payload.
    pub stream: Vec<StreamPacket>,
}

/// Inspects a stored logical frame.
///
/// `logical` is what the project stores: for proxied Minecraft packets that is
/// the packet-id `VarInt` followed by the body; for passively captured frames it
/// is the raw transport payload.
#[must_use]
pub fn inspect_logical(
    state: ProtocolState,
    direction: Direction,
    logical: &[u8],
    protocol_version: Option<i32>,
) -> PacketInsight {
    if matches!(state, ProtocolState::Opaque | ProtocolState::Closed) {
        return inspect_transport_payload(direction, logical, protocol_version);
    }
    let Ok(Some((packet_id, prefix))) = decode_var_i32(logical) else {
        return PacketInsight {
            error: Some("frame does not start with a packet-id VarInt".into()),
            ..structural_read(logical)
        };
    };
    inspect_packet(
        state,
        direction,
        packet_id,
        logical.get(prefix..).unwrap_or_default(),
        protocol_version,
    )
}

/// Inspects one packet body that has already been split from its id.
#[must_use]
pub fn inspect_packet(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> PacketInsight {
    let mut insight = registry_decode(state, direction, packet_id, body, protocol_version)
        .or_else(|| structure_decode(state, direction, body, protocol_version))
        .unwrap_or_else(|| structural_read(body));
    if body.len() >= LARGE_BODY_BYTES {
        insight.notes.push(format!(
            "Body is {} bytes; only the leading fields were walked.",
            body.len()
        ));
    }
    insight
}

// --- identification by state and id (stable across every protocol version) ---

fn registry_decode(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    let name = crate::registry::PacketRegistry::stable_packet_name(state, direction, packet_id)
        .or_else(|| login_plugin_name(state, direction, packet_id, protocol_version))?;
    let common = decode_common_packet(state, direction, packet_id, body, protocol_version);
    let fields = common.fields.unwrap_or_else(|| structural_value(body));
    Some(PacketInsight {
        summary: Some(summarize(name, &fields)),
        name: Some(name.to_owned()),
        label: Some(title_case(name)),
        fields: Some(fields),
        channel: common.channel,
        loader: common.loader,
        identification: Identification::Registry,
        error: common.error,
        notes: Vec::new(),
        stream: Vec::new(),
    })
}

/// The login plugin exchange only exists from 1.13 (protocol 393) onwards, so
/// its ids are stable but version-gated.
fn login_plugin_name(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    protocol_version: Option<i32>,
) -> Option<&'static str> {
    if state != ProtocolState::Login || protocol_version.is_none_or(|version| version < 393) {
        return None;
    }
    match (direction, packet_id) {
        (Direction::ServerToClient, 4) => Some("login_plugin_request"),
        (Direction::ClientToServer, 2) => Some("login_plugin_response"),
        _ => None,
    }
}

// --- identification by body shape (play and configuration) ---

type Decoder = fn(&[u8], Option<i32>) -> Option<(&'static str, Value, Vec<String>)>;

fn structure_decode(
    state: ProtocolState,
    direction: Direction,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    if !matches!(state, ProtocolState::Play | ProtocolState::Configuration) {
        return None;
    }
    // Ordered strictest first: an exact-length or fully-consuming match is
    // stronger evidence than a prefix that merely parses.
    let decoders: &[Decoder] = match direction {
        Direction::ClientToServer => &[
            decode_keep_alive,
            decode_signed_chat_message,
            decode_signed_chat_command,
            decode_custom_payload,
            decode_lone_string,
        ],
        Direction::ServerToClient => &[
            decode_keep_alive,
            decode_text_component_packet,
            decode_custom_payload,
            decode_lone_string,
        ],
    };
    for decoder in decoders {
        if let Some((name, fields, notes)) = decoder(body, protocol_version) {
            let channel = fields
                .get("channel")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let loader = channel.as_deref().and_then(loader_for_channel);
            return Some(PacketInsight {
                summary: Some(summarize(name, &fields)),
                name: Some(name.to_owned()),
                label: Some(title_case(name)),
                fields: Some(fields),
                channel,
                loader: loader.map(str::to_owned),
                identification: Identification::Structure,
                error: None,
                notes,
                stream: Vec::new(),
            });
        }
    }
    None
}

/// 1.19+ serverbound chat: message, timestamp, salt, optional signature, then
/// the acknowledged-message bitset. The fixed 256-byte signature and a
/// plausible timestamp make this shape unmistakable.
fn decode_signed_chat_message(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    let (message, offset) = read_string(body, 0, 256)?;
    let timestamp = read_i64(body, offset)?;
    if !plausible_timestamp_millis(timestamp) {
        return None;
    }
    let salt = read_i64(body, offset + 8)?;
    let signed = *body.get(offset + 16)? != 0;
    let mut cursor = offset + 17;
    if signed {
        cursor = cursor.checked_add(SIGNATURE_BYTES)?;
        if cursor > body.len() {
            return None;
        }
    }
    let (acknowledged, cursor) = decode_var_i32(body.get(cursor..)?)
        .ok()
        .flatten()
        .map(|(value, length)| (value, cursor + length))?;
    if !(0..=1_024).contains(&acknowledged) {
        return None;
    }
    // Remaining bytes are the fixed acknowledgement bitset plus, on 1.21.5+, a
    // checksum byte. Anything larger means this is a different packet.
    let trailing = body.len().checked_sub(cursor)?;
    if trailing > 9 {
        return None;
    }
    let mut notes = vec![format!(
        "Client acknowledged {acknowledged} prior message(s) in this packet."
    )];
    if signed {
        notes.push(
            "Message carries a 256-byte player signature. Editing the text invalidates it and \
             modern servers will reject or kick the client."
                .into(),
        );
    }
    Some((
        "chat_message",
        json!({
            "message": message,
            "timestamp_millis": timestamp,
            "timestamp": format_millis(timestamp),
            "salt": salt,
            "signed": signed,
            "acknowledged_count": acknowledged,
        }),
        notes,
    ))
}

/// 1.19–1.20.4 serverbound signed command: the command text, timestamp, salt,
/// then a per-argument signature array.
fn decode_signed_chat_command(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    let (command, offset) = read_string(body, 0, 256)?;
    if command.is_empty() || command.starts_with('/') {
        return None;
    }
    let timestamp = read_i64(body, offset)?;
    if !plausible_timestamp_millis(timestamp) {
        return None;
    }
    let salt = read_i64(body, offset + 8)?;
    let (argument_count, mut cursor) = decode_var_i32(body.get(offset + 16..)?)
        .ok()
        .flatten()
        .map(|(value, length)| (value, offset + 16 + length))?;
    if !(0..=64).contains(&argument_count) {
        return None;
    }
    let mut arguments = Vec::new();
    for _ in 0..argument_count {
        let (name, next) = read_string(body, cursor, 16)?;
        cursor = next.checked_add(SIGNATURE_BYTES)?;
        if cursor > body.len() {
            return None;
        }
        arguments.push(Value::String(name));
    }
    Some((
        "chat_command",
        json!({
            "command": format!("/{command}"),
            "timestamp_millis": timestamp,
            "timestamp": format_millis(timestamp),
            "salt": salt,
            "signed_arguments": arguments,
        }),
        if argument_count > 0 {
            vec![
                "Command arguments are individually signed; editing them invalidates the \
                 signatures."
                    .into(),
            ]
        } else {
            Vec::new()
        },
    ))
}

/// Clientbound chat, disconnect, and other text-component packets. Modern
/// versions send NBT; 1.20.2 and older send a JSON string.
fn decode_text_component_packet(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    let (component, consumed) = read_text_component(body)?;
    if !(component.is_object() || component.is_string() || component.is_array()) {
        return None;
    }
    let trailing = body.len().checked_sub(consumed)?;
    // A trailing "overlay"/"action bar" boolean marks system chat; nothing left
    // marks a disconnect reason or another single-component packet.
    let (name, overlay) = match trailing {
        0 => ("text_component", None),
        1 => ("system_chat", Some(body[consumed] != 0)),
        _ => return None,
    };
    let text = component_to_text(&component);
    if text.is_empty() {
        return None;
    }
    let mut fields = Map::new();
    fields.insert("text".into(), Value::String(text));
    if let Some(overlay) = overlay {
        fields.insert("action_bar".into(), Value::Bool(overlay));
    }
    fields.insert("component".into(), component);
    Some((name, Value::Object(fields), Vec::new()))
}

/// Plugin / custom payload: a namespaced identifier followed by opaque data.
/// This is the mod and plugin attack surface, so it is worth naming precisely.
fn decode_custom_payload(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    let (channel, offset) = read_string(body, 0, 256)?;
    if !is_identifier(&channel) {
        return None;
    }
    let data = body.get(offset..)?;
    let mut fields = Map::new();
    fields.insert("channel".into(), Value::String(channel.clone()));
    fields.insert("data_length".into(), Value::from(data.len()));
    fields.insert("data_preview".into(), Value::String(hex_preview(data, 64)));
    if let Some(text) = printable_run(data, 8) {
        fields.insert("data_text".into(), Value::String(text));
    }
    let notes = loader_for_channel(&channel)
        .map(|loader| {
            vec![format!(
                "Channel belongs to the {loader} mod loader; its payload may carry its own \
                 integrity checks."
            )]
        })
        .unwrap_or_default();
    Some(("custom_payload", Value::Object(fields), notes))
}

/// Keep alive is exactly one long in both directions in every modern version.
fn decode_keep_alive(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    if body.len() != 8 {
        return None;
    }
    Some((
        "keep_alive",
        json!({ "id": read_i64(body, 0)? }),
        Vec::new(),
    ))
}

/// A body that is exactly one length-prefixed string: unsigned chat commands
/// (1.20.5+), brand strings, resource-pack hashes, and similar.
fn decode_lone_string(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value, Vec<String>)> {
    let (text, consumed) = read_string(body, 0, 32_767)?;
    if consumed != body.len() || text.is_empty() || !text.chars().any(char::is_alphanumeric) {
        return None;
    }
    let name = if text.starts_with('/') {
        "chat_command"
    } else {
        "string_payload"
    };
    Some((name, json!({ "value": text }), Vec::new()))
}

// --- raw transport payloads ---

/// Splits a passively captured TCP payload into Minecraft frames when it looks
/// like plaintext protocol traffic. Encrypted or mid-stream payloads simply
/// report the structural read instead.
fn inspect_transport_payload(
    direction: Direction,
    payload: &[u8],
    protocol_version: Option<i32>,
) -> PacketInsight {
    let mut stream = Vec::new();
    let mut identified = 0usize;
    let mut cursor = 0usize;
    while cursor < payload.len() && stream.len() < MAX_STREAM_PACKETS {
        let Ok(Some((length, prefix))) = decode_var_i32(&payload[cursor..]) else {
            break;
        };
        let Ok(length) = usize::try_from(length) else {
            break;
        };
        if length == 0 || length > payload.len() - cursor - prefix {
            break;
        }
        let start = cursor + prefix;
        let frame = &payload[start..start + length];
        let Ok(Some((packet_id, id_prefix))) = decode_var_i32(frame) else {
            break;
        };
        // Real packet ids are small. A multi-byte or negative id here means the
        // "length" was ciphertext that happened to look like a VarInt.
        if !(0..=0x03ff).contains(&packet_id) {
            break;
        }
        let inner = inspect_packet(
            ProtocolState::Play,
            direction,
            packet_id,
            &frame[id_prefix..],
            protocol_version,
        );
        if inner.identification != Identification::Unidentified {
            identified += 1;
        }
        stream.push(StreamPacket {
            offset: cursor,
            length: prefix + length,
            packet_id: Some(packet_id),
            name: inner.name,
            summary: inner.summary,
        });
        cursor = start + length;
    }

    // Random bytes routinely produce one accidental length-prefixed "frame", so
    // the framing is only reported when it proves itself: either a frame
    // actually decoded into a known packet, or several frames tile the payload
    // exactly, which ciphertext does not do by chance.
    let tiles_exactly = cursor == payload.len();
    if identified == 0 && !(tiles_exactly && stream.len() >= 3) {
        stream.clear();
    }

    let mut insight = structural_read(payload);
    if stream.is_empty() {
        insight.label = Some("Transport payload".into());
        insight.summary = Some(format!(
            "{} bytes of raw {} payload; no plaintext Minecraft framing recovered.",
            payload.len(),
            match direction {
                Direction::ClientToServer => "client→server",
                Direction::ServerToClient => "server→client",
            }
        ));
        insight.notes.push(
            "Passive capture sees the wire as-is. Once the session negotiates encryption the \
             payload stays ciphertext here."
                .into(),
        );
        return insight;
    }
    let trailing = payload.len().saturating_sub(cursor);
    insight.label = Some("Minecraft frames".into());
    insight.summary = Some(format!(
        "{} plaintext frame(s) recovered from {} bytes",
        stream.len(),
        payload.len()
    ));
    insight.name = Some("framed_stream".into());
    insight.identification = Identification::Structure;
    if trailing > 0 {
        insight.notes.push(format!(
            "{trailing} trailing byte(s) belong to a frame split across TCP segments."
        ));
    }
    insight.stream = stream;
    insight
}

// --- generic structural read (always available) ---

/// The floor everything falls back to: enough structure that an unnamed packet
/// is still worth looking at.
fn structural_read(body: &[u8]) -> PacketInsight {
    let fields = structural_value(body);
    PacketInsight {
        summary: Some(format!("{} byte body", body.len())),
        label: Some("Unrecognised packet".into()),
        fields: Some(fields),
        identification: Identification::Unidentified,
        ..PacketInsight::default()
    }
}

fn structural_value(body: &[u8]) -> Value {
    let window = &body[..body.len().min(LARGE_BODY_BYTES)];
    let mut fields = Map::new();
    fields.insert("length".into(), Value::from(body.len()));
    fields.insert("hex_preview".into(), Value::String(hex_preview(window, 64)));
    let strings: Vec<Value> = extract_strings(window, 6, 12)
        .into_iter()
        .map(Value::String)
        .collect();
    if !strings.is_empty() {
        fields.insert("printable_strings".into(), Value::Array(strings));
    }
    if let Ok(Some((value, _))) = decode_var_i32(window) {
        fields.insert("leading_var_int".into(), Value::from(value));
    }
    Value::Object(fields)
}

// --- helpers ---

fn read_string(input: &[u8], offset: usize, max_characters: usize) -> Option<(String, usize)> {
    let remaining = input.get(offset..)?;
    let (length, prefix) = decode_var_i32(remaining).ok().flatten()?;
    let length = usize::try_from(length).ok()?;
    // Minecraft caps strings by character count; four bytes per character is
    // the protocol's own upper bound.
    if length > MAX_STRING_BYTES || length > max_characters.saturating_mul(4) {
        return None;
    }
    let start = offset.checked_add(prefix)?;
    let end = start.checked_add(length)?;
    let value = std::str::from_utf8(input.get(start..end)?).ok()?;
    if value.chars().count() > max_characters {
        return None;
    }
    Some((value.to_owned(), end))
}

fn read_i64(input: &[u8], offset: usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    Some(i64::from_be_bytes(input.get(offset..end)?.try_into().ok()?))
}

fn read_text_component(input: &[u8]) -> Option<(Value, usize)> {
    if let Ok((value, consumed)) = read_nbt(input) {
        return Some((value, consumed));
    }
    let (text, consumed) = read_string(input, 0, 262_144)?;
    let trimmed = text.trim_start();
    if !trimmed.starts_with(['{', '[', '"']) {
        return None;
    }
    let value = serde_json::from_str(&text).ok()?;
    Some((value, consumed))
}

/// Rejects timestamps outside a decade around 2020, which is what separates a
/// real chat timestamp from eight arbitrary bytes.
fn plausible_timestamp_millis(value: i64) -> bool {
    const YEAR_2015: i64 = 1_420_070_400_000;
    const YEAR_2100: i64 = 4_102_444_800_000;
    (YEAR_2015..YEAR_2100).contains(&value)
}

fn format_millis(value: i64) -> String {
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

fn is_identifier(value: &str) -> bool {
    let Some((namespace, path)) = value.split_once(':') else {
        return false;
    };
    !namespace.is_empty()
        && !path.is_empty()
        && namespace.len() <= 64
        && namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-.".contains(&byte)
        })
        && path.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-./".contains(&byte)
        })
}

fn loader_for_channel(channel: &str) -> Option<&'static str> {
    let lower = channel.to_ascii_lowercase();
    if lower.contains("neoforge") {
        Some("neoforge")
    } else if lower.starts_with("fml:") || lower.starts_with("forge:") || lower.contains("fml|hs") {
        Some("forge")
    } else if lower.starts_with("fabric:") || lower.starts_with("fabric-") {
        Some("fabric")
    } else if lower.starts_with("quilt:") {
        Some("quilt")
    } else {
        None
    }
}

fn hex_preview(bytes: &[u8], limit: usize) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let window = &bytes[..bytes.len().min(limit)];
    let mut output = String::with_capacity(window.len() * 3 + 3);
    for (index, byte) in window.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    if bytes.len() > window.len() {
        output.push('…');
    }
    output
}

fn printable_run(bytes: &[u8], minimum: usize) -> Option<String> {
    extract_strings(bytes, minimum, 1).into_iter().next()
}

fn extract_strings(bytes: &[u8], minimum: usize, limit: usize) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = String::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(char::from(*byte));
        } else {
            if current.chars().count() >= minimum {
                found.push(std::mem::take(&mut current));
                if found.len() >= limit {
                    return found;
                }
            }
            current.clear();
        }
    }
    if current.chars().count() >= minimum && found.len() < limit {
        found.push(current);
    }
    found
}

fn title_case(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    for (index, word) in name.split('_').enumerate() {
        if index > 0 {
            output.push(' ');
        }
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            output.extend(first.to_uppercase());
            output.push_str(characters.as_str());
        }
    }
    output
}

/// Builds the one-line row description from whichever decoded field carries the
/// meaning of the packet.
fn summarize(name: &str, fields: &Value) -> String {
    for key in [
        "message",
        "command",
        "text",
        "value",
        "channel",
        "server_address",
        "username",
        "response",
        "id",
    ] {
        let Some(value) = fields.get(key) else {
            continue;
        };
        let rendered = match value {
            Value::String(text) => text.clone(),
            Value::Null | Value::Object(_) | Value::Array(_) => continue,
            other => other.to_string(),
        };
        if rendered.is_empty() {
            continue;
        }
        return format!("{name}: {}", truncate(&rendered, MAX_TEXT_SUMMARY));
    }
    name.to_owned()
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.replace(['\n', '\r'], " ");
    }
    let clipped: String = value.chars().take(limit).collect();
    format!("{}…", clipped.replace(['\n', '\r'], " "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_var_i32;

    fn push_string(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&encode_var_i32(i32::try_from(value.len()).unwrap()));
        output.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn decodes_a_signed_chat_message() {
        let mut body = Vec::new();
        push_string(&mut body, "hello world");
        body.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
        body.extend_from_slice(&42_i64.to_be_bytes());
        body.push(1);
        body.extend_from_slice(&[0_u8; SIGNATURE_BYTES]);
        body.extend_from_slice(&encode_var_i32(0));
        body.extend_from_slice(&[0, 0, 0]);

        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            0x06,
            &body,
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("chat_message"));
        assert_eq!(insight.identification, Identification::Structure);
        assert_eq!(insight.fields.unwrap()["message"], "hello world");
        assert!(insight.summary.unwrap().contains("hello world"));
        assert!(insight.notes.iter().any(|note| note.contains("signature")));
    }

    #[test]
    fn decodes_a_system_chat_component() {
        // NBT { text: "server says hi" } followed by the overlay flag.
        let mut body = vec![0x0a, 0x08, 0x00, 0x04];
        body.extend_from_slice(b"text");
        body.extend_from_slice(&14_u16.to_be_bytes());
        body.extend_from_slice(b"server says hi");
        body.push(0x00);
        body.push(0x00);

        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            0x6c,
            &body,
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("system_chat"));
        assert_eq!(insight.fields.unwrap()["text"], "server says hi");
    }

    #[test]
    fn decodes_a_mod_channel_payload() {
        let mut body = Vec::new();
        push_string(&mut body, "fabric:registry/sync");
        body.extend_from_slice(&[1, 2, 3, 4]);

        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            0x18,
            &body,
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("custom_payload"));
        assert_eq!(insight.channel.as_deref(), Some("fabric:registry/sync"));
        assert_eq!(insight.loader.as_deref(), Some("fabric"));
    }

    #[test]
    fn names_handshake_from_the_registry() {
        let mut body = encode_var_i32(767).to_vec();
        push_string(&mut body, "play.example.net");
        body.extend_from_slice(&25_565_u16.to_be_bytes());
        body.extend_from_slice(&encode_var_i32(2));

        let mut logical = encode_var_i32(0).to_vec();
        logical.extend_from_slice(&body);
        let insight = inspect_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &logical,
            None,
        );
        assert_eq!(insight.name.as_deref(), Some("handshake"));
        assert_eq!(insight.identification, Identification::Registry);
        assert_eq!(
            insight.fields.unwrap()["server_address"],
            "play.example.net"
        );
    }

    #[test]
    fn recovers_frames_from_a_transport_payload() {
        let mut frame = encode_var_i32(0x06).to_vec();
        let body_start = frame.len();
        push_string(&mut frame, "hello");
        frame.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
        frame.extend_from_slice(&7_i64.to_be_bytes());
        frame.push(0);
        frame.extend_from_slice(&encode_var_i32(0));
        frame.extend_from_slice(&[0, 0, 0]);
        assert!(frame.len() > body_start);

        let mut payload = encode_var_i32(i32::try_from(frame.len()).unwrap()).to_vec();
        payload.extend_from_slice(&frame);

        let insight = inspect_logical(
            ProtocolState::Opaque,
            Direction::ClientToServer,
            &payload,
            Some(767),
        );
        assert_eq!(insight.stream.len(), 1);
        assert_eq!(insight.stream[0].name.as_deref(), Some("chat_message"));
    }

    #[test]
    fn unrecognised_bodies_still_describe_themselves() {
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            0x21,
            &[0xff, 0x00, 0x13, 0x37, 0x99],
            Some(767),
        );
        assert_eq!(insight.identification, Identification::Unidentified);
        assert_eq!(insight.fields.unwrap()["length"], 5);
    }

    #[test]
    fn encrypted_payloads_are_not_mistaken_for_frames() {
        let payload: Vec<u8> = (0_u32..96)
            .map(|index| u8::try_from((index * 37 + 11) % 256).expect("byte range"))
            .collect();
        let insight = inspect_logical(
            ProtocolState::Opaque,
            Direction::ServerToClient,
            &payload,
            None,
        );
        assert!(insight.stream.is_empty());
        assert!(insight.summary.unwrap().contains("no plaintext"));
    }
}
