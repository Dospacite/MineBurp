//! On-demand packet inspection.
//!
//! Decoding is deliberately *not* done while capturing: at Minecraft packet
//! rates that work is wasted on rows nobody opens. The desktop app calls into
//! this module only when an operator selects a packet.
//!
//! Identification happens in three tiers, strongest first:
//!
//! 1. Handshake, status, and login ids have never moved, so the id alone names
//!    the packet.
//! 2. Configuration ids have been renumbered twice since 1.20.2, so the version
//!    table in [`crate::registry`] proposes a name and the body has to agree
//!    with it before it is used.
//! 3. Play ids are renumbered nearly every release, so nothing is read from the
//!    id at all: each decoder carries a strict validator and a packet is only
//!    named when its body actually parses as that packet and consumes the bytes
//!    it should.
//!
//! A decoder that half-matches reports nothing rather than a plausible lie.

use mineburp_core::{Direction, ProtocolState};
use serde_json::{Map, Value, json};

use crate::{
    common::decode_common_packet,
    nbt::{component_to_text, read_nbt},
    reader::{
        Reader, plausible_altitude, plausible_coordinate, plausible_pitch, plausible_yaw,
        unpack_position,
    },
    registry::PacketRegistry,
    varint::decode_var_i32,
};

const MAX_TEXT_SUMMARY: usize = 240;
const MAX_STREAM_PACKETS: usize = 512;
const SIGNATURE_BYTES: usize = 256;

/// How confident the inspector is about the name it reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identification {
    /// The state and packet id identify the packet, and the body agrees.
    Registry,
    /// The body parsed cleanly as a known packet shape. Play-state ids move
    /// between versions, so shape is the evidence here, not the id.
    Structure,
    /// Nothing matched; only the raw frame is available.
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
            ..structural_read()
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
    registry_decode(state, direction, packet_id, body, protocol_version)
        .or_else(|| configuration_decode(state, direction, packet_id, body, protocol_version))
        .or_else(|| play_decode(state, direction, packet_id, body, protocol_version))
        .or_else(|| structure_decode(state, direction, body, protocol_version))
        .unwrap_or_else(structural_read)
}

/// Bodies past this size are not shape-tested while capturing.
///
/// The size is what separates a packet worth naming from a chunk, registry, or
/// map payload: those are never named by shape, and walking their NBT once per
/// packet is exactly the work capture must not do.
const MAX_IDENTIFY_BYTES: usize = 4 * 1024;

/// Names a packet while capturing, without building a decode for it.
///
/// The history table wants a name for every row, but the full decode is
/// deliberately deferred until a packet is opened. This runs the same
/// identification and throws the fields away.
#[must_use]
pub fn identify_packet(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<String> {
    if let Some(name) = PacketRegistry::stable_packet_name(state, direction, packet_id)
        .or_else(|| login_plugin_name(state, direction, packet_id, protocol_version))
    {
        return Some(name.to_owned());
    }
    // A table lookup is a slice index, so the packets the size cap exists to
    // protect — chunks, registries, maps — are named for free when the version
    // has a table, and only the shape work is skipped.
    let tabulated = (state == ProtocolState::Play)
        .then(|| PacketRegistry::play_packet_name(direction, packet_id, protocol_version))
        .flatten();
    if body.len() > MAX_IDENTIFY_BYTES {
        return tabulated.map(str::to_owned);
    }
    configuration_decode(state, direction, packet_id, body, protocol_version)
        .or_else(|| play_decode(state, direction, packet_id, body, protocol_version))
        .or_else(|| structure_decode(state, direction, body, protocol_version))
        .and_then(|insight| insight.name)
}

// --- identification by state and id (stable across every protocol version) ---

fn registry_decode(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    let name = PacketRegistry::stable_packet_name(state, direction, packet_id)
        .or_else(|| login_plugin_name(state, direction, packet_id, protocol_version))?;
    let common = decode_common_packet(state, direction, packet_id, body, protocol_version);
    let fields = common.fields.unwrap_or_else(|| json!({}));
    Some(PacketInsight {
        summary: Some(summarize(name, &fields)),
        name: Some(name.to_owned()),
        label: Some(title_case(name)),
        fields: Some(fields),
        channel: common.channel,
        loader: common.loader,
        identification: Identification::Registry,
        error: common.error,
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

// --- configuration: a versioned id table, confirmed against the body ---

fn configuration_decode(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    if state != ProtocolState::Configuration {
        return None;
    }
    let name = PacketRegistry::configuration_packet_name(direction, packet_id, protocol_version)?;
    let fields = configuration_fields(name, body)?;
    let channel = fields
        .get("channel")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let loader = channel.as_deref().and_then(loader_for_channel);
    Some(PacketInsight {
        summary: Some(summarize(name, &fields)),
        name: Some(name.to_owned()),
        label: Some(title_case(name)),
        fields: Some(fields),
        channel,
        loader: loader.map(str::to_owned),
        identification: Identification::Registry,
        error: None,
        stream: Vec::new(),
    })
}

/// Confirms an id-proposed configuration name against the bytes.
///
/// Returning `None` means the body does not look like that packet — the id
/// table is being read with the wrong protocol version — and the packet falls
/// through to shape identification instead of being mislabelled.
fn configuration_fields(name: &str, body: &[u8]) -> Option<Value> {
    let mut reader = Reader::new(body);
    match name {
        "finish_configuration" | "finish_configuration_ack" | "reset_chat" => {
            body.is_empty().then(|| json!({}))
        }
        "keep_alive" => {
            if body.len() != 8 {
                return None;
            }
            Some(json!({ "id": reader.i64()? }))
        }
        "ping" | "pong" => {
            if body.len() != 4 {
                return None;
            }
            Some(json!({ "id": reader.i32()? }))
        }
        "plugin_message" => decode_custom_payload(body, None).map(|(_, fields)| fields),
        "client_information" => decode_client_information(body, None).map(|(_, fields)| fields),
        "disconnect" => decode_text_component_packet(body, None).map(|(_, fields)| fields),
        "known_packs" | "select_known_packs" => decode_known_packs(body, None).map(|(_, f)| f),
        "cookie_request" | "store_cookie" | "cookie_response" | "remove_resource_pack" => {
            let key = reader.identifier();
            Some(json!({ "key": key.unwrap_or_default() }))
        }
        "add_resource_pack" => decode_resource_pack_push(body, None).map(|(_, fields)| fields),
        "resource_pack_response" => {
            // 1.20.3 put a pack UUID in front of the result.
            if body.len() == 17 {
                reader.take(16)?;
            }
            let result = reader.var_i32().filter(|value| (0..=6).contains(value))?;
            reader
                .is_empty()
                .then(|| json!({ "result": resource_pack_result(result) }))
        }
        "transfer" => {
            let host = reader.string(255)?;
            let port = reader
                .var_i32()
                .filter(|value| (0..=65_535).contains(value))?;
            reader
                .is_empty()
                .then(|| json!({ "host": host, "port": port }))
        }
        "registry_data" => {
            // 1.20.5 split the registries into one packet each; before that the
            // whole set arrived as a single NBT compound.
            if let Some(registry) = reader.identifier() {
                let entries = reader.counted(65_536)?;
                return Some(json!({ "registry": registry, "entries": entries }));
            }
            read_nbt(body).ok().map(|_| json!({}))
        }
        "update_tags" | "update_enabled_features" | "server_links" | "custom_report_details" => {
            let count = reader.counted(8_192)?;
            Some(json!({ "entries": count }))
        }
        _ => Some(json!({})),
    }
}

fn resource_pack_result(value: i32) -> &'static str {
    match value {
        0 => "successfully_loaded",
        1 => "declined",
        2 => "failed_download",
        3 => "accepted",
        4 => "downloaded",
        5 => "invalid_url",
        6 => "failed_reload",
        _ => "discarded",
    }
}

// --- play: a generated id table, with the body given the final word ---

/// Names a play packet from the table generated for its protocol version.
///
/// This is the only tier that reads a play id, and it exists because shape has a
/// floor: a one-byte body holding `0` or `1` is an arm swing, a client command,
/// and a movement-input bitmask at once, and no validator can separate them. The
/// table is trusted because it is *derived* — `mineburp-packet-table` reads the
/// ids out of the version's own data generator report — never typed out.
///
/// It still does not outrank the bytes. The protocol version comes from a
/// handshake the client wrote, so it is a claim; the body is evidence. When a
/// decoder reads the body as a different packet, the body wins and the packet is
/// reported as a structural match, which is also what a version mismatch looks
/// like from the inside.
fn play_decode(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    if state != ProtocolState::Play {
        return None;
    }
    let name = PacketRegistry::play_packet_name(direction, packet_id, protocol_version)?;
    let Some(shape) = structure_decode(state, direction, body, protocol_version) else {
        return Some(PacketInsight {
            summary: Some(name.to_owned()),
            name: Some(name.to_owned()),
            label: Some(title_case(name)),
            identification: Identification::Registry,
            ..PacketInsight::default()
        });
    };
    if shape.name.as_deref() != Some(name) {
        return Some(shape);
    }
    Some(PacketInsight {
        identification: Identification::Registry,
        ..shape
    })
}

// --- identification by body shape (play and configuration) ---

type Decoder = fn(&[u8], Option<i32>) -> Option<(&'static str, Value)>;

/// Serverbound decoders, ordered strictest first: an exact-length or
/// fully-consuming match is stronger evidence than a prefix that merely parses.
const SERVERBOUND: &[Decoder] = &[
    decode_keep_alive,
    decode_client_information,
    decode_player_position_and_rotation,
    decode_player_position,
    decode_player_rotation,
    decode_move_vehicle,
    decode_signed_chat_message,
    decode_signed_chat_command,
    decode_player_action,
    decode_use_item_on,
    decode_sign_update,
    decode_interact,
    decode_command_suggestion,
    decode_known_packs,
    decode_player_command,
    decode_custom_payload,
    decode_use_item,
    decode_set_held_item,
    decode_lone_string,
];

const CLIENTBOUND: &[Decoder] = &[
    decode_keep_alive,
    decode_text_component_packet,
    decode_update_time,
    decode_player_abilities,
    decode_set_health,
    decode_set_experience,
    decode_game_event,
    decode_default_spawn_position,
    decode_block_update,
    decode_block_destruction,
    decode_block_event,
    decode_level_event,
    decode_synchronize_player_position,
    decode_teleport_entity,
    decode_login_play,
    decode_open_screen,
    decode_player_info_remove,
    decode_resource_pack_push,
    decode_custom_payload,
    decode_set_entity_motion,
    decode_move_entity,
    decode_remove_entities,
    decode_lone_string,
];

fn structure_decode(
    state: ProtocolState,
    direction: Direction,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<PacketInsight> {
    if !matches!(state, ProtocolState::Play | ProtocolState::Configuration) {
        return None;
    }
    let decoders = match direction {
        Direction::ClientToServer => SERVERBOUND,
        Direction::ServerToClient => CLIENTBOUND,
    };
    for decoder in decoders {
        let Some((name, fields)) = decoder(body, protocol_version) else {
            continue;
        };
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
            stream: Vec::new(),
        });
    }
    None
}

/// Keep alive is exactly one long in both directions in every modern version.
///
/// The length alone is not evidence — plenty of packets are eight bytes — so the
/// id has to look like one too: servers send either a millisecond clock or a
/// counter. Anything else is a different packet that happens to be this long.
fn decode_keep_alive(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 8 {
        return None;
    }
    let id = Reader::new(body)
        .i64()
        .filter(|value| (0..=i64::from(u32::MAX)).contains(value) || plausible_timestamp(*value))?;
    Some(("keep_alive", json!({ "id": id })))
}

/// 1.19+ serverbound chat: message, timestamp, salt, optional signature, then
/// the acknowledged-message bitset. The fixed 256-byte signature and a
/// plausible timestamp make this shape unmistakable.
fn decode_signed_chat_message(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let message = reader.string(256)?;
    // An empty message is never sent, and accepting one turned any packet whose
    // first byte was zero into a chat message waiting for a plausible timestamp.
    if message.is_empty() {
        return None;
    }
    let timestamp = reader.i64().filter(|value| plausible_timestamp(*value))?;
    let salt = reader.i64()?;
    let signed = reader.bool()?;
    if signed {
        reader.take(SIGNATURE_BYTES)?;
    }
    let acknowledged = reader.counted(1_024)?;
    // What is left is the fixed acknowledgement bitset plus, on 1.21.5+, a
    // checksum byte. Anything larger means this is a different packet.
    if reader.remaining() > 9 {
        return None;
    }
    Some((
        "chat_message",
        json!({
            "message": message,
            "timestamp": format_millis(timestamp),
            "salt": salt,
            "signed": signed,
            "acknowledged": acknowledged,
        }),
    ))
}

/// 1.19–1.20.4 serverbound signed command: the command text, timestamp, salt,
/// then a per-argument signature array.
fn decode_signed_chat_command(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let command = reader.string(256)?;
    if command.is_empty() || command.starts_with('/') {
        return None;
    }
    let timestamp = reader.i64().filter(|value| plausible_timestamp(*value))?;
    let salt = reader.i64()?;
    let arguments = reader.counted(64)?;
    let mut signed = Vec::new();
    for _ in 0..arguments {
        signed.push(Value::String(reader.string(16)?));
        reader.take(SIGNATURE_BYTES)?;
    }
    Some((
        "chat_command",
        json!({
            "command": format!("/{command}"),
            "timestamp": format_millis(timestamp),
            "salt": salt,
            "signed_arguments": signed,
        }),
    ))
}

/// Clientbound chat, disconnect, and other text-component packets. Modern
/// versions send NBT; 1.20.2 and older send a JSON string.
fn decode_text_component_packet(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let (component, consumed) = read_text_component(body)?;
    if !(component.is_object() || component.is_string() || component.is_array()) {
        return None;
    }
    // A trailing "overlay" boolean marks system chat; nothing left marks a
    // disconnect reason or another single-component packet.
    let (name, overlay) = match body.len().checked_sub(consumed)? {
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
    Some((name, Value::Object(fields)))
}

/// Plugin / custom payload: a namespaced identifier followed by opaque data.
/// This is the mod and plugin attack surface, so it is worth naming precisely.
fn decode_custom_payload(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let channel = reader.identifier()?;
    let mut fields = Map::new();
    fields.insert("channel".into(), Value::String(channel));
    if let Some(text) = printable_run(reader.rest(), 8) {
        fields.insert("data_text".into(), Value::String(text));
    }
    Some(("custom_payload", Value::Object(fields)))
}

/// The settings a client sends on join and whenever its options change: locale,
/// view distance, chat mode, and the skin-part bitmask.
fn decode_client_information(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let locale = reader.string(16)?;
    if locale.len() < 2
        || !locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    let view_distance = reader.i8().filter(|value| (2..=64).contains(value))?;
    let chat_mode = reader.var_i32().filter(|value| (0..=2).contains(value))?;
    let chat_colors = reader.bool()?;
    let skin_parts = reader.u8()?;
    let main_hand = reader.var_i32().filter(|value| (0..=1).contains(value))?;
    // Text filtering, server listing, and (1.21.2+) particle status follow; the
    // exact tail depends on the version, so only its size is checked.
    if reader.remaining() > 3 {
        return None;
    }
    Some((
        "client_information",
        json!({
            "locale": locale,
            "view_distance": view_distance,
            "chat_mode": match chat_mode { 0 => "enabled", 1 => "commands_only", _ => "hidden" },
            "chat_colors": chat_colors,
            "skin_parts": format!("0x{skin_parts:02x}"),
            "main_hand": if main_hand == 0 { "left" } else { "right" },
        }),
    ))
}

/// Movement without rotation: three doubles and the on-ground flags byte.
fn decode_player_position(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 25 {
        return None;
    }
    let mut reader = Reader::new(body);
    let (x, y, z) = read_location(&mut reader)?;
    let flags = reader.u8().filter(|value| *value <= 0x03)?;
    Some((
        "set_player_position",
        json!({ "x": x, "y": y, "z": z, "on_ground": flags & 0x01 != 0 }),
    ))
}

/// Movement with rotation: the position packet plus yaw and pitch.
fn decode_player_position_and_rotation(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    if body.len() != 33 {
        return None;
    }
    let mut reader = Reader::new(body);
    let (x, y, z) = read_location(&mut reader)?;
    let (yaw, pitch) = read_rotation(&mut reader)?;
    let flags = reader.u8().filter(|value| *value <= 0x03)?;
    Some((
        "set_player_position_and_rotation",
        json!({
            "x": x, "y": y, "z": z,
            "yaw": yaw, "pitch": pitch,
            "on_ground": flags & 0x01 != 0,
        }),
    ))
}

fn decode_player_rotation(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 9 {
        return None;
    }
    let mut reader = Reader::new(body);
    let (yaw, pitch) = read_rotation(&mut reader)?;
    let flags = reader.u8().filter(|value| *value <= 0x03)?;
    Some((
        "set_player_rotation",
        json!({ "yaw": yaw, "pitch": pitch, "on_ground": flags & 0x01 != 0 }),
    ))
}

/// Digging and the actions that share its packet: drop, swap, and shoot.
fn decode_player_action(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let status = reader.var_i32().filter(|value| (0..=6).contains(value))?;
    let position = unpack_position(reader.i64()?)?;
    let face = reader.u8().filter(|value| *value <= 5)?;
    let sequence = reader.var_i32().filter(|value| *value >= 0)?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "player_action",
        json!({
            "status": match status {
                0 => "start_digging",
                1 => "cancel_digging",
                2 => "finish_digging",
                3 => "drop_item_stack",
                4 => "drop_item",
                5 => "release_use_item",
                _ => "swap_item_in_hand",
            },
            "position": format_position(position),
            "face": face_name(face),
            "sequence": sequence,
        }),
    ))
}

/// Placing a block or using an item against one — the click that lands on a
/// block rather than on air or an entity.
fn decode_use_item_on(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let hand = reader.var_i32().filter(|value| (0..=1).contains(value))?;
    let position = unpack_position(reader.i64()?)?;
    let face = reader.var_i32().filter(|value| (0..=5).contains(value))?;
    let cursor = [reader.f32()?, reader.f32()?, reader.f32()?];
    if !cursor
        .iter()
        .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
    {
        return None;
    }
    let inside_block = reader.bool()?;
    // 1.21.2 added a "hit world border" flag before the sequence number. The
    // tail is two small values either way, so the version decides when it is
    // known and both readings are tried when it is not — accepting whichever
    // consumes the body exactly, which is the same evidence used everywhere.
    let world_border = match protocol {
        Some(version) if version >= 768 => Some(reader.bool()?),
        Some(_) => None,
        None => read_optional_flag(&mut reader),
    };
    let sequence = reader.var_i32().filter(|value| *value >= 0)?;
    if !reader.is_empty() {
        return None;
    }
    let mut fields = json!({
        "hand": if hand == 0 { "main" } else { "off" },
        "position": format_position(position),
        "face": face_name(u8::try_from(face).ok()?),
        "cursor": format!("{:.2}, {:.2}, {:.2}", cursor[0], cursor[1], cursor[2]),
        "inside_block": inside_block,
        "sequence": sequence,
    });
    if let (Some(hit), Some(object)) = (world_border, fields.as_object_mut()) {
        object.insert("hit_world_border".into(), Value::Bool(hit));
    }
    Some(("use_item_on", fields))
}

/// Reads a boolean only if what follows it still tiles the rest of the body.
///
/// Used where a version added a flag in front of a trailing `VarInt`: guessing
/// wrong leaves bytes over, and leftover bytes are what disqualifies a decode.
fn read_optional_flag(reader: &mut Reader<'_>) -> Option<bool> {
    let checkpoint = reader.clone();
    let flag = reader.bool();
    let tail = reader.var_i32();
    if flag.is_some() && tail.is_some_and(|value| value >= 0) && reader.is_empty() {
        return flag;
    }
    *reader = checkpoint;
    None
}

/// Attacking or right-clicking an entity: the click that lands on a mob or
/// another player. The trailing sneak flag and the bounded interaction type are
/// what make the shape unmistakable.
fn decode_interact(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let kind = reader.var_i32().filter(|value| (0..=2).contains(value))?;
    let mut target = None;
    if kind == 2 {
        let point = [reader.f32()?, reader.f32()?, reader.f32()?];
        if !point
            .iter()
            .all(|value| value.is_finite() && value.abs() <= 64.0)
        {
            return None;
        }
        target = Some(format!("{:.2}, {:.2}, {:.2}", point[0], point[1], point[2]));
    }
    let hand = if kind == 1 {
        None
    } else {
        Some(reader.var_i32().filter(|value| (0..=1).contains(value))?)
    };
    let sneaking = reader.bool()?;
    if !reader.is_empty() {
        return None;
    }
    let mut fields = Map::new();
    fields.insert("entity_id".into(), json!(entity_id));
    fields.insert(
        "action".into(),
        Value::String(
            match kind {
                0 => "interact",
                1 => "attack",
                _ => "interact_at",
            }
            .into(),
        ),
    );
    if let Some(hand) = hand {
        fields.insert(
            "hand".into(),
            Value::String(if hand == 0 { "main" } else { "off" }.into()),
        );
    }
    if let Some(target) = target {
        fields.insert("target".into(), Value::String(target));
    }
    fields.insert("sneaking".into(), Value::Bool(sneaking));
    Some(("interact", Value::Object(fields)))
}

/// Using an item with nothing in front of the player — eating, drawing a bow,
/// throwing a pearl.
///
/// A two-byte body is left alone deliberately: `hand` plus a small sequence
/// number is byte-for-byte a hotbar switch, and guessing between them would be
/// exactly the plausible lie this module refuses to tell. Sequence numbers pass
/// 127 within seconds of joining, so this names the packet from then on.
fn decode_use_item(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let hand = reader.var_i32().filter(|value| (0..=1).contains(value))?;
    let sequence = reader.var_i32().filter(|value| *value >= 128)?;
    // 1.21.3 appended the rotation the client was facing.
    let rotation = if reader.is_empty() {
        None
    } else {
        let yaw = reader.f32().filter(|value| plausible_yaw(*value))?;
        let pitch = reader.f32().filter(|value| plausible_pitch(*value))?;
        Some((yaw, pitch))
    };
    if !reader.is_empty() {
        return None;
    }
    let mut fields = json!({
        "hand": if hand == 0 { "main" } else { "off" },
        "sequence": sequence,
    });
    if let (Some((yaw, pitch)), Some(object)) = (rotation, fields.as_object_mut()) {
        object.insert("yaw".into(), json!(yaw));
        object.insert("pitch".into(), json!(pitch));
    }
    Some(("use_item", fields))
}

/// Sneaking, sprinting, and the other one-shot player state changes.
fn decode_player_command(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let action = reader.var_i32().filter(|value| (0..=8).contains(value))?;
    let boost = reader.var_i32().filter(|value| (0..=100).contains(value))?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "player_command",
        json!({
            "entity_id": entity_id,
            "action": match action {
                0 => "start_sneaking",
                1 => "stop_sneaking",
                2 => "leave_bed",
                3 => "start_sprinting",
                4 => "stop_sprinting",
                5 => "start_horse_jump",
                6 => "stop_horse_jump",
                7 => "open_vehicle_inventory",
                _ => "start_elytra_flight",
            },
            "jump_boost": boost,
        }),
    ))
}

/// Steering a boat, horse, or minecart: the vehicle's own position and facing.
fn decode_move_vehicle(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    // 1.21.2 appended an on-ground flag to the position and rotation.
    if !matches!(body.len(), 32 | 33) {
        return None;
    }
    let mut reader = Reader::new(body);
    let (x, y, z) = read_location(&mut reader)?;
    let (yaw, pitch) = read_rotation(&mut reader)?;
    if !reader.is_empty() {
        reader.bool()?;
    }
    Some((
        "move_vehicle",
        json!({ "x": x, "y": y, "z": z, "yaw": yaw, "pitch": pitch }),
    ))
}

/// Tab completion while a command is being typed.
fn decode_command_suggestion(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let transaction = reader.var_i32().filter(|value| *value >= 0)?;
    let text = reader.string(32_500)?;
    if !reader.is_empty() || !text.starts_with('/') {
        return None;
    }
    Some((
        "command_suggestion",
        json!({ "transaction": transaction, "text": text }),
    ))
}

/// Finishing a sign edit: the block, which face was written, and four lines.
fn decode_sign_update(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let position = unpack_position(reader.i64()?)?;
    // 1.20.5 put a front/back flag in front of the lines.
    let checkpoint = reader.clone();
    let (front, lines) = if let Some(lines) = read_sign_lines(&mut reader) {
        (None, lines)
    } else {
        reader = checkpoint;
        let front = reader.bool()?;
        (Some(front), read_sign_lines(&mut reader)?)
    };
    let mut fields = Map::new();
    fields.insert("position".into(), Value::String(format_position(position)));
    if let Some(front) = front {
        fields.insert(
            "face".into(),
            Value::String(if front { "front" } else { "back" }.into()),
        );
    }
    fields.insert("lines".into(), Value::Array(lines));
    Some(("sign_update", Value::Object(fields)))
}

fn read_sign_lines(reader: &mut Reader<'_>) -> Option<Vec<Value>> {
    let mut lines = Vec::with_capacity(4);
    for _ in 0..4 {
        lines.push(Value::String(reader.string(384)?));
    }
    reader.is_empty().then_some(lines)
}

/// The hotbar slot the client switched to.
fn decode_set_held_item(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 2 {
        return None;
    }
    let slot = Reader::new(body)
        .i16()
        .filter(|value| (0..=8).contains(value))?;
    Some(("set_held_item", json!({ "slot": slot })))
}

/// The data-pack negotiation added in 1.20.5: an array of namespace, id, and
/// version triples that has to tile the body exactly.
fn decode_known_packs(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let count = reader.counted(1_024)?;
    if count == 0 {
        return None;
    }
    let mut packs = Vec::with_capacity(count);
    for _ in 0..count {
        let namespace = reader.string(64)?;
        let id = reader.string(128)?;
        let version = reader.string(64)?;
        packs.push(Value::String(format!("{namespace}:{id} {version}")));
    }
    if !reader.is_empty() {
        return None;
    }
    Some(("known_packs", json!({ "packs": packs })))
}

/// A body that is exactly one length-prefixed string: unsigned chat commands
/// (1.20.5+), brand strings, resource-pack hashes, and similar.
fn decode_lone_string(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let text = reader.string(32_767)?;
    if !reader.is_empty() || text.is_empty() || !text.chars().any(char::is_alphanumeric) {
        return None;
    }
    let name = if text.starts_with('/') {
        "chat_command"
    } else {
        "string_payload"
    };
    Some((name, json!({ "value": text })))
}

/// World age and time of day, which every server sends on a fixed tick.
fn decode_update_time(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    // 1.21.2 appended a "time advances" flag.
    if !matches!(body.len(), 16 | 17) {
        return None;
    }
    let mut reader = Reader::new(body);
    let world_age = reader.i64().filter(|value| *value >= 0)?;
    let time_of_day = reader.i64()?;
    if time_of_day.abs() > 1_000_000_000_000 {
        return None;
    }
    let day_time = time_of_day.rem_euclid(24_000);
    Some((
        "update_time",
        json!({
            "world_age": world_age,
            "time_of_day": day_time,
            "clock": format!("{:02}:{:02}", (day_time / 1_000 + 6) % 24, (day_time % 1_000) * 60 / 1_000),
        }),
    ))
}

/// Health, hunger, and saturation.
fn decode_set_health(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let health = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=1_024.0).contains(value))
        .filter(|value| *value == 0.0 || *value >= 0.5)?;
    let food = reader.var_i32().filter(|value| (0..=20).contains(value))?;
    let saturation = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=20.0).contains(value))?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "set_health",
        json!({ "health": health, "food": food, "saturation": saturation }),
    ))
}

/// Experience bar, level, and total.
fn decode_set_experience(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let bar = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))?;
    let level = reader
        .var_i32()
        .filter(|value| (0..=24_791).contains(value))?;
    let total = reader.var_i32().filter(|value| *value >= 0)?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "set_experience",
        json!({ "progress": bar, "level": level, "total": total }),
    ))
}

/// Flight speed and field-of-view modifier, sent whenever the server changes
/// what the player may do.
fn decode_player_abilities(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 9 {
        return None;
    }
    let mut reader = Reader::new(body);
    let flags = reader.u8().filter(|value| *value <= 0x0f)?;
    let flying_speed = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))?;
    let fov_modifier = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=10.0).contains(value))?;
    Some((
        "player_abilities",
        json!({
            "invulnerable": flags & 0x01 != 0,
            "flying": flags & 0x02 != 0,
            "allow_flying": flags & 0x04 != 0,
            "instant_break": flags & 0x08 != 0,
            "flying_speed": flying_speed,
            "fov_modifier": fov_modifier,
        }),
    ))
}

/// Weather and gamemode changes, and the "join game" cue.
fn decode_game_event(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 5 {
        return None;
    }
    let mut reader = Reader::new(body);
    let event = reader.u8().filter(|value| *value <= 15)?;
    let value = reader.f32().filter(|value| value.is_finite())?;
    Some((
        "game_event",
        json!({
            "event": match event {
                0 => "no_respawn_block",
                1 => "begin_raining",
                2 => "end_raining",
                3 => "change_game_mode",
                4 => "win_game",
                5 => "demo_event",
                6 => "arrow_hit_player",
                7 => "rain_level_change",
                8 => "thunder_level_change",
                9 => "puffer_fish_sting",
                10 => "guardian_elder_effect",
                11 => "immediate_respawn",
                12 => "limited_crafting",
                _ => "level_chunks_load_start",
            },
            "value": value,
        }),
    ))
}

/// One block changing state.
fn decode_block_update(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if !(9..=12).contains(&body.len()) {
        return None;
    }
    let mut reader = Reader::new(body);
    let position = unpack_position(reader.i64()?)?;
    let state = reader
        .var_i32()
        .filter(|value| (0..=65_535).contains(value))?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "block_update",
        json!({ "position": format_position(position), "block_state": state }),
    ))
}

/// Where a fresh client spawns.
fn decode_default_spawn_position(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    if body.len() != 12 {
        return None;
    }
    let mut reader = Reader::new(body);
    let position = unpack_position(reader.i64()?)?;
    let angle = reader
        .f32()
        .filter(|value| value.is_finite() && value.abs() <= 360.0)?;
    Some((
        "set_default_spawn_position",
        json!({ "position": format_position(position), "angle": angle }),
    ))
}

/// The teleport a server sends to correct or move the client.
fn decode_synchronize_player_position(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let (x, y, z) = read_location(&mut reader)?;
    let (yaw, pitch) = read_rotation(&mut reader)?;
    let flags = reader.u8().filter(|value| *value <= 0x3f)?;
    let teleport_id = reader.var_i32().filter(|value| *value >= 0)?;
    // 1.19–1.21.1 end with an optional "dismount vehicle" boolean.
    if reader.remaining() > 1 {
        return None;
    }
    Some((
        "synchronize_player_position",
        json!({
            "x": x, "y": y, "z": z,
            "yaw": yaw, "pitch": pitch,
            "relative": format!("0x{flags:02x}"),
            "teleport_id": teleport_id,
        }),
    ))
}

/// The clientbound login packet that opens play: an entity id, the hardcore
/// flag, and the list of dimensions the server offers.
fn decode_login_play(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.i32()?;
    let hardcore = reader.bool()?;
    let count = reader.counted(256)?;
    if count == 0 {
        return None;
    }
    let mut dimensions = Vec::with_capacity(count);
    for _ in 0..count {
        dimensions.push(Value::String(reader.identifier()?));
    }
    let max_players = reader.var_i32().filter(|value| *value >= 0)?;
    let view_distance = reader.var_i32().filter(|value| (2..=64).contains(value))?;
    Some((
        "login",
        json!({
            "entity_id": entity_id,
            "hardcore": hardcore,
            "dimensions": dimensions,
            "max_players": max_players,
            "view_distance": view_distance,
        }),
    ))
}

/// The crack overlay while a block is being mined — the other half of what an
/// operator sees when someone holds down left click.
///
/// This packet and `move_entity_pos_rot` are both a `VarInt` id followed by nine
/// bytes, so the two are separated by their last byte alone: a crack stage runs
/// 0..=9 while an on-ground flag is 0 or 1. The overlap is given to the move,
/// which is orders of magnitude more common, and the first two crack stages are
/// left unnamed rather than named on a coin flip.
fn decode_block_destruction(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let position = unpack_position(reader.i64()?)?;
    let stage = reader.u8().filter(|value| (2..=9).contains(value))?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "block_destruction",
        json!({
            "entity_id": entity_id,
            "position": format_position(position),
            "stage": stage,
        }),
    ))
}

/// Chests opening, note blocks playing, pistons moving.
fn decode_block_event(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let position = unpack_position(reader.i64()?)?;
    let action = reader.u8()?;
    let parameter = reader.u8()?;
    let block = reader
        .var_i32()
        .filter(|value| (0..=1_024).contains(value))?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "block_event",
        json!({
            "position": format_position(position),
            "action": action,
            "parameter": parameter,
            "block_type": block,
        }),
    ))
}

/// Doors, dispensers, and the other one-shot world effects.
fn decode_level_event(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 17 {
        return None;
    }
    let mut reader = Reader::new(body);
    // Event ids are drawn from three documented blocks; anything else is a
    // different packet that happens to be seventeen bytes long.
    let event = reader
        .i32()
        .filter(|value| (1_000..=1_100).contains(value) || (2_000..=3_010).contains(value))?;
    let position = unpack_position(reader.i64()?)?;
    let data = reader.i32()?;
    let global = reader.bool()?;
    Some((
        "level_event",
        json!({
            "event": event,
            "position": format_position(position),
            "data": data,
            "global": global,
        }),
    ))
}

/// A container, workbench, or other screen the server opens on the client.
fn decode_open_screen(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let window = reader.var_i32().filter(|value| (1..=127).contains(value))?;
    let kind = reader.var_i32().filter(|value| (0..=63).contains(value))?;
    let rest = reader.rest();
    let (component, consumed) = read_text_component(rest)?;
    if consumed != rest.len() {
        return None;
    }
    let title = component_to_text(&component);
    if title.is_empty() {
        return None;
    }
    Some((
        "open_screen",
        json!({ "window_id": window, "type": kind, "title": title }),
    ))
}

/// Entities the client should forget: despawns, deaths, and unloads.
fn decode_remove_entities(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let count = reader.counted(4_096)?;
    if count == 0 {
        return None;
    }
    let mut entities = Vec::with_capacity(count.min(32));
    for index in 0..count {
        let id = reader.var_i32().filter(|value| *value >= 0)?;
        if index < 32 {
            entities.push(json!(id));
        }
    }
    if !reader.is_empty() {
        return None;
    }
    Some((
        "remove_entities",
        json!({ "count": count, "entities": entities }),
    ))
}

/// Players leaving the tab list, which is a `VarInt` count of whole UUIDs.
fn decode_player_info_remove(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let count = reader.counted(1_024)?;
    if count == 0 {
        return None;
    }
    let mut players = Vec::with_capacity(count.min(16));
    for index in 0..count {
        let uuid = reader.uuid()?;
        if index < 16 {
            players.push(Value::String(uuid.to_string()));
        }
    }
    if !reader.is_empty() {
        return None;
    }
    Some((
        "player_info_remove",
        json!({ "count": count, "players": players }),
    ))
}

/// Knock-back, explosions, and anything else that pushes an entity.
fn decode_set_entity_motion(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    if reader.remaining() != 6 {
        return None;
    }
    // Velocity travels as blocks per tick times 8000.
    let velocity: Vec<f64> = (0..3)
        .map(|_| reader.i16().map(|value| f64::from(value) / 8_000.0))
        .collect::<Option<Vec<_>>>()?;
    Some((
        "set_entity_motion",
        json!({
            "entity_id": entity_id,
            "velocity": format!("{:.3}, {:.3}, {:.3}", velocity[0], velocity[1], velocity[2]),
        }),
    ))
}

/// The short relative moves servers send for every entity in view.
///
/// One decoder for the three variants because they differ only in what follows
/// the entity id, and each one has to consume the body exactly.
fn decode_move_entity(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let mut fields = Map::new();
    fields.insert("entity_id".into(), json!(entity_id));
    let name = match reader.remaining() {
        // Deltas travel as blocks times 4096.
        7 | 9 => {
            let delta: Vec<f64> = (0..3)
                .map(|_| reader.i16().map(|value| f64::from(value) / 4_096.0))
                .collect::<Option<Vec<_>>>()?;
            fields.insert(
                "delta".into(),
                Value::String(format!("{:.3}, {:.3}, {:.3}", delta[0], delta[1], delta[2])),
            );
            if reader.remaining() == 3 {
                read_entity_angles(&mut reader, &mut fields)?;
                "move_entity_pos_rot"
            } else {
                "move_entity_pos"
            }
        }
        3 => {
            read_entity_angles(&mut reader, &mut fields)?;
            "move_entity_rot"
        }
        _ => return None,
    };
    fields.insert("on_ground".into(), Value::Bool(reader.bool()?));
    if !reader.is_empty() {
        return None;
    }
    Some((name, Value::Object(fields)))
}

/// An absolute entity move, sent when a relative delta would not reach.
fn decode_teleport_entity(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let remaining = reader.remaining();
    // 1.21.2 grew the packet from position, facing, and a flag to a full state:
    // position, velocity, float angles, and a relative-movement mask.
    if !matches!(remaining, 27 | 61) {
        return None;
    }
    let (x, y, z) = read_location(&mut reader)?;
    let mut fields = Map::new();
    fields.insert("entity_id".into(), json!(entity_id));
    fields.insert("x".into(), json!(x));
    fields.insert("y".into(), json!(y));
    fields.insert("z".into(), json!(z));
    if remaining == 27 {
        read_entity_angles(&mut reader, &mut fields)?;
    } else {
        for _ in 0..3 {
            reader.f64().filter(|value| value.is_finite())?;
        }
        let (yaw, pitch) = read_rotation(&mut reader)?;
        fields.insert("yaw".into(), json!(yaw));
        fields.insert("pitch".into(), json!(pitch));
        reader.i32()?;
    }
    fields.insert("on_ground".into(), Value::Bool(reader.bool()?));
    if !reader.is_empty() {
        return None;
    }
    Some(("teleport_entity", Value::Object(fields)))
}

/// Entity facing travels as two bytes covering a full turn.
fn read_entity_angles(reader: &mut Reader<'_>, fields: &mut Map<String, Value>) -> Option<()> {
    let yaw = f64::from(reader.u8()?) * 360.0 / 256.0;
    let pitch = f64::from(reader.u8()?) * 360.0 / 256.0;
    fields.insert("yaw".into(), json!(format!("{yaw:.1}")));
    fields.insert("pitch".into(), json!(format!("{pitch:.1}")));
    Some(())
}

/// A resource pack the server asks the client to load.
fn decode_resource_pack_push(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    // 1.20.3 put a pack UUID in front of the URL.
    let checkpoint = reader.clone();
    let url = match reader.string(32_767) {
        Some(value) if value.starts_with("http") => value,
        _ => {
            reader = checkpoint;
            reader.take(16)?;
            reader
                .string(32_767)
                .filter(|value| value.starts_with("http"))?
        }
    };
    let hash = reader.string(40)?;
    if !hash.is_empty() && !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let forced = reader.bool()?;
    Some((
        "add_resource_pack",
        json!({ "url": url, "hash": hash, "forced": forced }),
    ))
}

// --- raw transport payloads ---

/// Splits a passively captured TCP payload into Minecraft frames when it looks
/// like plaintext protocol traffic. Encrypted or mid-stream payloads simply
/// report the raw frame instead.
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

    let mut insight = structural_read();
    if stream.is_empty() {
        insight.summary = Some(format!("{} bytes", payload.len()));
        return insight;
    }
    insight.label = Some("Minecraft frames".into());
    insight.summary = Some(format!(
        "{} frame(s) in {} bytes",
        stream.len(),
        payload.len()
    ));
    insight.name = Some("framed_stream".into());
    insight.identification = Identification::Structure;
    insight.stream = stream;
    insight
}

// --- the floor everything falls back to ---

fn structural_read() -> PacketInsight {
    PacketInsight {
        identification: Identification::Unidentified,
        ..PacketInsight::default()
    }
}

// --- helpers ---

fn read_location(reader: &mut Reader<'_>) -> Option<(f64, f64, f64)> {
    let x = reader.f64().filter(|value| plausible_coordinate(*value))?;
    let y = reader.f64().filter(|value| plausible_altitude(*value))?;
    let z = reader.f64().filter(|value| plausible_coordinate(*value))?;
    Some((x, y, z))
}

fn read_rotation(reader: &mut Reader<'_>) -> Option<(f32, f32)> {
    let yaw = reader.f32().filter(|value| plausible_yaw(*value))?;
    let pitch = reader.f32().filter(|value| plausible_pitch(*value))?;
    Some((yaw, pitch))
}

fn format_position((x, y, z): (i32, i32, i32)) -> String {
    format!("{x}, {y}, {z}")
}

fn face_name(face: u8) -> &'static str {
    match face {
        0 => "bottom",
        1 => "top",
        2 => "north",
        3 => "south",
        4 => "west",
        _ => "east",
    }
}

fn read_text_component(input: &[u8]) -> Option<(Value, usize)> {
    if let Ok((value, consumed)) = read_nbt(input) {
        return Some((value, consumed));
    }
    let mut reader = Reader::new(input);
    let text = reader.string(262_144)?;
    let trimmed = text.trim_start();
    if !trimmed.starts_with(['{', '[', '"']) {
        return None;
    }
    let value = serde_json::from_str(&text).ok()?;
    Some((value, reader.position()))
}

/// Rejects timestamps outside a plausible window, which is what separates a
/// real chat timestamp from eight arbitrary bytes.
fn plausible_timestamp(value: i64) -> bool {
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

fn printable_run(bytes: &[u8], minimum: usize) -> Option<String> {
    let mut current = String::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(char::from(*byte));
        } else {
            if current.chars().count() >= minimum {
                return Some(current);
            }
            current.clear();
        }
    }
    (current.chars().count() >= minimum).then_some(current)
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
        "url",
        "locale",
        "position",
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

    fn play(direction: Direction, body: &[u8]) -> PacketInsight {
        inspect_packet(ProtocolState::Play, direction, 0x00, body, Some(767))
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

        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("chat_message"));
        assert_eq!(insight.identification, Identification::Structure);
        assert_eq!(insight.fields.unwrap()["message"], "hello world");
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

        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("system_chat"));
        assert_eq!(insight.fields.unwrap()["text"], "server says hi");
    }

    #[test]
    fn decodes_a_mod_channel_payload() {
        let mut body = Vec::new();
        push_string(&mut body, "fabric:registry/sync");
        body.extend_from_slice(&[1, 2, 3, 4]);

        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("custom_payload"));
        assert_eq!(insight.channel.as_deref(), Some("fabric:registry/sync"));
        assert_eq!(insight.loader.as_deref(), Some("fabric"));
    }

    #[test]
    fn decodes_movement_packets() {
        let mut body = Vec::new();
        body.extend_from_slice(&8.5_f64.to_be_bytes());
        body.extend_from_slice(&64.0_f64.to_be_bytes());
        body.extend_from_slice(&(-19.25_f64).to_be_bytes());
        body.push(1);
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("set_player_position"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["y"], 64.0);
        assert_eq!(fields["on_ground"], true);

        body.pop();
        body.extend_from_slice(&90.0_f32.to_be_bytes());
        body.extend_from_slice(&(-12.5_f32).to_be_bytes());
        body.push(0);
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(
            insight.name.as_deref(),
            Some("set_player_position_and_rotation")
        );
        assert_eq!(insight.fields.unwrap()["pitch"], -12.5);
    }

    #[test]
    fn decodes_client_information() {
        let mut body = Vec::new();
        push_string(&mut body, "en_us");
        body.push(12); // view distance
        body.extend_from_slice(&encode_var_i32(0)); // chat mode
        body.push(1); // chat colours
        body.push(0x7f); // skin parts
        body.extend_from_slice(&encode_var_i32(1)); // main hand
        body.push(0); // text filtering
        body.push(1); // server listing

        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("client_information"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["locale"], "en_us");
        assert_eq!(fields["view_distance"], 12);
        assert_eq!(fields["main_hand"], "right");
    }

    #[test]
    fn decodes_a_dig_action() {
        let position =
            ((7_i64 & 0x3ff_ffff) << 38) | ((-3_i64 & 0x3ff_ffff) << 12) | (0x48 & 0xfff);
        let mut body = encode_var_i32(0).to_vec();
        body.extend_from_slice(&position.to_be_bytes());
        body.push(1);
        body.extend_from_slice(&encode_var_i32(41));

        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("player_action"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["status"], "start_digging");
        assert_eq!(fields["position"], "7, 72, -3");
        assert_eq!(fields["face"], "top");
    }

    fn packed_position(x: i64, y: i64, z: i64) -> [u8; 8] {
        (((x & 0x3ff_ffff) << 38) | ((z & 0x3ff_ffff) << 12) | (y & 0xfff)).to_be_bytes()
    }

    #[test]
    fn decodes_clicking_an_entity() {
        // Attack: entity id, type 1, sneaking.
        let mut body = encode_var_i32(4_812).to_vec();
        body.extend_from_slice(&encode_var_i32(1));
        body.push(0);
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("interact"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["action"], "attack");
        assert_eq!(fields["entity_id"], 4_812);

        // Right click at a point on the entity: type 2 carries the hit vector
        // and the hand, and the sneak flag still closes the body.
        let mut body = encode_var_i32(7).to_vec();
        body.extend_from_slice(&encode_var_i32(2));
        for value in [0.5_f32, 1.25, -0.25] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&encode_var_i32(0));
        body.push(1);
        let fields = play(Direction::ClientToServer, &body).fields.unwrap();
        assert_eq!(fields["action"], "interact_at");
        assert_eq!(fields["hand"], "main");
        assert_eq!(fields["sneaking"], true);
    }

    #[test]
    fn decodes_right_click_actions() {
        // use_item: hand plus a sequence number that has left the ambiguous
        // two-byte window.
        let mut body = encode_var_i32(0).to_vec();
        body.extend_from_slice(&encode_var_i32(4_096));
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("use_item"));
        assert_eq!(insight.fields.unwrap()["sequence"], 4_096);

        // A small sequence is byte-for-byte a hotbar switch, so the packet that
        // can be confirmed by length wins rather than the one that cannot.
        let mut body = encode_var_i32(0).to_vec();
        body.extend_from_slice(&encode_var_i32(3));
        assert_eq!(
            play(Direction::ClientToServer, &body).name.as_deref(),
            Some("set_held_item")
        );
    }

    #[test]
    fn decodes_placing_a_block_on_1_21_2_and_earlier() {
        let mut body = encode_var_i32(0).to_vec();
        body.extend_from_slice(&packed_position(12, 70, -34));
        body.extend_from_slice(&encode_var_i32(1));
        for value in [0.5_f32, 1.0, 0.5] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.push(0); // inside block
        let classic = body.clone();

        // 1.21.2 inserted the world-border flag in front of the sequence.
        body.push(0);
        body.extend_from_slice(&encode_var_i32(300));
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            0x00,
            &body,
            Some(768),
        );
        assert_eq!(insight.name.as_deref(), Some("use_item_on"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["position"], "12, 70, -34");
        assert_eq!(fields["hit_world_border"], false);

        let mut older = classic;
        older.extend_from_slice(&encode_var_i32(300));
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            0x00,
            &older,
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("use_item_on"));
        assert_eq!(insight.fields.unwrap()["face"], "top");
    }

    #[test]
    fn decodes_sneaking_and_sprinting() {
        let mut body = encode_var_i32(391).to_vec();
        body.extend_from_slice(&encode_var_i32(3));
        body.extend_from_slice(&encode_var_i32(0));
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("player_command"));
        assert_eq!(insight.fields.unwrap()["action"], "start_sprinting");
    }

    #[test]
    fn decodes_entity_movement_and_removal() {
        // A relative move with a new facing.
        let mut body = encode_var_i32(120).to_vec();
        for delta in [410_i16, 0, -205] {
            body.extend_from_slice(&delta.to_be_bytes());
        }
        body.push(64);
        body.push(0);
        body.push(1);
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("move_entity_pos_rot"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["on_ground"], true);
        assert_eq!(fields["yaw"], "90.0");

        // The same packet without the facing bytes.
        let mut body = encode_var_i32(120).to_vec();
        for delta in [410_i16, 0, -205] {
            body.extend_from_slice(&delta.to_be_bytes());
        }
        body.push(1);
        assert_eq!(
            play(Direction::ServerToClient, &body).name.as_deref(),
            Some("move_entity_pos")
        );

        let mut body = encode_var_i32(3).to_vec();
        for id in [120_i32, 121, 122] {
            body.extend_from_slice(&encode_var_i32(id));
        }
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("remove_entities"));
        assert_eq!(insight.fields.unwrap()["count"], 3);
    }

    #[test]
    fn decodes_block_effects() {
        let mut body = encode_var_i32(88).to_vec();
        body.extend_from_slice(&packed_position(-4, 63, 19));
        body.push(7);
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("block_destruction"));
        assert_eq!(insight.fields.unwrap()["stage"], 7);

        let mut body = 1_010_i32.to_be_bytes().to_vec();
        body.extend_from_slice(&packed_position(1, 64, 2));
        body.extend_from_slice(&0_i32.to_be_bytes());
        body.push(0);
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("level_event"));
        assert_eq!(insight.fields.unwrap()["position"], "1, 64, 2");
    }

    #[test]
    fn an_eight_byte_body_is_not_automatically_a_keep_alive() {
        // A packed chunk-position long: too large to be a counter and far from
        // any plausible clock, so it must not be named for its length alone.
        let insight = play(
            Direction::ServerToClient,
            &0x2a3b_4c5d_6e7f_8091_u64.to_be_bytes(),
        );
        assert_eq!(insight.identification, Identification::Unidentified);

        let insight = play(
            Direction::ServerToClient,
            &1_700_000_000_000_i64.to_be_bytes(),
        );
        assert_eq!(insight.name.as_deref(), Some("keep_alive"));
    }

    #[test]
    fn decodes_a_sign_edit_in_both_shapes() {
        let mut body = packed_position(5, 65, 5).to_vec();
        body.push(1); // 1.20.5+ front/back flag
        for line in ["hello", "there", "", ""] {
            push_string(&mut body, line);
        }
        let insight = play(Direction::ClientToServer, &body);
        assert_eq!(insight.name.as_deref(), Some("sign_update"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["face"], "front");
        assert_eq!(fields["lines"][0], "hello");
    }

    /// Ids the generated 1.21.4 table carries, so the intent of each case is
    /// readable without counting entries in the data file.
    const SWING: i32 = 58;
    const MOVE_PLAYER_POS: i32 = 28;

    #[test]
    fn a_generated_table_names_the_packets_shape_can_never_reach() {
        // One byte holding a hand: an arm swing, a client command, and a
        // container close are byte-for-byte identical, so only the table can
        // say which one this is.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &[0x00],
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("swing"));
        assert_eq!(insight.identification, Identification::Registry);
        assert!(
            insight.fields.is_none(),
            "a name from the table is not a decode: there are no fields to invent"
        );

        // The same id on a version with no generated table stays unnamed rather
        // than borrowing a neighbouring release's numbering.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &[0x00],
            Some(767),
        );
        assert_eq!(insight.identification, Identification::Unidentified);
    }

    #[test]
    fn the_body_overrules_the_table_when_they_disagree() {
        let mut body = Vec::new();
        body.extend_from_slice(&8.5_f64.to_be_bytes());
        body.extend_from_slice(&64.0_f64.to_be_bytes());
        body.extend_from_slice(&(-19.25_f64).to_be_bytes());
        body.push(1);

        // Sent under the id the table calls an arm swing: the bytes are a
        // movement packet, and a client is free to lie about its version.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &body,
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("set_player_position"));
        assert_eq!(insight.identification, Identification::Structure);

        // Under the id the table agrees with, the same bytes are promoted: the
        // id and the body are two independent witnesses to one name.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            MOVE_PLAYER_POS,
            &body,
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("set_player_position"));
        assert_eq!(insight.identification, Identification::Registry);
        assert_eq!(insight.fields.unwrap()["y"], 64.0);
    }

    #[test]
    fn a_table_names_oversized_bodies_capture_refuses_to_shape_test() {
        let huge = vec![0x00_u8; MAX_IDENTIFY_BYTES + 1];
        assert_eq!(
            identify_packet(
                ProtocolState::Play,
                Direction::ClientToServer,
                SWING,
                &huge,
                Some(769)
            )
            .as_deref(),
            Some("swing"),
            "a table lookup costs nothing, so the size cap only skips shape work"
        );
        assert_eq!(
            identify_packet(
                ProtocolState::Play,
                Direction::ClientToServer,
                SWING,
                &huge,
                Some(767)
            ),
            None
        );
    }

    #[test]
    fn decodes_configuration_packets_from_their_version_table() {
        // 1.21 clientbound keep alive lives at 0x04 in configuration.
        let insight = inspect_packet(
            ProtocolState::Configuration,
            Direction::ServerToClient,
            0x04,
            &7_i64.to_be_bytes(),
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("keep_alive"));
        assert_eq!(insight.identification, Identification::Registry);

        // The same id in 1.20.4 is ping, which takes four bytes, so the eight
        // byte body must not be accepted under that name.
        let insight = inspect_packet(
            ProtocolState::Configuration,
            Direction::ServerToClient,
            0x04,
            &7_i64.to_be_bytes(),
            Some(765),
        );
        assert_eq!(insight.name.as_deref(), Some("keep_alive"));
        assert_eq!(
            insight.identification,
            Identification::Structure,
            "a body that contradicts the id table falls back to its shape"
        );
    }

    #[test]
    fn decodes_known_packs() {
        let mut body = encode_var_i32(1).to_vec();
        push_string(&mut body, "minecraft");
        push_string(&mut body, "core");
        push_string(&mut body, "1.21");
        let insight = inspect_packet(
            ProtocolState::Configuration,
            Direction::ClientToServer,
            0x07,
            &body,
            Some(767),
        );
        assert_eq!(insight.name.as_deref(), Some("known_packs"));
        assert_eq!(insight.fields.unwrap()["packs"][0], "minecraft:core 1.21");
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
        push_string(&mut frame, "hello");
        frame.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
        frame.extend_from_slice(&7_i64.to_be_bytes());
        frame.push(0);
        frame.extend_from_slice(&encode_var_i32(0));
        frame.extend_from_slice(&[0, 0, 0]);

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
    fn unrecognised_bodies_report_nothing_rather_than_noise() {
        let insight = play(Direction::ServerToClient, &[0xff, 0x00, 0x13, 0x37, 0x99]);
        assert_eq!(insight.identification, Identification::Unidentified);
        assert!(
            insight.fields.is_none(),
            "an unidentified packet has no fields to show"
        );
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
    }
}
