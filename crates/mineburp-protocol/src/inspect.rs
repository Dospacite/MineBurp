//! On-demand packet inspection.
//!
//! Decoding is deliberately *not* done while capturing: at Minecraft packet
//! rates that work is wasted on rows nobody opens. The desktop app calls into
//! this module only when an operator selects a packet.
//!
//! Identification happens in tiers, strongest first:
//!
//! 1. Handshake, status, and the first login ids have never moved, so the id
//!    alone names the packet.
//! 2. Every other login, configuration, and play id is read through a table
//!    generated for that exact protocol from the release's own data (see
//!    [`crate::registry`]). The table names the packet; the body is then
//!    decoded *as that packet* — from the bundled `minecraft-data` description
//!    where there is one ([`crate::protodef`]), otherwise by the hand-written
//!    decoder for that name. A body that does not match is reported as a
//!    warning on the packet rather than renamed: the table is the stronger
//!    witness, and a mismatch is exactly what a client lying about its
//!    version, a modded server, or a malformed packet looks like.
//! 3. Without a table — an unknown protocol, or passive capture that never saw
//!    a handshake — play and configuration packets are identified from the
//!    shape of their body: each decoder carries a strict validator and names a
//!    packet only when its body parses as that packet and consumes the bytes
//!    it should.
//!
//! A decoder that half-matches reports nothing rather than a plausible lie.

use mineburp_core::{Direction, ProtocolState};
use serde_json::{Map, Value, json};

use crate::{
    common::decode_common_packet,
    nbt::{component_to_text, read_nbt},
    present::{format_millis, interactive_events, plausible_timestamp, present},
    protodef,
    reader::{
        Reader, plausible_altitude, plausible_coordinate, plausible_pitch, plausible_yaw,
        unpack_position,
    },
    registry::PacketRegistry,
    registry_names,
    varint::decode_var_i32,
};

const MAX_TEXT_SUMMARY: usize = 240;
const MAX_STREAM_PACKETS: usize = 512;
const SIGNATURE_BYTES: usize = 256;

/// How confident the inspector is about the name it reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identification {
    /// The state and packet id name the packet: a fixed id, or a table
    /// generated for this exact protocol. Any disagreement from the body is in
    /// [`PacketInsight::warnings`].
    Registry,
    /// The body parsed cleanly as a known packet shape. Used where no table
    /// covers the protocol, so shape is the only evidence.
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
    /// Where the body disagrees with the name its id was given — a version
    /// mismatch, a modded packet, or a malformed one. The name is kept; these
    /// say why it should not be taken on trust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Where the fields came from: `definition` (the bundled description of
    /// this protocol), `decoder` (a hand-written decoder), or `shape`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_by: Option<String>,
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
    let mut insight = decode_packet_body(state, direction, packet_id, body, protocol_version);
    // Registry names are added here rather than in the decoders so that
    // `identify_packet`, which runs while capturing, never pays for them.
    if let (Some(name), Some(fields)) = (insight.name.as_deref(), insight.fields.as_mut()) {
        registry_names::annotate(name, protocol_version, fields);
    }
    insight
}

fn decode_packet_body(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> PacketInsight {
    if let Some(insight) = registry_decode(state, direction, packet_id, body, protocol_version) {
        return insight;
    }
    if let Some(name) = tabulated_name(state, direction, packet_id, protocol_version) {
        return tabulated_decode(state, direction, packet_id, body, protocol_version, name);
    }
    if PacketRegistry::is_tabulated(state, protocol_version) {
        // The protocol has a table and this id is not in it: a modded or
        // malformed packet. Guessing a vanilla name from its shape would be
        // the plausible lie this module refuses to tell.
        return PacketInsight {
            warnings: vec![format!(
                "id {packet_id:#04x} is not a {state:?} packet in protocol {}",
                protocol_version.unwrap_or_default()
            )],
            ..structural_read()
        };
    }
    structure_decode(state, direction, body, protocol_version).unwrap_or_else(structural_read)
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
/// deliberately deferred until a packet is opened. Where a table covers the
/// protocol this is a slice index; shape identification — capped at
/// [`MAX_IDENTIFY_BYTES`] — runs only where none does.
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
        .or_else(|| tabulated_name(state, direction, packet_id, protocol_version))
    {
        return Some(name.to_owned());
    }
    if PacketRegistry::is_tabulated(state, protocol_version) || body.len() > MAX_IDENTIFY_BYTES {
        return None;
    }
    structure_decode(state, direction, body, protocol_version).and_then(|insight| insight.name)
}

/// The name a generated table (or, for login, a version gate) gives an id.
fn tabulated_name(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    protocol_version: Option<i32>,
) -> Option<&'static str> {
    match state {
        ProtocolState::Login => {
            PacketRegistry::login_packet_name(direction, packet_id, protocol_version)
        }
        ProtocolState::Configuration | ProtocolState::Play => {
            PacketRegistry::table_packet_name(state, direction, packet_id, protocol_version)
        }
        _ => None,
    }
}

/// The name the layout walker and the replacement rules key on: the table's
/// name where there is one, otherwise whatever the inspector settles on.
pub(crate) fn resolve_name(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<String> {
    if let Some(name) = PacketRegistry::stable_packet_name(state, direction, packet_id)
        .or_else(|| login_plugin_name(state, direction, packet_id, protocol_version))
        .or_else(|| tabulated_name(state, direction, packet_id, protocol_version))
    {
        return Some(name.to_owned());
    }
    inspect_packet(state, direction, packet_id, body, protocol_version).name
}

// --- identification by state and id (stable across every protocol version) ---

/// Packets whose hand-written decode in [`crate::common`] says more than the
/// description does — a parsed status JSON, a plugin channel's loader.
fn prefers_common_decode(name: &str) -> bool {
    matches!(
        name,
        "handshake"
            | "status_response"
            | "ping_request"
            | "pong_response"
            | "set_compression"
            | "login_plugin_request"
            | "login_plugin_response"
    )
}

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
    let definition = protodef::decode_packet(state, direction, packet_id, body, protocol_version)
        .filter(protodef::DefinitionDecode::is_complete);
    let common_usable = common.error.is_none() && common.fields.is_some();
    let (fields, decoded_by, error) = match definition {
        Some(definition) if !(prefers_common_decode(name) && common_usable) => {
            (present(name, definition.fields), "definition", None)
        }
        _ => (
            common
                .fields
                .map_or_else(|| json!({}), |fields| present(name, fields)),
            "decoder",
            common.error,
        ),
    };
    let channel = common.channel.or_else(|| channel_of(&fields));
    let loader = common.loader.or_else(|| {
        channel
            .as_deref()
            .and_then(loader_for_channel)
            .map(str::to_owned)
    });
    Some(PacketInsight {
        summary: Some(summarize(name, &fields)),
        name: Some(name.to_owned()),
        label: Some(title_case(name)),
        fields: Some(fields),
        channel,
        loader,
        identification: Identification::Registry,
        error,
        stream: Vec::new(),
        warnings: Vec::new(),
        decoded_by: Some(decoded_by.into()),
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

// --- tabulated: the table names the packet, the body is decoded as it ---

fn tabulated_decode(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
    name: &'static str,
) -> PacketInsight {
    let definition = protodef::decode_packet(state, direction, packet_id, body, protocol_version);
    let mut warnings = Vec::new();
    let mut error = None;
    let (fields, decoded_by) = match definition {
        Some(definition) if definition.is_complete() => {
            (present(name, definition.fields), Some("definition"))
        }
        definition => {
            let hand = hand_decode(state, name, body, protocol_version);
            match (hand, definition) {
                (Some(fields), _) => (fields, Some("decoder")),
                (None, Some(definition)) => {
                    let reason = definition.error.unwrap_or_default();
                    warnings.push(format!(
                        "the body does not match `{name}` as protocol {} describes it: {reason}",
                        protocol_version.unwrap_or_default()
                    ));
                    error = Some(reason);
                    (present(name, definition.fields), Some("definition"))
                }
                (None, None) => {
                    if has_hand_decoder(state, name) {
                        warnings.push(format!(
                            "the body does not have the shape of `{name}` this decoder expects"
                        ));
                    }
                    (json!({}), None)
                }
            }
        }
    };
    if !warnings.is_empty()
        && let Some(shape) = structure_decode(state, direction, body, None)
        && let Some(other) = shape.name.filter(|other| other != name)
    {
        warnings.push(format!("the body also reads as `{other}`"));
    }
    let channel = channel_of(&fields);
    let loader = channel.as_deref().and_then(loader_for_channel);
    PacketInsight {
        summary: Some(summarize(name, &fields)),
        name: Some(name.to_owned()),
        label: Some(title_case(name)),
        fields: Some(fields),
        channel,
        loader: loader.map(str::to_owned),
        identification: Identification::Registry,
        error,
        stream: Vec::new(),
        warnings,
        decoded_by: decoded_by.map(str::to_owned),
    }
}

fn channel_of(fields: &Value) -> Option<String> {
    fields
        .get("channel")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The channel and loader a play `custom_payload` frame names, without
/// decoding the rest of its body.
///
/// Capture stores this on every row so the history's channel search and the
/// `channel` filter work for modern plugin messages, whose packet id is only
/// known from the version table. Reading the identifier is one bounded string;
/// the payload itself stays opaque until the packet is opened.
#[must_use]
pub fn plugin_channel(body: &[u8]) -> Option<(String, Option<String>)> {
    let mut reader = Reader::new(body);
    let channel = reader.identifier()?;
    let loader = loader_for_channel(&channel).map(str::to_owned);
    Some((channel, loader))
}

/// The hand-written decoders, keyed by the table name they decode.
///
/// These predate the bundled descriptions and remain the decode for releases
/// without one (26.2, 1.14.2, 1.7) and the fallback when a description fails.
fn hand_decoders(state: ProtocolState, name: &str) -> &'static [Decoder] {
    if state == ProtocolState::Configuration {
        return &[];
    }
    match name {
        "keep_alive" => &[decode_keep_alive_any],
        "chat_message" => &[decode_signed_chat_message],
        "chat_command" => &[decode_signed_chat_command, decode_lone_string],
        "chat_command_signed" => &[decode_signed_chat_command],
        "disconnect"
        | "system_chat"
        | "set_title_text"
        | "set_subtitle_text"
        | "set_action_bar_text"
        | "login_disconnect"
        | "tab_list" => &[decode_text_component_packet],
        "custom_payload" => &[decode_custom_payload],
        "client_information" => &[decode_client_information],
        "set_player_position" => &[decode_player_position],
        "set_player_position_and_rotation" => &[decode_player_position_and_rotation],
        "set_player_rotation" => &[decode_player_rotation],
        "player_action" => &[decode_player_action],
        "use_item_on" => &[decode_use_item_on],
        "click_container" => &[decode_click_container],
        "sign_update" => &[decode_sign_update],
        "interact" => &[decode_interact],
        "command_suggestion" => &[decode_command_suggestion],
        "player_command" => &[decode_player_command],
        "use_item" => &[decode_use_item_any],
        "set_held_item" => &[decode_set_held_item],
        "move_vehicle" => &[decode_move_vehicle],
        "update_time" => &[decode_update_time],
        "player_abilities" => &[decode_player_abilities],
        "set_health" => &[decode_set_health],
        "set_experience" => &[decode_set_experience],
        "container_set_data" => &[decode_container_set_data],
        "game_event" => &[decode_game_event],
        "set_default_spawn_position" => &[decode_default_spawn_position],
        "block_update" => &[decode_block_update],
        "block_destruction" => &[decode_block_destruction],
        "block_event" => &[decode_block_event],
        "level_event" => &[decode_level_event],
        "synchronize_player_position" => &[decode_synchronize_player_position],
        "teleport_entity" => &[decode_teleport_entity],
        "login" => &[decode_login_play],
        "open_screen" => &[decode_open_screen],
        "boss_bar" => &[decode_boss_bar],
        "sound_effect" => &[decode_sound_effect],
        "add_entity" => &[decode_spawn_entity],
        "damage_event" => &[decode_damage_event],
        "entity_effect" => &[decode_entity_effect],
        "remove_entity_effect" => &[decode_remove_entity_effect],
        "scoreboard_objective" => &[decode_scoreboard_objective],
        "update_score" => &[decode_update_score],
        "reset_score" => &[decode_reset_score],
        "combat_death" => &[decode_combat_death],
        "player_info_remove" => &[decode_player_info_remove],
        "add_resource_pack" => &[decode_resource_pack_push],
        "set_entity_motion" => &[decode_set_entity_motion],
        "move_entity_pos" | "move_entity_pos_rot" | "move_entity_rot" => &[decode_move_entity],
        "remove_entities" => &[decode_remove_entities],
        _ => &[],
    }
}

fn has_hand_decoder(state: ProtocolState, name: &str) -> bool {
    !hand_decoders(state, name).is_empty()
        || (state == ProtocolState::Configuration && configuration_fields(name, &[]).is_some())
}

fn hand_decode(
    state: ProtocolState,
    name: &str,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Option<Value> {
    if state == ProtocolState::Configuration {
        return configuration_fields(name, body);
    }
    hand_decoders(state, name)
        .iter()
        .find_map(|decoder| decoder(body, protocol_version))
        .map(|(_, fields)| fields)
}

/// Keep alive where the table already says so: any eight bytes.
fn decode_keep_alive_any(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 8 {
        return None;
    }
    Some(("keep_alive", json!({ "id": Reader::new(body).i64()? })))
}

/// Item use where the table already says so: a small sequence number is no
/// longer ambiguous with a hotbar switch.
fn decode_use_item_any(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let hand = reader.var_i32().filter(|value| (0..=1).contains(value))?;
    let sequence = reader.var_i32().filter(|value| *value >= 0)?;
    if !reader.is_empty() {
        return decode_use_item(body, protocol);
    }
    Some((
        "use_item",
        json!({ "hand": if hand == 0 { "main" } else { "off" }, "sequence": sequence }),
    ))
}

/// Validates a configuration body against the name its id was given.
///
/// Returning `None` means the body does not look like that packet; a name with
/// no validator here also returns `None`, so the bundled description decides.
fn configuration_fields(name: &str, body: &[u8]) -> Option<Value> {
    let mut reader = Reader::new(body);
    let fields = match name {
        "finish_configuration" | "finish_configuration_ack" | "reset_chat" | "clear_dialog" => {
            json!({})
        }
        "keep_alive" => json!({ "id": reader.i64()? }),
        "ping" | "pong" => json!({ "id": reader.i32()? }),
        "plugin_message" => return decode_custom_payload(body, None).map(|(_, fields)| fields),
        "client_information" => {
            return decode_client_information(body, None).map(|(_, fields)| fields);
        }
        "disconnect" => {
            return decode_text_component_packet(body, None).map(|(_, fields)| fields);
        }
        "known_packs" | "select_known_packs" => {
            return decode_known_packs(body, None).map(|(_, fields)| fields);
        }
        "cookie_request" => json!({ "key": reader.identifier()? }),
        "store_cookie" | "cookie_response" => {
            let key = reader.identifier()?;
            // A stored cookie always carries a payload; a response says
            // whether it has one.
            let present = name == "store_cookie" || reader.bool()?;
            let payload = if present {
                Some(reader.byte_array()?)
            } else {
                None
            };
            json!({
                "key": key,
                "payload": payload.map(crate::protodef::to_hex),
                "payload_text": payload.and_then(|bytes| printable_run(bytes, 4)),
            })
        }
        "remove_resource_pack" => {
            // 1.20.3+: an optional pack UUID; absent means "remove all".
            let present = reader.bool()?;
            let id = if present { Some(reader.uuid()?) } else { None };
            json!({ "pack": id.map_or_else(|| "all".to_owned(), |id| id.to_string()) })
        }
        "add_resource_pack" => {
            return decode_resource_pack_push(body, None).map(|(_, fields)| fields);
        }
        "resource_pack_response" => {
            // 1.20.3 put a pack UUID in front of the result.
            if body.len() == 17 {
                reader.take(16)?;
            }
            let result = reader.var_i32().filter(|value| (0..=6).contains(value))?;
            json!({ "result": resource_pack_result(result) })
        }
        "transfer" => {
            let host = reader.string(255)?;
            let port = reader
                .var_i32()
                .filter(|value| (0..=65_535).contains(value))?;
            json!({ "host": host, "port": port })
        }
        _ => return None,
    };
    reader.is_empty().then_some(fields)
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
    decode_click_container,
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
    decode_container_set_data,
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
    decode_boss_bar,
    decode_sound_effect,
    decode_spawn_entity,
    decode_damage_event,
    decode_entity_effect,
    decode_remove_entity_effect,
    decode_scoreboard_objective,
    decode_update_score,
    decode_reset_score,
    decode_combat_death,
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
        let channel = channel_of(&fields);
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
            warnings: Vec::new(),
            decoded_by: Some("shape".into()),
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
    let events = interactive_events(&component);
    if !events.is_empty() {
        fields.insert("interactive_events".into(), Value::Array(events));
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

/// Boss bar creation and the four updates a server can send for one.
///
/// The `UUID` plus an action enum of at most five values is already narrow
/// evidence, and each action's payload has its own bounds, so this shape is
/// hard to reach by accident.
fn decode_boss_bar(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let uuid = reader.uuid()?;
    let action = reader.var_i32().filter(|value| (0..=5).contains(value))?;
    let mut fields = Map::new();
    fields.insert("uuid".into(), Value::String(uuid.to_string()));
    match action {
        // Add: title, health, colour, overlay, and flags.
        0 => {
            let (component, consumed) = read_text_component(reader.rest())?;
            reader.take(consumed)?;
            let title = component_to_text(&component);
            if title.is_empty() {
                return None;
            }
            let health = reader
                .f32()
                .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))?;
            let color = reader.var_i32().filter(|value| (0..=5).contains(value))?;
            let overlay = reader.var_i32().filter(|value| (0..=3).contains(value))?;
            let flags = reader.u8().filter(|value| *value <= 0x07)?;
            fields.insert("action".into(), Value::String("add".into()));
            fields.insert("title".into(), Value::String(title));
            fields.insert("health".into(), json!(health));
            fields.insert("color".into(), json!(color));
            fields.insert("overlay".into(), json!(overlay));
            fields.insert("flags".into(), json!(format!("0x{flags:02x}")));
        }
        1 => {
            let health = reader
                .f32()
                .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))?;
            fields.insert("action".into(), Value::String("update_health".into()));
            fields.insert("health".into(), json!(health));
        }
        2 => {
            let color = reader.var_i32().filter(|value| (0..=5).contains(value))?;
            fields.insert("action".into(), Value::String("update_color".into()));
            fields.insert("color".into(), json!(color));
        }
        3 => {
            let overlay = reader.var_i32().filter(|value| (0..=3).contains(value))?;
            fields.insert("action".into(), Value::String("update_style".into()));
            fields.insert("overlay".into(), json!(overlay));
        }
        4 => {
            let flags = reader.u8().filter(|value| *value <= 0x07)?;
            fields.insert("action".into(), Value::String("update_flags".into()));
            fields.insert("flags".into(), json!(format!("0x{flags:02x}")));
        }
        _ => {
            fields.insert("action".into(), Value::String("remove".into()));
        }
    }
    reader
        .is_empty()
        .then_some(("boss_bar", Value::Object(fields)))
}

/// A sound played at a world position. The packed position, bounded category,
/// and volume/pitch ranges together make this shape specific.
///
/// Its sibling `stop_sound` is deliberately not decoded: an entity id followed
/// by an identifier is byte-for-byte both a stopped sound and a worn-off
/// potion effect, so naming either would be a coin flip the module refuses.
fn decode_sound_effect(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let sound = reader
        .var_i32()
        .filter(|value| (0..=2_048).contains(value))?;
    let category = reader.var_i32().filter(|value| (0..=8).contains(value))?;
    let position = unpack_position(reader.i64()?)?;
    let volume = reader
        .f32()
        .filter(|value| value.is_finite() && (0.0..=64.0).contains(value))?;
    let pitch = reader
        .f32()
        .filter(|value| value.is_finite() && (0.5..=4.0).contains(value))?;
    let _seed = reader.i64()?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "sound_effect",
        json!({
            "sound_id": sound,
            "category": sound_category(category),
            "position": format_position(position),
            "volume": volume,
            "pitch": pitch,
        }),
    ))
}

fn sound_category(value: i32) -> &'static str {
    match value {
        0 => "master",
        1 => "music",
        2 => "record",
        3 => "weather",
        4 => "block",
        5 => "hostile",
        6 => "neutral",
        7 => "player",
        _ => "ambient",
    }
}

/// An entity appearing in view. The fixed run of coordinates, angles, and
/// velocity around two small ids is strong evidence.
fn decode_spawn_entity(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let uuid = reader.uuid()?;
    let kind = reader
        .var_i32()
        .filter(|value| (0..=1_024).contains(value))?;
    let (x, y, z) = read_location(&mut reader)?;
    let pitch = f64::from(reader.u8()?) * 360.0 / 256.0;
    let yaw = f64::from(reader.u8()?) * 360.0 / 256.0;
    let data = reader.var_i32()?;
    let velocity: Vec<f64> = (0..3)
        .map(|_| reader.i16().map(|value| f64::from(value) / 8_000.0))
        .collect::<Option<Vec<_>>>()?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "add_entity",
        json!({
            "entity_id": entity_id,
            "uuid": uuid.to_string(),
            "type": kind,
            "x": x, "y": y, "z": z,
            "yaw": yaw, "pitch": pitch,
            "data": data,
            "velocity": format!("{:.3}, {:.3}, {:.3}", velocity[0], velocity[1], velocity[2]),
        }),
    ))
}

/// The hurt animation and its cause, added in 1.19.4.
fn decode_damage_event(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    protocol.filter(|version| *version >= 763)?;
    let mut reader = Reader::new(body);
    let kind = reader.var_i32().filter(|value| (0..=64).contains(value))?;
    let mut fields = Map::new();
    fields.insert("type".into(), json!(kind));
    for key in ["source_entity", "direct_entity"] {
        if reader.bool()? {
            let id = reader.var_i32().filter(|value| *value >= 0)?;
            fields.insert(key.into(), json!(id));
        }
    }
    if reader.bool()? {
        let (x, y, z) = read_location(&mut reader)?;
        fields.insert(
            "position".into(),
            Value::String(format!("{x:.2}, {y:.2}, {z:.2}")),
        );
    }
    if !reader.is_empty() {
        return None;
    }
    Some(("damage_event", Value::Object(fields)))
}

/// Furnace arrows, brewing stands, and the other progress bars a server
/// pushes as window properties.
///
/// This packet and `game_event` are both five bytes, so this decoder runs
/// first and carries the stricter evidence: a real property total is a tick
/// budget above zero and no larger than about a thousand, which no finite
/// game-event float satisfies — a gamemode float has a zero low half, and a
/// rain level's high word already exceeds any such total.
fn decode_container_set_data(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    if body.len() != 5 {
        return None;
    }
    let mut reader = Reader::new(body);
    let window = reader.u8().filter(|value| *value <= 63)?;
    let progress = reader.i16().filter(|value| (0..=1_000).contains(value))?;
    let total = reader.i16().filter(|value| (1..=1_000).contains(value))?;
    if progress > total {
        return None;
    }
    Some((
        "container_set_data",
        json!({ "window_id": window, "progress": progress, "total": total }),
    ))
}

/// A status effect applied to an entity, in the 1.20.2 field order.
fn decode_entity_effect(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let effect = reader.var_i32().filter(|value| (1..=40).contains(value))?;
    let amplifier = reader.var_i32().filter(|value| (0..=256).contains(value))?;
    let duration = reader.var_i32()?;
    let flags = reader.u8().filter(|value| *value <= 0x07)?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "entity_effect",
        json!({
            "entity_id": entity_id,
            "effect": effect,
            "amplifier": amplifier,
            "duration": if duration < 0 { "infinite".to_owned() } else { duration.to_string() },
            "ambient": flags & 0x01 != 0,
            "particles": flags & 0x02 != 0,
            "icon": flags & 0x04 != 0,
        }),
    ))
}

/// A potion effect wearing off.
fn decode_remove_entity_effect(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let entity_id = reader.var_i32().filter(|value| *value >= 0)?;
    let effect = reader.identifier()?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "remove_entity_effect",
        json!({ "entity_id": entity_id, "effect": effect }),
    ))
}

/// Creating or rewriting a scoreboard objective.
///
/// The objective-name budget of sixteen characters over a restricted alphabet,
/// followed by a mode byte and — when present — a title component, is what
/// separates this from any other string-led packet.
fn decode_scoreboard_objective(
    body: &[u8],
    _protocol: Option<i32>,
) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let objective = read_objective_name(&mut reader)?;
    let mode = reader.u8().filter(|value| *value <= 2)?;
    let mut fields = Map::new();
    fields.insert("objective".into(), Value::String(objective));
    if mode == 1 {
        fields.insert("action".into(), Value::String("remove".into()));
    } else {
        let (component, consumed) = read_text_component(reader.rest())?;
        reader.take(consumed)?;
        let title = component_to_text(&component);
        if title.is_empty() {
            return None;
        }
        let criterion = reader.var_i32().filter(|value| (0..=2).contains(value))?;
        fields.insert(
            "action".into(),
            Value::String(if mode == 0 {
                "create".into()
            } else {
                "update".into()
            }),
        );
        fields.insert("title".into(), Value::String(title));
        fields.insert(
            "render_type".into(),
            Value::String(match criterion {
                0 => "integer".into(),
                1 => "hearts".into(),
                _ => "blank".into(),
            }),
        );
        read_optional_number_format(&mut reader, &mut fields)?;
    }
    reader
        .is_empty()
        .then_some(("scoreboard_objective", Value::Object(fields)))
}

fn read_objective_name(reader: &mut Reader<'_>) -> Option<String> {
    let name = reader.string(16)?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-+.".contains(&byte)))
    .then_some(name)
}

/// The optional display format added to score packets in 1.20.3.
///
/// Older releases stop after the render type, so a failed strict read simply
/// rewinds and leaves nothing behind rather than rejecting the packet.
fn read_optional_number_format(
    reader: &mut Reader<'_>,
    fields: &mut Map<String, Value>,
) -> Option<()> {
    let checkpoint = reader.clone();
    if !matches!(reader.bool(), Some(true)) {
        *reader = checkpoint;
        return Some(());
    }
    match reader.var_i32() {
        Some(0) => {
            fields.insert("number_format".into(), Value::String("blank".into()));
            Some(())
        }
        Some(1) => {
            let (component, consumed) = read_text_component(reader.rest())?;
            reader.take(consumed)?;
            fields.insert(
                "number_format".into(),
                Value::String(component_to_text(&component)),
            );
            Some(())
        }
        Some(2) => {
            let text = reader.string(256)?;
            fields.insert("number_format".into(), Value::String(text));
            Some(())
        }
        _ => {
            // A format kind this decoder does not know rewinds to the mark:
            // the packet is still named from what came before it.
            *reader = checkpoint;
            Some(())
        }
    }
}

/// Setting a player's score on an objective, 1.20.3 shape.
fn decode_update_score(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    protocol.filter(|version| *version >= 764)?;
    let mut reader = Reader::new(body);
    let entity = reader.string(40)?;
    let objective = read_objective_name(&mut reader)?;
    let score = reader.var_i32().filter(|value| *value >= 0)?;
    let mut fields = Map::new();
    fields.insert("entity".into(), Value::String(entity));
    fields.insert("objective".into(), Value::String(objective));
    fields.insert("score".into(), json!(score));
    if matches!(reader.bool(), Some(true)) {
        let (component, consumed) = read_text_component(reader.rest())?;
        reader.take(consumed)?;
        fields.insert(
            "display_name".into(),
            Value::String(component_to_text(&component)),
        );
    }
    read_optional_number_format(&mut reader, &mut fields)?;
    reader
        .is_empty()
        .then_some(("update_score", Value::Object(fields)))
}

/// Clearing a player's score on an objective: exactly two names.
fn decode_reset_score(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    protocol.filter(|version| *version >= 764)?;
    let mut reader = Reader::new(body);
    let entity = reader.string(40)?;
    let objective = read_objective_name(&mut reader)?;
    if !reader.is_empty() {
        return None;
    }
    Some((
        "reset_score",
        json!({ "entity": entity, "objective": objective }),
    ))
}

/// A player death announced with its kill message: an entity id followed by
/// nothing but a text component.
fn decode_combat_death(body: &[u8], _protocol: Option<i32>) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let player_id = reader.var_i32().filter(|value| *value >= 0)?;
    let rest = reader.rest();
    let (component, consumed) = read_text_component(rest)?;
    if consumed != rest.len() {
        return None;
    }
    let message = component_to_text(&component);
    if message.is_empty() {
        return None;
    }
    Some((
        "combat_death",
        json!({ "player_id": player_id, "message": message }),
    ))
}

/// Clicking a container slot.
///
/// The layout has moved several times: 1.17.1 put a state id after the window
/// id, 1.20.5 replaced item NBT with typed components, 1.21.2 widened the
/// window id to a `VarInt`, and 1.21.5 sends *hashed* stacks — item id, count,
/// and component hashes — which can be walked without a registry. A modern
/// stack carrying real components cannot be walked without one, so between
/// 1.20.5 and 1.21.4 only clicks with empty stacks are named; everything else
/// stays raw rather than half-read.
fn decode_click_container(body: &[u8], protocol: Option<i32>) -> Option<(&'static str, Value)> {
    match protocol {
        Some(version) => click_container_as(body, version),
        // Without a version, try the layouts newest first; each consumes the
        // body exactly or not at all.
        None => [770, 768, 766, 764, 756]
            .into_iter()
            .find_map(|version| click_container_as(body, version)),
    }
}

fn click_container_as(body: &[u8], version: i32) -> Option<(&'static str, Value)> {
    let mut reader = Reader::new(body);
    let window = if version >= 768 {
        reader.var_i32().filter(|value| (0..=255).contains(value))?
    } else {
        i32::from(reader.u8()?)
    };
    let state_id = if version >= 756 {
        Some(reader.var_i32().filter(|value| *value >= 0)?)
    } else {
        None
    };
    let slot = reader.i16().filter(|value| (-1000..=999).contains(value))?;
    let button = reader.u8().filter(|value| *value <= 40)?;
    let mode = reader.var_i32().filter(|value| (0..=6).contains(value))?;
    let count = reader.counted(128)?;
    let mut changed = Vec::with_capacity(count);
    for _ in 0..count {
        let changed_slot = reader.i16().filter(|value| (-1000..=999).contains(value))?;
        let item = read_click_item(&mut reader, version)?;
        changed.push(json!({ "slot": changed_slot, "item": item }));
    }
    let carried = read_click_item(&mut reader, version)?;
    if !reader.is_empty() {
        return None;
    }
    let mut fields = Map::new();
    fields.insert("window_id".into(), json!(window));
    if let Some(state_id) = state_id {
        fields.insert("state_id".into(), json!(state_id));
    }
    fields.insert("slot".into(), json!(slot));
    fields.insert("button".into(), json!(button));
    fields.insert("mode".into(), json!(mode));
    fields.insert("changed_slots".into(), Value::Array(changed));
    fields.insert("carried_item".into(), carried);
    Some(("click_container", Value::Object(fields)))
}

fn read_click_item(reader: &mut Reader<'_>, version: i32) -> Option<Value> {
    if version >= 770 {
        decode_hashed_item(reader)
    } else if version >= 766 {
        decode_cursor_item_modern(reader)
    } else {
        decode_cursor_item_legacy(reader)
    }
}

/// A 1.21.5+ hashed stack: presence, item id, count, then the added
/// components as (type, CRC32C) pairs and the removed ones as types.
fn decode_hashed_item(reader: &mut Reader<'_>) -> Option<Value> {
    if !reader.bool()? {
        return Some(Value::Null);
    }
    let id = reader.var_i32().filter(|value| *value >= 0)?;
    let count = reader.var_i32().filter(|value| (1..=99).contains(value))?;
    let added = reader.counted(256)?;
    let mut hashes = Vec::with_capacity(added);
    for _ in 0..added {
        let kind = reader.var_i32().filter(|value| *value >= 0)?;
        let hash = reader.i32()?;
        hashes.push(json!({ "type": kind, "hash": format!("{:08x}", hash.cast_unsigned()) }));
    }
    let removed = reader.counted(256)?;
    let mut removals = Vec::with_capacity(removed);
    for _ in 0..removed {
        removals.push(json!(reader.var_i32().filter(|value| *value >= 0)?));
    }
    Some(json!({
        "id": id,
        "count": count,
        "component_hashes": hashes,
        "removed_components": removals,
    }))
}

/// A 1.20.5–1.21.4 stack: a count, and nothing else when it is empty. A
/// non-empty stack needs the component registry to walk; refusing keeps the
/// decoder honest instead of naming a partial read.
fn decode_cursor_item_modern(reader: &mut Reader<'_>) -> Option<Value> {
    let count = reader.var_i32().filter(|value| (0..=99).contains(value))?;
    if count == 0 { Some(Value::Null) } else { None }
}

/// A stack before 1.20.5: presence, id, count, and NBT (a lone `TAG_End` when
/// the stack carries none).
fn decode_cursor_item_legacy(reader: &mut Reader<'_>) -> Option<Value> {
    if !reader.bool()? {
        return Some(Value::Null);
    }
    let id = reader
        .var_i32()
        .filter(|value| (0..=4_000).contains(value))?;
    let count = reader.u8().filter(|value| (1..=64).contains(value))?;
    let rest = reader.rest();
    let consumed = if rest.first() == Some(&0) {
        1
    } else {
        read_nbt(rest).ok()?.1
    };
    reader.take(consumed)?;
    Some(json!({ "id": id, "count": count }))
}

// --- raw transport payloads ---

/// The `GameSpy4` query protocol Java servers answer over UDP: LAN discovery,
/// server-list pings, and the external query listener.
///
/// Every datagram starts with the `0xFEFD` magic, an opcode, and a session id,
/// which is specific enough evidence to name even though the statistics
/// payload's chunked key/value layout is only summarised, not walked.
fn decode_query_protocol(payload: &[u8]) -> Option<PacketInsight> {
    if payload.len() < 5 || payload.first()? != &0xFE || payload.get(1)? != &0xFD {
        return None;
    }
    let opcode = *payload.get(2)?;
    let session = i32::from_be_bytes(payload.get(3..7)?.try_into().ok()?);
    let (name, summary_tail) = match opcode {
        9 => {
            // A handshake request ends in padding; the reply carries the
            // challenge token as trailing text.
            ("query_handshake", printable_run(&payload[7..], 1))
        }
        0 => {
            // A stats request carries an 11-byte payload; replies carry the
            // chunked key/value sections.
            ("query_stats", printable_run(&payload[7..], 1))
        }
        _ => return None,
    };
    Some(PacketInsight {
        name: Some(name.into()),
        label: Some(title_case(name)),
        summary: Some(format!("{name}: session {session}")),
        fields: Some(json!({
            "session": session,
            "payload": summary_tail.unwrap_or_default(),
        })),
        identification: Identification::Structure,
        ..PacketInsight::default()
    })
}

/// Splits a passively captured TCP payload into Minecraft frames when it looks
/// like plaintext protocol traffic. Encrypted or mid-stream payloads simply
/// report the raw frame instead.
fn inspect_transport_payload(
    direction: Direction,
    payload: &[u8],
    protocol_version: Option<i32>,
) -> PacketInsight {
    if let Some(query) = decode_query_protocol(payload) {
        return query;
    }
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
        // Shape only: a passively captured frame may belong to any state, so
        // reading its id through the play table would name a login packet as
        // whatever play packet shares its id.
        let inner = structure_decode(
            ProtocolState::Play,
            direction,
            &frame[id_prefix..],
            protocol_version,
        )
        .unwrap_or_else(structural_read);
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
        "plain_message",
        "command",
        "content_text",
        "reason_text",
        "text_rendered",
        "title_text",
        "header_text",
        "text",
        "title",
        "objective",
        "value",
        "channel",
        "server_address",
        "host",
        "username",
        "key",
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
    let clipped: String = value.chars().take(limit).map(visible_char).collect();
    if value.chars().count() <= limit {
        clipped
    } else {
        format!("{clipped}…")
    }
}

/// Line breaks become spaces; other control characters become their Unicode
/// control picture, so a Forge handshake reads `host␀FORGE` rather than
/// `hostFORGE` with an invisible NUL.
fn visible_char(character: char) -> char {
    match character {
        '\n' | '\r' => ' ',
        '\u{7f}' => '\u{2421}',
        control if u32::from(control) < 0x20 => {
            char::from_u32(0x2400 + u32::from(control)).unwrap_or(' ')
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_var_i32;

    fn push_string(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&encode_var_i32(i32::try_from(value.len()).unwrap()));
        output.extend_from_slice(value.as_bytes());
    }

    /// The shape tier on its own, as it runs for a release with no table: the
    /// decoders still see the protocol, so version-gated layouts are tested.
    fn play(direction: Direction, body: &[u8]) -> PacketInsight {
        structure_decode(ProtocolState::Play, direction, body, Some(767))
            .unwrap_or_else(structural_read)
    }

    fn play_untabulated(direction: Direction, body: &[u8]) -> PacketInsight {
        structure_decode(ProtocolState::Play, direction, body, Some(763))
            .unwrap_or_else(structural_read)
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
    fn reads_the_channel_from_a_modern_custom_payload_preamble() {
        let mut body = Vec::new();
        push_string(&mut body, "mineburp:inventory");
        body.extend_from_slice(&[2, 0, 0, 0, 1]);

        let (channel, loader) = plugin_channel(&body).expect("identifier");
        assert_eq!(channel, "mineburp:inventory");
        assert_eq!(loader, None);
        assert!(plugin_channel(&[0x00]).is_none());
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
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ClientToServer,
            &body,
            Some(768),
        )
        .unwrap_or_else(structural_read);
        assert_eq!(insight.name.as_deref(), Some("use_item_on"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["position"], "12, 70, -34");
        assert_eq!(fields["hit_world_border"], false);

        let mut older = classic;
        older.extend_from_slice(&encode_var_i32(300));
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ClientToServer,
            &older,
            Some(767),
        )
        .unwrap_or_else(structural_read);
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

    fn nbt_text(text: &str) -> Vec<u8> {
        // Network NBT: a root compound with no name, one string field, an end
        // tag.
        let mut bytes = vec![0x0a, 0x08];
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(b"text");
        bytes.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
        bytes.push(0x00);
        bytes
    }

    #[test]
    fn decodes_boss_bar_actions() {
        let uuid = [0x11_u8; 16];

        // Add: title, health, colour, overlay, flags.
        let mut body = uuid.to_vec();
        body.extend_from_slice(&encode_var_i32(0));
        body.extend_from_slice(&nbt_text("Ender Dragon"));
        body.extend_from_slice(&0.75_f32.to_be_bytes());
        body.extend_from_slice(&encode_var_i32(3));
        body.extend_from_slice(&encode_var_i32(0));
        body.push(0x01);
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("boss_bar"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["action"], "add");
        assert_eq!(fields["title"], "Ender Dragon");
        assert_eq!(fields["health"], 0.75);

        // Health update, then removal.
        let mut body = uuid.to_vec();
        body.extend_from_slice(&encode_var_i32(1));
        body.extend_from_slice(&0.5_f32.to_be_bytes());
        assert_eq!(
            play(Direction::ServerToClient, &body).fields.unwrap()["health"],
            0.5
        );

        let mut body = uuid.to_vec();
        body.extend_from_slice(&encode_var_i32(5));
        let fields = play(Direction::ServerToClient, &body).fields.unwrap();
        assert_eq!(fields["action"], "remove");

        // An out-of-range action leaves the packet unnamed.
        let mut body = uuid.to_vec();
        body.extend_from_slice(&encode_var_i32(9));
        assert_eq!(
            play_untabulated(Direction::ServerToClient, &body).identification,
            Identification::Unidentified
        );
    }

    #[test]
    fn decodes_a_sound_effect() {
        let mut body = encode_var_i32(42).to_vec();
        body.extend_from_slice(&encode_var_i32(4)); // block category
        body.extend_from_slice(&packed_position(-12, 70, 300));
        body.extend_from_slice(&0.8_f32.to_be_bytes());
        body.extend_from_slice(&1.25_f32.to_be_bytes());
        body.extend_from_slice(&9_i64.to_be_bytes());
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("sound_effect"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["category"], "block");
        assert_eq!(fields["position"], "-12, 70, 300");
        assert_eq!(fields["pitch"], 1.25);
    }

    #[test]
    fn decodes_an_entity_spawning() {
        let mut body = encode_var_i32(4_812).to_vec();
        body.extend_from_slice(&[0x22_u8; 16]);
        body.extend_from_slice(&encode_var_i32(95)); // creeper-ish type id
        for value in [12.5_f64, 64.0, -30.25] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.push(128); // pitch
        body.push(32); // yaw
        body.extend_from_slice(&encode_var_i32(0));
        for delta in [0_i16, -800, 1_600] {
            body.extend_from_slice(&delta.to_be_bytes());
        }
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("add_entity"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["entity_id"], 4_812);
        assert_eq!(fields["type"], 95);
        assert_eq!(fields["y"], 64.0);
    }

    #[test]
    fn decodes_damage_and_death_packets() {
        // Damage from a known attacker at a reported position.
        let mut body = encode_var_i32(5).to_vec(); // damage type
        body.push(1);
        body.extend_from_slice(&encode_var_i32(4_812));
        body.push(0);
        body.push(1); // has position
        for value in [8.5_f64, 64.0, -19.25] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ServerToClient,
            &body,
            Some(767),
        )
        .unwrap_or_else(structural_read);
        assert_eq!(insight.name.as_deref(), Some("damage_event"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["source_entity"], 4_812);

        // The same shape on an older release is not this packet.
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ServerToClient,
            &body,
            Some(758),
        )
        .unwrap_or_else(structural_read);
        assert_ne!(insight.name.as_deref(), Some("damage_event"));

        // Death: entity id plus nothing but a component.
        let mut body = encode_var_i32(1).to_vec();
        body.extend_from_slice(&nbt_text("Player fell from a high place"));
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("combat_death"));
        assert!(insight.summary.unwrap().contains("fell"));
    }

    #[test]
    fn decodes_window_properties_but_not_game_events() {
        // A furnace progress bar: window 2, progress 40 of 100.
        let mut body = vec![2_u8];
        body.extend_from_slice(&40_i16.to_be_bytes());
        body.extend_from_slice(&100_i16.to_be_bytes());
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("container_set_data"));

        // A game event (change gamemode to 3) parses as a zero total here and
        // must stay with its own decoder.
        let mut body = vec![3_u8];
        body.extend_from_slice(&3.0_f32.to_be_bytes());
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("game_event"));
    }

    #[test]
    fn decodes_status_effects() {
        let mut body = encode_var_i32(120).to_vec();
        body.extend_from_slice(&encode_var_i32(10)); // speed
        body.extend_from_slice(&encode_var_i32(1)); // amplifier
        body.extend_from_slice(&encode_var_i32(-1)); // infinite
        body.push(0b101);
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("entity_effect"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["duration"], "infinite");
        assert_eq!(fields["particles"], false);

        // Wearing off: entity id plus a namespaced effect.
        let mut body = encode_var_i32(120).to_vec();
        push_string(&mut body, "minecraft:speed");
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("remove_entity_effect"));
    }

    #[test]
    fn decodes_scoreboard_packets() {
        // Create an objective with an integer render type.
        let mut body = push_objective_header("kills", 0);
        body.extend_from_slice(&encode_var_i32(0));
        let insight = play(Direction::ServerToClient, &body);
        assert_eq!(insight.name.as_deref(), Some("scoreboard_objective"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["action"], "create");
        assert_eq!(fields["title"], "Kills!");

        // Remove it: name and mode only.
        let mut body = Vec::new();
        push_string(&mut body, "kills");
        body.push(1);
        assert_eq!(
            play(Direction::ServerToClient, &body).name.as_deref(),
            Some("scoreboard_objective")
        );

        // Set a score on 1.20.3+; on older releases the same bytes are not
        // this packet because the shape did not exist yet.
        let mut body = push_score_header(764);
        body.extend_from_slice(&encode_var_i32(15));
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ServerToClient,
            &body,
            Some(764),
        )
        .unwrap_or_else(structural_read);
        assert_eq!(insight.name.as_deref(), Some("update_score"));
        assert_eq!(insight.fields.unwrap()["score"], 15);
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ServerToClient,
            &body,
            Some(758),
        )
        .unwrap_or_else(structural_read);
        assert_ne!(insight.name.as_deref(), Some("update_score"));

        // Reset that score: exactly two names.
        let body = push_score_header(764);
        let insight = structure_decode(
            ProtocolState::Play,
            Direction::ServerToClient,
            &body,
            Some(764),
        )
        .unwrap_or_else(structural_read);
        assert_eq!(insight.name.as_deref(), Some("reset_score"));
    }

    fn push_objective_header(name: &str, mode: u8) -> Vec<u8> {
        let mut body = Vec::new();
        push_string(&mut body, name);
        body.push(mode);
        if mode != 1 {
            body.extend_from_slice(&nbt_text("Kills!"));
        }
        body
    }

    fn push_score_header(protocol: i32) -> Vec<u8> {
        let _ = protocol;
        let mut body = Vec::new();
        push_string(&mut body, "MineBurpTester");
        body.extend_from_slice(&encode_var_i32(5));
        body.extend_from_slice(b"kills");
        body
    }

    fn click_header(window_as_varint: bool) -> Vec<u8> {
        // Window 1, state id 5, slot 45, button 0, mode 0.
        let mut body = if window_as_varint {
            encode_var_i32(1).to_vec()
        } else {
            vec![1]
        };
        body.extend_from_slice(&encode_var_i32(5));
        body.extend_from_slice(&45_i16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&encode_var_i32(0));
        body
    }

    fn shape(direction: Direction, body: &[u8], protocol: i32) -> PacketInsight {
        structure_decode(ProtocolState::Play, direction, body, Some(protocol))
            .unwrap_or_else(structural_read)
    }

    #[test]
    fn decodes_container_clicks_in_every_layout() {
        // 1.20.5–1.21.1: window id, state id, …, an empty component stack.
        let mut body = click_header(false);
        body.extend_from_slice(&encode_var_i32(0)); // no changed slots
        body.extend_from_slice(&encode_var_i32(0)); // empty carried stack
        let insight = shape(Direction::ClientToServer, &body, 767);
        assert_eq!(insight.name.as_deref(), Some("click_container"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["window_id"], 1);
        assert_eq!(fields["state_id"], 5);
        assert_eq!(fields["slot"], 45);
        assert_eq!(fields["changed_slots"], json!([]));
        assert_eq!(fields["carried_item"], Value::Null);

        // Before 1.20.5: a presence flag for the carried stack.
        let mut legacy = click_header(false);
        legacy.extend_from_slice(&encode_var_i32(0));
        legacy.push(0);
        let insight = shape(Direction::ClientToServer, &legacy, 758);
        assert_eq!(insight.name.as_deref(), Some("click_container"));

        // 1.21.5: a VarInt window id and hashed stacks, which are walkable.
        let mut hashed = click_header(true);
        hashed.extend_from_slice(&encode_var_i32(1)); // one changed slot
        hashed.extend_from_slice(&36_i16.to_be_bytes());
        hashed.push(1); // present
        hashed.extend_from_slice(&encode_var_i32(812)); // item id
        hashed.extend_from_slice(&encode_var_i32(3)); // count
        hashed.extend_from_slice(&encode_var_i32(1)); // one component hash
        hashed.extend_from_slice(&encode_var_i32(9));
        hashed.extend_from_slice(&0x1234_5678_i32.to_be_bytes());
        hashed.extend_from_slice(&encode_var_i32(0)); // none removed
        hashed.push(0); // carried stack absent
        let insight = shape(Direction::ClientToServer, &hashed, 770);
        assert_eq!(insight.name.as_deref(), Some("click_container"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["changed_slots"][0]["slot"], 36);
        assert_eq!(fields["changed_slots"][0]["item"]["id"], 812);
        assert_eq!(
            fields["changed_slots"][0]["item"]["component_hashes"][0]["hash"],
            "12345678"
        );
    }

    #[test]
    fn an_eight_byte_body_is_not_automatically_a_keep_alive() {
        // A packed chunk-position long: too large to be a counter and far from
        // any plausible clock, so it must not be named for its length alone.
        let insight = play_untabulated(
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
        // say which one this is — and the description then decodes it.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &[0x00],
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("swing"));
        assert_eq!(insight.identification, Identification::Registry);
        assert_eq!(insight.decoded_by.as_deref(), Some("definition"));
        assert_eq!(insight.fields.unwrap()["hand"], 0);
        assert!(insight.warnings.is_empty());

        // The same id on a version with no generated table stays unnamed rather
        // than borrowing a neighbouring release's numbering.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &[0x00],
            Some(485),
        );
        assert_eq!(insight.identification, Identification::Unidentified);
    }

    #[test]
    fn a_body_that_contradicts_its_table_name_is_flagged_rather_than_renamed() {
        let mut body = Vec::new();
        body.extend_from_slice(&8.5_f64.to_be_bytes());
        body.extend_from_slice(&64.0_f64.to_be_bytes());
        body.extend_from_slice(&(-19.25_f64).to_be_bytes());
        body.push(1);

        // Sent under the id the table calls an arm swing: the table is the
        // stronger witness, so the name stays, and the mismatch — including
        // what the bytes look like instead — is reported.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            SWING,
            &body,
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("swing"));
        assert_eq!(insight.identification, Identification::Registry);
        assert!(insight.error.is_some());
        assert!(
            insight
                .warnings
                .iter()
                .any(|warning| warning.contains("set_player_position")),
            "{:?}",
            insight.warnings
        );

        // Under the id the table agrees with, the same bytes decode cleanly.
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            MOVE_PLAYER_POS,
            &body,
            Some(769),
        );
        assert_eq!(insight.name.as_deref(), Some("set_player_position"));
        assert_eq!(insight.identification, Identification::Registry);
        assert!(insight.warnings.is_empty());
        assert_eq!(insight.fields.unwrap()["y"], 64.0);
    }

    #[test]
    fn an_id_missing_from_a_table_is_not_guessed_from_its_shape() {
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ClientToServer,
            0x7f,
            &[0x00],
            Some(769),
        );
        assert_eq!(insight.name, None);
        assert_eq!(insight.warnings.len(), 1);
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
                Some(485)
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

        // The same id in 1.20.4 is ping, which takes four bytes. The table
        // still names it ping; the eight-byte body is flagged, along with the
        // packet it reads as instead.
        let insight = inspect_packet(
            ProtocolState::Configuration,
            Direction::ServerToClient,
            0x04,
            &7_i64.to_be_bytes(),
            Some(765),
        );
        assert_eq!(insight.name.as_deref(), Some("ping"));
        assert_eq!(insight.identification, Identification::Registry);
        assert!(
            insight
                .warnings
                .iter()
                .any(|warning| warning.contains("keep_alive")),
            "{:?}",
            insight.warnings
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
        assert_eq!(insight.decoded_by.as_deref(), Some("definition"));
        assert_eq!(
            insight.fields.unwrap()["packs"][0],
            json!({ "namespace": "minecraft", "id": "core", "version": "1.21" })
        );
        // The hand-written shape decoder, used where no description exists.
        assert_eq!(
            decode_known_packs(&body, None).unwrap().1["packs"][0],
            "minecraft:core 1.21"
        );
    }

    // --- table-first decoding of real bodies for 1.21.11 (protocol 774) ---

    const MODERN: i32 = 774;

    fn id_of(state: ProtocolState, direction: Direction, name: &str) -> i32 {
        PacketRegistry::packet_id(state, direction, name, Some(MODERN))
            .unwrap_or_else(|| panic!("{name} is in the {MODERN} table"))
    }

    fn nbt_string(output: &mut Vec<u8>, name: &str, value: &str) {
        output.push(0x08);
        output.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }

    fn textures_property() -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(
            r#"{"profileName":"Notch","textures":{"SKIN":{"url":"http://textures.minecraft.net/texture/abc"}}}"#,
        )
    }

    #[test]
    fn login_success_properties_and_skins_are_decoded() {
        let mut body = vec![0x11; 16];
        push_string(&mut body, "Notch");
        body.extend_from_slice(&encode_var_i32(1));
        push_string(&mut body, "textures");
        push_string(&mut body, &textures_property());
        body.push(0); // no signature
        let insight = inspect_packet(
            ProtocolState::Login,
            Direction::ServerToClient,
            2,
            &body,
            Some(MODERN),
        );
        assert_eq!(insight.name.as_deref(), Some("login_success"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["username"], "Notch");
        assert_eq!(
            fields["properties"][0]["decoded"]["skin_url"],
            "http://textures.minecraft.net/texture/abc"
        );
    }

    #[test]
    fn player_info_updates_are_decoded_from_the_description() {
        let mut body = vec![0x01]; // add_player only
        body.extend_from_slice(&encode_var_i32(1));
        body.extend_from_slice(&[0x22; 16]);
        push_string(&mut body, "Notch");
        body.extend_from_slice(&encode_var_i32(1));
        push_string(&mut body, "textures");
        push_string(&mut body, &textures_property());
        body.push(0);
        let id = id_of(
            ProtocolState::Play,
            Direction::ServerToClient,
            "player_info_update",
        );
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            id,
            &body,
            Some(MODERN),
        );
        assert_eq!(insight.name.as_deref(), Some("player_info_update"));
        assert_eq!(insight.decoded_by.as_deref(), Some("definition"));
        assert!(insight.warnings.is_empty(), "{:?}", insight.warnings);
        let fields = insight.fields.unwrap();
        assert_eq!(fields["action"]["add_player"], true);
        assert_eq!(fields["data"][0]["player"]["name"], "Notch");
        assert_eq!(
            fields["data"][0]["player"]["properties"][0]["decoded"]["profileName"],
            "Notch"
        );

        // Every field has a span, so a rule can rename the player by path and
        // the string's length prefix is rewritten with it.
        let mut logical = encode_var_i32(id).to_vec();
        logical.extend_from_slice(&body);
        let layout = crate::layout::layout_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &logical,
            Some(MODERN),
        );
        assert!(layout.complete);
        assert!(
            layout
                .fields
                .iter()
                .any(|field| field.name == "data[0].player.name")
        );
        let edited = crate::rewrite::apply_edits(
            ProtocolState::Play,
            Direction::ServerToClient,
            Some(MODERN),
            &logical,
            &[mineburp_core::PacketEdit::Field {
                name: "data[0].player.name".into(),
                value: "Herobrine".into(),
            }],
        )
        .expect("the field edit applies");
        let insight = inspect_logical(
            ProtocolState::Play,
            Direction::ServerToClient,
            &edited,
            Some(MODERN),
        );
        assert!(insight.warnings.is_empty(), "{:?}", insight.warnings);
        assert_eq!(
            insight.fields.unwrap()["data"][0]["player"]["name"],
            "Herobrine"
        );
    }

    #[test]
    fn system_chat_click_actions_are_surfaced() {
        let mut body = vec![0x0a];
        nbt_string(&mut body, "text", "Free diamonds");
        body.push(0x0a);
        body.extend_from_slice(&11_u16.to_be_bytes());
        body.extend_from_slice(b"click_event");
        nbt_string(&mut body, "action", "run_command");
        nbt_string(&mut body, "command", "/op attacker");
        body.push(0x00); // end click_event
        body.push(0x00); // end root
        body.push(0x00); // not the action bar
        let id = id_of(
            ProtocolState::Play,
            Direction::ServerToClient,
            "system_chat",
        );
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            id,
            &body,
            Some(MODERN),
        );
        assert_eq!(insight.name.as_deref(), Some("system_chat"));
        let fields = insight.fields.unwrap();
        assert_eq!(fields["content_text"], "Free diamonds");
        assert_eq!(fields["interactive_events"][0]["action"], "run_command");
        assert_eq!(fields["interactive_events"][0]["value"], "/op attacker");
        assert_eq!(
            insight.summary.as_deref(),
            Some("system_chat: Free diamonds")
        );
    }

    #[test]
    fn declared_commands_are_reconstructed_as_syntax() {
        let mut body = encode_var_i32(3).to_vec();
        // Root: type 0, one child.
        body.push(0x00);
        body.extend_from_slice(&encode_var_i32(1));
        body.extend_from_slice(&encode_var_i32(1));
        // Literal "give": type 1, one child.
        body.push(0x01);
        body.extend_from_slice(&encode_var_i32(1));
        body.extend_from_slice(&encode_var_i32(2));
        push_string(&mut body, "give");
        // Argument "targets": type 2, executable (0x04), entity parser (6) with
        // its one flags byte.
        body.push(0x02 | 0x04);
        body.extend_from_slice(&encode_var_i32(0));
        push_string(&mut body, "targets");
        body.extend_from_slice(&encode_var_i32(6));
        body.push(0x00);
        body.extend_from_slice(&encode_var_i32(0)); // root index
        let id = id_of(ProtocolState::Play, Direction::ServerToClient, "commands");
        let insight = inspect_packet(
            ProtocolState::Play,
            Direction::ServerToClient,
            id,
            &body,
            Some(MODERN),
        );
        assert!(
            insight.warnings.is_empty(),
            "{:?} {:?}",
            insight.warnings,
            insight.fields
        );
        assert_eq!(
            insight.fields.unwrap()["commands"],
            json!(["/give <targets:entity>"])
        );
    }

    /// Every name a shape decoder can report, by the direction it runs in.
    const SHAPE_SERVERBOUND: &[&str] = &[
        "keep_alive",
        "client_information",
        "set_player_position_and_rotation",
        "set_player_position",
        "set_player_rotation",
        "move_vehicle",
        "chat_message",
        "chat_command",
        "player_action",
        "use_item_on",
        "click_container",
        "sign_update",
        "interact",
        "command_suggestion",
        "player_command",
        "custom_payload",
        "use_item",
        "set_held_item",
    ];
    const SHAPE_CLIENTBOUND: &[&str] = &[
        "keep_alive",
        "system_chat",
        "update_time",
        "player_abilities",
        "set_health",
        "set_experience",
        "container_set_data",
        "game_event",
        "set_default_spawn_position",
        "block_update",
        "block_destruction",
        "block_event",
        "level_event",
        "synchronize_player_position",
        "teleport_entity",
        "login",
        "open_screen",
        "boss_bar",
        "sound_effect",
        "add_entity",
        "damage_event",
        "entity_effect",
        "remove_entity_effect",
        "scoreboard_objective",
        "update_score",
        "reset_score",
        "combat_death",
        "player_info_remove",
        "add_resource_pack",
        "custom_payload",
        "set_entity_motion",
        "move_entity_pos",
        "move_entity_pos_rot",
        "move_entity_rot",
        "remove_entities",
    ];
    /// Shape-only names, and the table names they stand in for. A shape
    /// decoder can tell a lone text component from other packets but not a
    /// disconnect from a title, so it uses a generic name; with a table the
    /// specific one is reported instead.
    const SHAPE_ONLY: &[(&str, &[&str])] = &[
        (
            "text_component",
            &[
                "disconnect",
                "set_title_text",
                "set_subtitle_text",
                "set_action_bar_text",
            ],
        ),
        ("string_payload", &[]),
    ];

    #[test]
    fn every_shape_name_is_a_name_the_tables_use() {
        // One packet is one name whichever tier identified it: a shape name the
        // tables never produce would split one packet into two rows.
        let table = |direction, name: &str| {
            PacketRegistry::packet_id(ProtocolState::Play, direction, name, Some(MODERN))
        };
        for name in SHAPE_SERVERBOUND {
            assert!(
                table(Direction::ClientToServer, name).is_some(),
                "serverbound {name}"
            );
        }
        for name in SHAPE_CLIENTBOUND {
            assert!(
                table(Direction::ServerToClient, name).is_some(),
                "clientbound {name}"
            );
        }
        for (_, stands_for) in SHAPE_ONLY {
            for name in *stands_for {
                assert!(table(Direction::ServerToClient, name).is_some(), "{name}");
            }
        }
        assert!(
            PacketRegistry::packet_id(
                ProtocolState::Configuration,
                Direction::ClientToServer,
                "known_packs",
                Some(MODERN)
            )
            .is_some()
        );
        // And every name a hand decoder is keyed by is one some table uses.
        for name in SHAPE_SERVERBOUND.iter().chain(SHAPE_CLIENTBOUND) {
            assert!(
                has_hand_decoder(ProtocolState::Play, name),
                "{name} has no decoder"
            );
        }
    }

    #[test]
    fn every_tabulated_protocol_names_each_id_once_per_direction() {
        for protocol in PacketRegistry::tabulated_protocols() {
            for state in [
                ProtocolState::Login,
                ProtocolState::Configuration,
                ProtocolState::Play,
            ] {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    let mut seen = std::collections::HashSet::new();
                    for id in 0..512 {
                        if let Some(name) =
                            PacketRegistry::table_packet_name(state, direction, id, Some(protocol))
                        {
                            assert!(
                                seen.insert(name),
                                "{protocol} {state:?} {direction:?}: `{name}` twice"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn random_frames_through_inspection_and_layout_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for protocol in [None, Some(763), Some(MODERN), Some(776)] {
            for state_kind in [
                ProtocolState::Login,
                ProtocolState::Configuration,
                ProtocolState::Play,
            ] {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    for id in 0..0x84 {
                        for _ in 0..4 {
                            let length = usize::try_from(next() % 600).unwrap();
                            let mut logical = encode_var_i32(id).to_vec();
                            logical.extend((0..length).map(|_| {
                                let value = next();
                                let bytes = value.to_le_bytes();
                                if value % 3 == 0 {
                                    bytes[1]
                                } else {
                                    bytes[0] % 3
                                }
                            }));
                            let insight =
                                inspect_logical(state_kind, direction, &logical, protocol);
                            let _ = serde_json::to_string(&insight).unwrap();
                            let layout = crate::layout::layout_logical(
                                state_kind, direction, &logical, protocol,
                            );
                            assert!(
                                layout
                                    .fields
                                    .iter()
                                    .all(|field| { field.offset + field.length <= logical.len() })
                            );
                        }
                    }
                }
            }
        }
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
    fn summaries_show_handshake_loader_markers() {
        let mut body = encode_var_i32(774).to_vec();
        push_string(&mut body, "play.example.net\0FORGE");
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
        assert_eq!(
            insight.summary.as_deref(),
            Some("handshake: play.example.net\u{2400}FORGE")
        );
        // The field keeps the real bytes so edits round-trip.
        assert_eq!(
            insight.fields.unwrap()["server_address"],
            "play.example.net\0FORGE"
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
        let insight = play_untabulated(Direction::ServerToClient, &[0xff, 0x00, 0x13, 0x37, 0x99]);
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

    #[test]
    fn names_a_query_protocol_datagram() {
        let mut handshake = vec![0xFE, 0xFD, 0x09];
        handshake.extend_from_slice(&0x1a2b_3c4d_i32.to_be_bytes());
        handshake.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let insight = inspect_logical(
            ProtocolState::Opaque,
            Direction::ClientToServer,
            &handshake,
            None,
        );
        assert_eq!(insight.name.as_deref(), Some("query_handshake"));
        assert_eq!(insight.fields.unwrap()["session"], 0x1a2b_3c4d);

        // A stats reply from the server carries the same magic and session.
        let mut stats = vec![0xFE, 0xFD, 0x00];
        stats.extend_from_slice(&0x1a2b_3c4d_i32.to_be_bytes());
        stats.extend_from_slice(b"hostname\0A server\0");
        let insight = inspect_logical(
            ProtocolState::Opaque,
            Direction::ServerToClient,
            &stats,
            None,
        );
        assert_eq!(insight.name.as_deref(), Some("query_stats"));

        // An unknown opcode under the real magic stays with the generic
        // framing reader rather than being guessed into a query packet.
        let unknown_opcode = [0xFE_u8, 0xFD, 0x08, 1, 2, 3, 4];
        let insight = inspect_logical(
            ProtocolState::Opaque,
            Direction::ClientToServer,
            &unknown_opcode,
            None,
        );
        assert_eq!(insight.name.as_deref(), None);
    }
}
