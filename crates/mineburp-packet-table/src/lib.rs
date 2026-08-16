//! Builds play-state packet-id tables from a version's own data.
//!
//! Play ids are renumbered nearly every release, which is why [`mineburp_protocol::inspect`]
//! identifies play packets from their body rather than their id. Shape has a
//! floor, though: a one-byte body holding `0` or `1` is an arm swing, a client
//! command, and a movement-input bitmask all at once, and no validator can
//! separate them.
//!
//! A table lifts that floor — but only if the table is *derived*, never typed
//! out. Everything here reads a machine-generated description of one version:
//!
//! * the vanilla data generator's `reports/packets.json`, which is the game
//!   telling you its own ids, and
//! * `minecraft-data`'s `protocol.json`, which reaches back to versions that
//!   predate the report.
//!
//! Names are mapped onto the names the inspector already uses, so a packet named
//! from a table and the same packet named from its shape are the same row.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TableError {
    #[error("{0} is not valid JSON: {1}")]
    Json(&'static str, serde_json::Error),
    #[error("{0}")]
    Shape(String),
    #[error("no packets were found for the play state")]
    Empty,
}

/// One protocol version's play-state ids, indexed by packet id.
///
/// The vectors are indexed rather than keyed because vanilla numbers play
/// packets contiguously from zero; a hole is a version that skipped an id, and
/// stays `null` rather than shifting everything after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayTable {
    pub protocol: i32,
    pub version: String,
    /// Where the table came from, so a stale or hand-edited entry is obvious.
    pub source: String,
    pub serverbound: Vec<Option<String>>,
    pub clientbound: Vec<Option<String>>,
}

impl PlayTable {
    #[must_use]
    pub fn packet_count(&self) -> usize {
        self.serverbound.iter().flatten().count() + self.clientbound.iter().flatten().count()
    }
}

/// The two directions of one state, keyed by id before they are laid out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Directions {
    pub serverbound: BTreeMap<i32, String>,
    pub clientbound: BTreeMap<i32, String>,
}

impl Directions {
    fn into_table(
        self,
        protocol: i32,
        version: String,
        source: String,
    ) -> Result<PlayTable, TableError> {
        if self.serverbound.is_empty() && self.clientbound.is_empty() {
            return Err(TableError::Empty);
        }
        Ok(PlayTable {
            protocol,
            version,
            source,
            serverbound: lay_out(&self.serverbound),
            clientbound: lay_out(&self.clientbound),
        })
    }
}

fn lay_out(entries: &BTreeMap<i32, String>) -> Vec<Option<String>> {
    let highest = entries.keys().copied().max().unwrap_or(-1);
    let mut slots = vec![None; usize::try_from(highest + 1).unwrap_or_default()];
    for (id, name) in entries {
        if let Ok(index) = usize::try_from(*id)
            && let Some(slot) = slots.get_mut(index)
        {
            *slot = Some(name.clone());
        }
    }
    slots
}

/// Reads the vanilla data generator's `reports/packets.json`.
///
/// The report is a map of state to direction to packet, each carrying its own
/// `protocol_id`, which is exactly the mapping the running game uses.
pub fn from_vanilla_report(
    json: &str,
    protocol: i32,
    version: &str,
) -> Result<PlayTable, TableError> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|error| TableError::Json("the packet report", error))?;
    let play = root
        .get("play")
        .ok_or_else(|| TableError::Shape("the report has no `play` state".into()))?;
    let mut directions = Directions::default();
    for (key, target) in [
        ("serverbound", &mut directions.serverbound),
        ("clientbound", &mut directions.clientbound),
    ] {
        let Some(entries) = play.get(key).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, value) in entries {
            let id = value
                .get("protocol_id")
                .unwrap_or(value)
                .as_i64()
                .ok_or_else(|| TableError::Shape(format!("`{name}` has no protocol id")))?;
            target.insert(
                i32::try_from(id)
                    .map_err(|_| TableError::Shape(format!("`{name}` has an absurd id {id}")))?,
                canonical_name(strip_namespace(name)).to_owned(),
            );
        }
    }
    directions.into_table(
        protocol,
        version.to_owned(),
        "vanilla data generator report".into(),
    )
}

/// Reads a `minecraft-data` `protocol.json`.
///
/// The ids live in the `packet` type's name mapper, which is a `mapper` node
/// whose `mappings` object is id to packet name. Older versions predate the
/// vanilla report, and this is the only machine-readable description of them.
pub fn from_prismarine(json: &str, protocol: i32, version: &str) -> Result<PlayTable, TableError> {
    let root: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| TableError::Json("the minecraft-data protocol", error))?;
    let play = root
        .get("play")
        .ok_or_else(|| TableError::Shape("the protocol has no `play` state".into()))?;
    let mut directions = Directions::default();
    for (key, target) in [
        ("toServer", &mut directions.serverbound),
        ("toClient", &mut directions.clientbound),
    ] {
        let Some(side) = play.get(key) else { continue };
        let Some(mappings) = find_mappings(side) else {
            continue;
        };
        for (id, name) in mappings {
            let Some(name) = name.as_str() else { continue };
            let id = parse_id(&id)
                .ok_or_else(|| TableError::Shape(format!("`{id}` is not a packet id")))?;
            target.insert(id, canonical_name(strip_prismarine(name)).to_owned());
        }
    }
    directions.into_table(protocol, version.to_owned(), "minecraft-data".into())
}

/// Finds the first `mappings` object under a subtree.
///
/// Walking rather than indexing a fixed path: the container layout around the
/// mapper has moved between `minecraft-data` releases, the mapper itself has
/// not.
fn find_mappings(value: &serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Object(mappings)) = map.get("mappings") {
                return Some(mappings.clone());
            }
            map.values().find_map(find_mappings)
        }
        serde_json::Value::Array(items) => items.iter().find_map(find_mappings),
        _ => None,
    }
}

fn parse_id(raw: &str) -> Option<i32> {
    let trimmed = raw.trim();
    trimmed.strip_prefix("0x").map_or_else(
        || trimmed.parse().ok(),
        |hex| i32::from_str_radix(hex, 16).ok(),
    )
}

fn strip_namespace(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, rest)| rest)
}

/// `minecraft-data` prefixes its names with the direction they travel.
fn strip_prismarine(name: &str) -> &str {
    name.strip_prefix("packet_").unwrap_or(name)
}

/// Maps a version's own packet name onto the name the inspector reports.
///
/// Without this a table would name a packet `move_player_pos` while the shape
/// decoder for the same bytes calls it `set_player_position`, and the history
/// would show one packet under two names depending on which tier identified it.
#[must_use]
pub fn canonical_name(name: &str) -> &str {
    match name {
        // Movement.
        "move_player_pos" | "position" => "set_player_position",
        "move_player_pos_rot" | "position_look" => "set_player_position_and_rotation",
        "move_player_rot" | "look" => "set_player_rotation",
        "move_player_status_only" | "flying" => "set_player_on_ground",
        "vehicle_move" | "steer_vehicle" => "move_vehicle",
        // Chat and commands.
        "chat" | "chat_message" => "chat_message",
        "chat_command_signed" | "chat_command" => "chat_command",
        "tab_complete" => "command_suggestion",
        // Inventory and held items.
        "set_carried_item" | "held_item_slot" | "held_item_change" => "set_held_item",
        // Clientbound world and player state.
        "player_position" | "position_look_clientbound" => "synchronize_player_position",
        "set_time" | "update_time" => "update_time",
        "spawn_position" | "set_default_spawn_position" => "set_default_spawn_position",
        "update_health" => "set_health",
        "experience" => "set_experience",
        "abilities" => "player_abilities",
        "game_state_change" => "game_event",
        "resource_pack_push" | "resource_pack_send" => "add_resource_pack",
        "block_break_animation" => "block_destruction",
        "block_action" => "block_event",
        "world_event" => "level_event",
        "open_window" => "open_screen",
        "entity_destroy" | "entity_remove" => "remove_entities",
        "entity_velocity" => "set_entity_motion",
        "rel_entity_move" => "move_entity_pos",
        "entity_move_look" => "move_entity_pos_rot",
        "entity_look" => "move_entity_rot",
        "entity_teleport" => "teleport_entity",
        "custom_payload" | "plugin_message" => "custom_payload",
        "block_change" => "block_update",
        "login" | "join_game" => "login",
        other => other,
    }
}

/// Replaces the entry for this protocol, keeping the file ordered by version.
#[must_use]
pub fn merge(existing: Vec<PlayTable>, table: PlayTable) -> Vec<PlayTable> {
    let mut tables: Vec<PlayTable> = existing
        .into_iter()
        .filter(|entry| entry.protocol != table.protocol)
        .collect();
    tables.push(table);
    tables.sort_by_key(|entry| entry.protocol);
    tables
}

pub fn render(tables: &[PlayTable]) -> Result<String, TableError> {
    let mut json = serde_json::to_string_pretty(tables)
        .map_err(|error| TableError::Json("the generated table", error))?;
    json.push('\n');
    Ok(json)
}

pub fn parse_existing(json: &str) -> Result<Vec<PlayTable>, TableError> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json).map_err(|error| TableError::Json("the existing table file", error))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
      "handshake": { "serverbound": { "minecraft:intention": { "protocol_id": 0 } } },
      "play": {
        "serverbound": {
          "minecraft:swing": { "protocol_id": 54 },
          "minecraft:move_player_pos": { "protocol_id": 26 },
          "minecraft:use_item_on": { "protocol_id": 56 }
        },
        "clientbound": {
          "minecraft:set_time": { "protocol_id": 98 },
          "minecraft:block_update": { "protocol_id": 9 }
        }
      }
    }"#;

    #[test]
    fn reads_the_vanilla_report_and_lays_ids_out_in_place() {
        let table = from_vanilla_report(REPORT, 769, "1.21.4").expect("the report parses");
        assert_eq!(table.protocol, 769);
        assert_eq!(table.serverbound[54].as_deref(), Some("swing"));
        assert_eq!(table.serverbound[56].as_deref(), Some("use_item_on"));
        assert_eq!(
            table.serverbound[26].as_deref(),
            Some("set_player_position"),
            "the version's own name is mapped onto the inspector's name"
        );
        assert_eq!(table.clientbound[98].as_deref(), Some("update_time"));
        assert!(
            table.serverbound[0].is_none(),
            "ids the state does not use stay empty rather than shifting the rest"
        );
        assert_eq!(table.packet_count(), 5);
    }

    #[test]
    fn reads_minecraft_data_protocol_descriptions() {
        let protocol = r#"{
          "play": {
            "toServer": { "types": { "packet": ["container", [
              { "name": "name", "type": ["mapper", { "type": "varint",
                "mappings": { "0x00": "teleport_confirm", "0x36": "arm_animation" } }] }
            ]] } },
            "toClient": { "types": { "packet": ["container", [
              { "name": "name", "type": ["mapper", { "type": "varint",
                "mappings": { "0x09": "block_change" } }] }
            ]] } }
          }
        }"#;
        let table = from_prismarine(protocol, 767, "1.21").expect("the protocol parses");
        assert_eq!(table.serverbound[0x36].as_deref(), Some("arm_animation"));
        assert_eq!(table.clientbound[0x09].as_deref(), Some("block_update"));
        assert_eq!(table.source, "minecraft-data");
    }

    #[test]
    fn a_regenerated_table_replaces_the_old_one_in_place() {
        let first = from_vanilla_report(REPORT, 769, "1.21.4").unwrap();
        let other = from_vanilla_report(REPORT, 767, "1.21").unwrap();
        let merged = merge(merge(Vec::new(), first.clone()), other);
        assert_eq!(
            merged
                .iter()
                .map(|entry| entry.protocol)
                .collect::<Vec<_>>(),
            vec![767, 769],
            "tables stay ordered by protocol"
        );

        let regenerated = PlayTable {
            source: "hand edited".into(),
            ..first
        };
        let merged = merge(merged, regenerated);
        assert_eq!(merged.len(), 2, "a protocol appears exactly once");
        assert_eq!(merged[1].source, "hand edited");
    }

    #[test]
    fn a_report_without_play_packets_is_an_error_rather_than_an_empty_table() {
        let error = from_vanilla_report(r#"{"play":{}}"#, 769, "1.21.4")
            .expect_err("an empty state must not be written out as a table");
        assert!(matches!(error, TableError::Empty));
    }
}
