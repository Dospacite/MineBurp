use std::{collections::HashMap, sync::OnceLock};

use mineburp_core::{Direction, ProtocolState};
use serde::{Deserialize, Serialize};

/// One protocol version's play-state ids, as generated from that version's own
/// data by the `mineburp-packet-table` tool.
///
/// Play ids are renumbered nearly every release, so a table is only ever used
/// for the exact protocol it was generated from — a neighbouring version's
/// numbering is not an approximation, it is a different table.
#[derive(Debug, Clone, Deserialize)]
struct PlayTable {
    protocol: i32,
    #[allow(dead_code, reason = "carried for provenance in the data file")]
    version: String,
    #[allow(dead_code, reason = "carried for provenance in the data file")]
    source: String,
    /// Packet names indexed by id; a gap the version does not use is `null`.
    serverbound: Vec<Option<String>>,
    clientbound: Vec<Option<String>>,
}

static PLAY_TABLES: OnceLock<Vec<PlayTable>> = OnceLock::new();

fn play_tables() -> &'static [PlayTable] {
    PLAY_TABLES.get_or_init(|| {
        serde_json::from_str(include_str!("../data/play-packets.json"))
            .expect("bundled play packet tables must be valid")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub protocol: i32,
    pub canonical: String,
    pub releases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PacketRegistry {
    versions: HashMap<i32, ProtocolVersion>,
}

impl Default for PacketRegistry {
    fn default() -> Self {
        Self::bundled()
    }
}

impl PacketRegistry {
    #[must_use]
    pub fn bundled() -> Self {
        let entries: Vec<ProtocolVersion> =
            serde_json::from_str(include_str!("../data/protocol-versions.json"))
                .expect("bundled protocol registry must be valid");
        Self {
            versions: entries
                .into_iter()
                .map(|entry| (entry.protocol, entry))
                .collect(),
        }
    }

    #[must_use]
    pub fn version(&self, protocol: i32) -> Option<&ProtocolVersion> {
        self.versions.get(&protocol)
    }

    #[must_use]
    pub fn supported_protocols(&self) -> Vec<&ProtocolVersion> {
        let mut values = self.versions.values().collect::<Vec<_>>();
        values.sort_by_key(|value| value.protocol);
        values
    }

    /// Names the packets whose id has never moved between protocol versions.
    ///
    /// Handshake, status, and login ids are fixed for every release the app
    /// supports, so identifying them from the id alone is safe. Play and
    /// configuration ids are renumbered constantly and are deliberately absent:
    /// [`crate::inspect`] identifies those from the body instead.
    #[must_use]
    pub fn stable_packet_name(
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
    ) -> Option<&'static str> {
        match (state, direction, packet_id) {
            (ProtocolState::Handshake, Direction::ClientToServer, 0) => Some("handshake"),
            (ProtocolState::Status, Direction::ClientToServer, 0) => Some("status_request"),
            (ProtocolState::Status, Direction::ClientToServer, 1) => Some("ping_request"),
            (ProtocolState::Status, Direction::ServerToClient, 0) => Some("status_response"),
            (ProtocolState::Status, Direction::ServerToClient, 1) => Some("pong_response"),
            (ProtocolState::Login, Direction::ClientToServer, 0) => Some("login_start"),
            (ProtocolState::Login, Direction::ClientToServer, 1) => Some("encryption_response"),
            (ProtocolState::Login, Direction::ServerToClient, 0) => Some("login_disconnect"),
            (ProtocolState::Login, Direction::ServerToClient, 1) => Some("encryption_request"),
            (ProtocolState::Login, Direction::ServerToClient, 2) => Some("login_success"),
            (ProtocolState::Login, Direction::ServerToClient, 3) => Some("set_compression"),
            _ => None,
        }
    }

    /// Names a configuration-state packet from its id.
    ///
    /// Configuration is the one modern state whose ids are worth tabulating:
    /// unlike play it has been renumbered exactly twice since it was introduced
    /// in 1.20.2 — 1.20.5 inserted the cookie and transfer packets, and 1.21
    /// appended the report-details and server-links pair. Callers still validate
    /// the body against the name they get back, so a wrong protocol version
    /// downgrades to a structural read rather than to a wrong label.
    #[must_use]
    pub fn configuration_packet_name(
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        // Configuration did not exist before 1.20.2.
        let protocol = protocol.filter(|version| *version >= 764)?;
        let cookies = protocol >= 766; // 1.20.5 added cookies and transfers.
        let links = protocol >= 767; // 1.21 added report details and links.
        match direction {
            Direction::ClientToServer => Some(match (packet_id, cookies) {
                (0x00, _) => "client_information",
                (0x01, false) | (0x02, true) => "plugin_message",
                (0x02, false) | (0x03, true) => "finish_configuration_ack",
                (0x03, false) | (0x04, true) => "keep_alive",
                (0x04, false) | (0x05, true) => "pong",
                (0x05, false) | (0x06, true) => "resource_pack_response",
                (0x01, true) => "cookie_response",
                (0x07, true) => "known_packs",
                _ => return None,
            }),
            Direction::ServerToClient => Some(match (packet_id, cookies) {
                (0x00, false) | (0x01, true) => "plugin_message",
                (0x01, false) | (0x02, true) => "disconnect",
                (0x02, false) | (0x03, true) => "finish_configuration",
                (0x03, false) | (0x04, true) => "keep_alive",
                (0x04, false) | (0x05, true) => "ping",
                (0x05, false) | (0x07, true) => "registry_data",
                (0x06, false) | (0x08, true) => "remove_resource_pack",
                (0x07, false) | (0x09, true) => "add_resource_pack",
                (0x08, false) | (0x0c, true) => "update_enabled_features",
                (0x09, false) | (0x0d, true) => "update_tags",
                (0x00, true) => "cookie_request",
                (0x06, true) => "reset_chat",
                (0x0a, true) => "store_cookie",
                (0x0b, true) => "transfer",
                (0x0e, true) => "select_known_packs",
                (0x0f, true) if links => "custom_report_details",
                (0x10, true) if links => "server_links",
                _ => return None,
            }),
        }
    }

    /// Names a play-state packet from the table generated for that protocol.
    ///
    /// This is the one place an id is trusted in play, and only because the
    /// table is *derived*: `mineburp-packet-table` reads the ids out of the
    /// version's own data generator report. The match on protocol is exact —
    /// there is no nearest-version fallback, because a neighbouring release
    /// renumbers rather than approximates. Callers still let a body that decodes
    /// as something else overrule the name.
    #[must_use]
    pub fn play_packet_name(
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        let protocol = protocol?;
        let table = play_tables()
            .iter()
            .find(|table| table.protocol == protocol)?;
        let names = match direction {
            Direction::ClientToServer => &table.serverbound,
            Direction::ServerToClient => &table.clientbound,
        };
        names.get(usize::try_from(packet_id).ok()?)?.as_deref()
    }

    /// The protocols a play table has been generated for.
    #[must_use]
    pub fn tabulated_protocols() -> Vec<i32> {
        play_tables().iter().map(|table| table.protocol).collect()
    }

    #[must_use]
    pub fn packet_name(
        &self,
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        let modern_configuration = protocol.is_some_and(|value| value >= 764);
        match (state, direction, packet_id) {
            (ProtocolState::Handshake, Direction::ClientToServer, 0) => Some("handshake"),
            (ProtocolState::Status, Direction::ClientToServer, 0) => Some("status_request"),
            (ProtocolState::Status, Direction::ClientToServer, 1) => Some("ping_request"),
            (ProtocolState::Status, Direction::ServerToClient, 0) => Some("status_response"),
            (ProtocolState::Status, Direction::ServerToClient, 1) => Some("pong_response"),
            (ProtocolState::Login, Direction::ClientToServer, 0) => Some("login_start"),
            (ProtocolState::Login, Direction::ServerToClient, 0) => Some("login_disconnect"),
            (ProtocolState::Login, Direction::ServerToClient, 1) => Some("encryption_request"),
            (ProtocolState::Login, Direction::ClientToServer, 1) => Some("encryption_response"),
            (ProtocolState::Login, Direction::ServerToClient, 2) => Some("login_success"),
            (ProtocolState::Login, Direction::ServerToClient, 3) => Some("set_compression"),
            (ProtocolState::Login, Direction::ServerToClient, 4) if modern_configuration => {
                Some("login_plugin_request")
            }
            (ProtocolState::Login, Direction::ClientToServer, 2) if modern_configuration => {
                Some("login_plugin_response")
            }
            (ProtocolState::Configuration, _, _) => {
                Self::configuration_packet_name(direction, packet_id, protocol)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_ids_follow_the_version_they_were_renumbered_in() {
        let name = |direction, id, protocol| {
            PacketRegistry::configuration_packet_name(direction, id, Some(protocol))
        };
        // 1.20.4 still numbers plugin messages before the cookie packets exist.
        assert_eq!(
            name(Direction::ServerToClient, 0x00, 765),
            Some("plugin_message")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x00, 767),
            Some("cookie_request")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x01, 767),
            Some("plugin_message")
        );
        assert_eq!(
            name(Direction::ClientToServer, 0x07, 767),
            Some("known_packs")
        );
        // Server links only exist from 1.21 onwards.
        assert_eq!(name(Direction::ServerToClient, 0x10, 766), None);
        assert_eq!(
            name(Direction::ServerToClient, 0x10, 767),
            Some("server_links")
        );
        // Configuration itself did not exist before 1.20.2.
        assert_eq!(name(Direction::ClientToServer, 0x00, 763), None);
    }

    #[test]
    fn play_ids_are_named_only_for_the_protocol_they_were_generated_from() {
        let name = |direction, id, protocol| {
            PacketRegistry::play_packet_name(direction, id, Some(protocol))
        };
        // 1.21.4's own report puts the arm swing at 58 — a packet whose body is
        // a single VarInt and which shape identification can never reach.
        assert_eq!(name(Direction::ClientToServer, 58, 769), Some("swing"));
        assert_eq!(
            name(Direction::ClientToServer, 41, 769),
            Some("player_input")
        );
        assert_eq!(
            name(Direction::ClientToServer, 28, 769),
            Some("set_player_position"),
            "the table reports the name the inspector uses, not the vanilla one"
        );

        // A protocol with no table, an id past the end of one, and an unknown
        // version all decline rather than guess from a neighbouring release.
        assert_eq!(name(Direction::ClientToServer, 58, 767), None);
        assert_eq!(name(Direction::ClientToServer, 4_096, 769), None);
        assert_eq!(
            PacketRegistry::play_packet_name(Direction::ClientToServer, 58, None),
            None
        );
        assert!(PacketRegistry::tabulated_protocols().contains(&769));
    }

    #[test]
    fn registry_has_legacy_and_modern_boundaries() {
        let registry = PacketRegistry::bundled();
        assert_eq!(registry.version(4).unwrap().canonical, "1.7.2");
        assert_eq!(registry.version(776).unwrap().canonical, "26.2");
    }
}
