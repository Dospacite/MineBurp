use std::{collections::HashMap, sync::OnceLock};

use mineburp_core::{Direction, ProtocolState};
use serde::{Deserialize, Serialize};

/// One state's ids, indexed by packet id; a gap the version does not use is
/// `null`.
#[derive(Debug, Clone, Default, Deserialize)]
struct StateTable {
    serverbound: Vec<Option<String>>,
    clientbound: Vec<Option<String>>,
}

impl StateTable {
    fn name(&self, direction: Direction, packet_id: i32) -> Option<&str> {
        let names = match direction {
            Direction::ClientToServer => &self.serverbound,
            Direction::ServerToClient => &self.clientbound,
        };
        names.get(usize::try_from(packet_id).ok()?)?.as_deref()
    }

    fn id(&self, direction: Direction, name: &str) -> Option<i32> {
        let names = match direction {
            Direction::ClientToServer => &self.serverbound,
            Direction::ServerToClient => &self.clientbound,
        };
        let index = names
            .iter()
            .position(|entry| entry.as_deref() == Some(name))?;
        i32::try_from(index).ok()
    }
}

/// One protocol version's ids, as generated from that version's own data by
/// the `mineburp-packet-table` tool.
///
/// Ids are renumbered nearly every release, so a table is only ever used for
/// the exact protocol it was generated from — a neighbouring version's
/// numbering is not an approximation, it is a different table.
#[derive(Debug, Clone, Deserialize)]
struct PacketTable {
    protocol: i32,
    #[allow(dead_code, reason = "carried for provenance in the data file")]
    version: String,
    source: String,
    #[serde(default)]
    login: Option<StateTable>,
    #[serde(default)]
    configuration: Option<StateTable>,
    play: StateTable,
}

impl PacketTable {
    fn state(&self, state: ProtocolState) -> Option<&StateTable> {
        match state {
            ProtocolState::Login => self.login.as_ref(),
            ProtocolState::Configuration => self.configuration.as_ref(),
            ProtocolState::Play => Some(&self.play),
            _ => None,
        }
    }
}

static PACKET_TABLES: OnceLock<HashMap<i32, PacketTable>> = OnceLock::new();

fn packet_tables() -> &'static HashMap<i32, PacketTable> {
    PACKET_TABLES.get_or_init(|| {
        let tables: Vec<PacketTable> =
            serde_json::from_str(include_str!("../data/packet-tables.json"))
                .expect("bundled packet tables must be valid");
        tables
            .into_iter()
            .map(|table| (table.protocol, table))
            .collect()
    })
}

fn state_table(state: ProtocolState, protocol: Option<i32>) -> Option<&'static StateTable> {
    packet_tables().get(&protocol?)?.state(state)
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
    /// Handshake, status, and the first four login ids are fixed for every
    /// release the app supports, so identifying them from the id alone is safe.
    /// Play and configuration ids are renumbered constantly and are absent
    /// here: they are only read through a generated table.
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

    /// Names a login-state packet, including the ones that are version-gated.
    ///
    /// Login ids 0–3 have never moved. Later additions are appended rather than
    /// inserted — the plugin exchange in 1.13, the acknowledgement that enters
    /// configuration in 1.20.2, the cookie pair in 1.20.5 — so their ids are
    /// stable too, but only from the release that introduced them. A generated
    /// table is used when there is one; the gates below cover versions without.
    #[must_use]
    pub fn login_packet_name(
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        if let Some(table) = state_table(ProtocolState::Login, protocol) {
            return table.name(direction, packet_id);
        }
        if let Some(name) = Self::stable_packet_name(ProtocolState::Login, direction, packet_id) {
            return Some(name);
        }
        let version = protocol?;
        match (direction, packet_id) {
            (Direction::ServerToClient, 4) if version >= 393 => Some("login_plugin_request"),
            (Direction::ClientToServer, 2) if version >= 393 => Some("login_plugin_response"),
            (Direction::ClientToServer, 3) if version >= 764 => Some("login_acknowledged"),
            (Direction::ServerToClient, 5) if version >= 766 => Some("cookie_request"),
            (Direction::ClientToServer, 4) if version >= 766 => Some("cookie_response"),
            _ => None,
        }
    }

    /// Names a configuration-state packet from the table generated for that
    /// protocol.
    ///
    /// Configuration was renumbered several times after it appeared in 1.20.2
    /// — 1.20.3 inserted the resource-pack removal, 1.20.5 the cookies and
    /// transfers, 1.21 the report details and server links, 1.21.6 the dialogs
    /// — so ids are only read through a table generated for the exact protocol.
    #[must_use]
    pub fn configuration_packet_name(
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        state_table(ProtocolState::Configuration, protocol)?.name(direction, packet_id)
    }

    /// Names a play-state packet from the table generated for that protocol.
    ///
    /// The match on protocol is exact — there is no nearest-version fallback,
    /// because a neighbouring release renumbers rather than approximates.
    #[must_use]
    pub fn play_packet_name(
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        state_table(ProtocolState::Play, protocol)?.name(direction, packet_id)
    }

    /// Names a packet in any tabulated state (login, configuration, or play).
    #[must_use]
    pub fn table_packet_name(
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        state_table(state, protocol)?.name(direction, packet_id)
    }

    /// The id a tabulated packet has in one protocol — the inverse of
    /// [`Self::table_packet_name`], for callers that need to recognise a packet
    /// by name (the proxy's state machine, for instance).
    #[must_use]
    pub fn packet_id(
        state: ProtocolState,
        direction: Direction,
        name: &str,
        protocol: Option<i32>,
    ) -> Option<i32> {
        state_table(state, protocol)?.id(direction, name)
    }

    /// True when a generated table covers this state of this protocol, which
    /// is when the id — not the body's shape — names the packet.
    #[must_use]
    pub fn is_tabulated(state: ProtocolState, protocol: Option<i32>) -> bool {
        state_table(state, protocol).is_some()
    }

    /// Where a protocol's table came from (`vanilla data generator report` or
    /// `minecraft-data`).
    #[must_use]
    pub fn table_source(protocol: i32) -> Option<&'static str> {
        packet_tables()
            .get(&protocol)
            .map(|table| table.source.as_str())
    }

    /// The protocols a table has been generated for.
    #[must_use]
    pub fn tabulated_protocols() -> Vec<i32> {
        let mut protocols: Vec<i32> = packet_tables().keys().copied().collect();
        protocols.sort_unstable();
        protocols
    }

    #[must_use]
    pub fn packet_name(
        &self,
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
        protocol: Option<i32>,
    ) -> Option<&'static str> {
        match state {
            ProtocolState::Handshake | ProtocolState::Status => {
                Self::stable_packet_name(state, direction, packet_id)
            }
            ProtocolState::Login => Self::login_packet_name(direction, packet_id, protocol),
            ProtocolState::Configuration | ProtocolState::Play => {
                Self::table_packet_name(state, direction, packet_id, protocol)
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
        // 1.20.2 had no resource-pack removal: 0x06 adds a pack, then the
        // feature flags and tags follow it.
        assert_eq!(
            name(Direction::ServerToClient, 0x06, 764),
            Some("add_resource_pack")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x07, 764),
            Some("update_enabled_features")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x08, 764),
            Some("update_tags")
        );
        // 1.20.3 inserted the removal in front of it.
        assert_eq!(
            name(Direction::ServerToClient, 0x06, 765),
            Some("remove_resource_pack")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x00, 765),
            Some("plugin_message")
        );
        assert_eq!(
            name(Direction::ServerToClient, 0x00, 767),
            Some("cookie_request")
        );
        assert_eq!(
            name(Direction::ClientToServer, 0x07, 767),
            Some("known_packs")
        );
        // Server links only exist from 1.21 onwards, dialogs from 1.21.6.
        assert_eq!(name(Direction::ServerToClient, 0x10, 766), None);
        assert_eq!(
            name(Direction::ServerToClient, 0x10, 767),
            Some("server_links")
        );
        assert_eq!(name(Direction::ServerToClient, 0x12, 770), None);
        assert_eq!(
            name(Direction::ServerToClient, 0x12, 771),
            Some("show_dialog")
        );
        assert_eq!(
            name(Direction::ClientToServer, 0x08, 771),
            Some("custom_click_action")
        );
        // Configuration itself did not exist before 1.20.2.
        assert_eq!(name(Direction::ClientToServer, 0x00, 763), None);
    }

    #[test]
    fn login_additions_are_named_only_from_the_release_that_added_them() {
        let name = |direction, id, protocol| {
            PacketRegistry::login_packet_name(direction, id, Some(protocol))
        };
        assert_eq!(name(Direction::ClientToServer, 0, 4), Some("login_start"));
        assert_eq!(name(Direction::ServerToClient, 4, 340), None);
        assert_eq!(
            name(Direction::ServerToClient, 4, 393),
            Some("login_plugin_request")
        );
        assert_eq!(name(Direction::ClientToServer, 3, 763), None);
        assert_eq!(
            name(Direction::ClientToServer, 3, 764),
            Some("login_acknowledged")
        );
        assert_eq!(name(Direction::ServerToClient, 5, 765), None);
        assert_eq!(
            name(Direction::ServerToClient, 5, 766),
            Some("cookie_request")
        );
        assert_eq!(
            name(Direction::ClientToServer, 4, 776),
            Some("cookie_response")
        );
        // An untabulated release still gets the gated names.
        assert_eq!(
            name(Direction::ClientToServer, 2, 485),
            Some("login_plugin_response")
        );
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
        assert_eq!(name(Direction::ClientToServer, 58, 485), None);
        assert_eq!(name(Direction::ClientToServer, 4_096, 769), None);
        assert_eq!(
            PacketRegistry::play_packet_name(Direction::ClientToServer, 58, None),
            None
        );
        assert!(PacketRegistry::tabulated_protocols().contains(&769));
        assert_eq!(
            PacketRegistry::packet_id(
                ProtocolState::Play,
                Direction::ClientToServer,
                "swing",
                Some(769)
            ),
            Some(58)
        );
    }

    #[test]
    fn every_release_has_a_table_except_the_ones_no_source_describes() {
        // 1.7.2 and 1.7.10 predate both sources' coverage, and minecraft-data
        // skips 1.14.2; every other release in the registry is tabulated.
        let registry = PacketRegistry::bundled();
        let tabulated = PacketRegistry::tabulated_protocols();
        let missing: Vec<i32> = registry
            .supported_protocols()
            .into_iter()
            .map(|entry| entry.protocol)
            .filter(|protocol| !tabulated.contains(protocol))
            .collect();
        assert_eq!(missing, vec![4, 5, 485]);
        assert_eq!(
            PacketRegistry::table_source(769),
            Some("vanilla data generator report")
        );
        assert_eq!(PacketRegistry::table_source(765), Some("minecraft-data"));
    }

    #[test]
    fn registry_has_legacy_and_modern_boundaries() {
        let registry = PacketRegistry::bundled();
        assert_eq!(registry.version(4).unwrap().canonical, "1.7.2");
        assert_eq!(registry.version(776).unwrap().canonical, "26.2");
    }
}
