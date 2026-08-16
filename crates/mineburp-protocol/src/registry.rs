use std::collections::HashMap;

use mineburp_core::{Direction, ProtocolState};
use serde::{Deserialize, Serialize};

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
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_legacy_and_modern_boundaries() {
        let registry = PacketRegistry::bundled();
        assert_eq!(registry.version(4).unwrap().canonical, "1.7.2");
        assert_eq!(registry.version(776).unwrap().canonical, "26.2");
    }
}
