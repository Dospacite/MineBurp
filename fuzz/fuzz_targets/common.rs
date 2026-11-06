//! Shared decoding of fuzz input into protocol context.

use arbitrary::Arbitrary;
use mineburp_core::{Direction, ProtocolState};

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum State {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
    Opaque,
}

impl From<State> for ProtocolState {
    fn from(state: State) -> Self {
        match state {
            State::Handshake => Self::Handshake,
            State::Status => Self::Status,
            State::Login => Self::Login,
            State::Configuration => Self::Configuration,
            State::Play => Self::Play,
            State::Opaque => Self::Opaque,
        }
    }
}

#[allow(dead_code)]
pub fn direction(server_to_client: bool) -> Direction {
    if server_to_client {
        Direction::ServerToClient
    } else {
        Direction::ClientToServer
    }
}

/// Picks a protocol version that has real tables behind it most of the time,
/// and an arbitrary one otherwise.
pub fn version(selector: u8, raw: i32) -> Option<i32> {
    static KNOWN: std::sync::LazyLock<Vec<i32>> = std::sync::LazyLock::new(|| {
        let mut versions = mineburp_protocol::definition_protocols();
        versions.extend(mineburp_protocol::PacketRegistry::tabulated_protocols());
        versions.sort_unstable();
        versions.dedup();
        versions
    });
    match selector {
        0 => None,
        1 => Some(raw),
        index => Some(KNOWN[usize::from(index - 2) % KNOWN.len()]),
    }
}
