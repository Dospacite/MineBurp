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
    const KNOWN: [i32; 12] = [4, 5, 47, 340, 754, 759, 760, 763, 764, 766, 767, 769];
    match selector % 16 {
        0 => None,
        1 => Some(raw),
        index => Some(KNOWN[usize::from(index - 2) % KNOWN.len()]),
    }
}
