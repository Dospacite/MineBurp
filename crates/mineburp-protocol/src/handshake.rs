use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::{ProtocolError, decode_var_i32, encode_var_i32};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("truncated handshake")]
    Truncated,
    #[error("server address is not valid UTF-8")]
    InvalidAddress,
    #[error("server address is longer than the protocol permits")]
    AddressTooLong,
}

pub fn decode_handshake(body: &[u8]) -> Result<Handshake, HandshakeError> {
    let Some((protocol_version, protocol_length)) = decode_var_i32(body)? else {
        return Err(HandshakeError::Truncated);
    };
    let remaining = &body[protocol_length..];
    let Some((address_length, address_prefix)) = decode_var_i32(remaining)? else {
        return Err(HandshakeError::Truncated);
    };
    let address_length =
        usize::try_from(address_length).map_err(|_| HandshakeError::AddressTooLong)?;
    let address_start = address_prefix;
    let address_end = address_start
        .checked_add(address_length)
        .ok_or(HandshakeError::AddressTooLong)?;
    let address = remaining
        .get(address_start..address_end)
        .ok_or(HandshakeError::Truncated)?;
    let tail = remaining
        .get(address_end..)
        .ok_or(HandshakeError::Truncated)?;
    if tail.len() < 2 {
        return Err(HandshakeError::Truncated);
    }
    let server_port = u16::from_be_bytes([tail[0], tail[1]]);
    let Some((next_state, _)) = decode_var_i32(&tail[2..])? else {
        return Err(HandshakeError::Truncated);
    };
    Ok(Handshake {
        protocol_version,
        server_address: String::from_utf8(address.to_vec())
            .map_err(|_| HandshakeError::InvalidAddress)?,
        server_port,
        next_state,
    })
}

pub fn encode_handshake(handshake: &Handshake) -> Result<Bytes, HandshakeError> {
    let address_length = i32::try_from(handshake.server_address.len())
        .map_err(|_| HandshakeError::AddressTooLong)?;
    let protocol = encode_var_i32(handshake.protocol_version);
    let address_prefix = encode_var_i32(address_length);
    let next_state = encode_var_i32(handshake.next_state);
    let mut output = BytesMut::with_capacity(
        protocol.len()
            + address_prefix.len()
            + handshake.server_address.len()
            + 2
            + next_state.len(),
    );
    output.extend_from_slice(&protocol);
    output.extend_from_slice(&address_prefix);
    output.extend_from_slice(handshake.server_address.as_bytes());
    output.put_u16(handshake.server_port);
    output.extend_from_slice(&next_state);
    Ok(output.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trip_preserves_forge_markers() {
        let handshake = Handshake {
            protocol_version: 763,
            server_address: "localhost\0FML2\0".into(),
            server_port: 25_565,
            next_state: 2,
        };
        let encoded = encode_handshake(&handshake).unwrap();
        assert_eq!(decode_handshake(&encoded).unwrap(), handshake);
    }
}
