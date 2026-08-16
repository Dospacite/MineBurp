use bytes::Bytes;
use mineburp_core::{Direction, ProtocolState};
use serde_json::{Value, json};

use crate::{decode_handshake, decode_var_i32};

#[derive(Debug, Clone, Default)]
pub struct CommonPacketDecode {
    pub fields: Option<Value>,
    pub channel: Option<String>,
    pub loader: Option<String>,
    pub error: Option<String>,
    pub payload_offset: usize,
}

#[must_use]
pub fn decode_common_packet(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> CommonPacketDecode {
    decode_common_packet_inner(state, direction, packet_id, body, protocol_version).unwrap_or_else(
        |error| CommonPacketDecode {
            error: Some(error),
            ..CommonPacketDecode::default()
        },
    )
}

fn decode_common_packet_inner(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol_version: Option<i32>,
) -> Result<CommonPacketDecode, String> {
    match (state, direction, packet_id) {
        (ProtocolState::Handshake, Direction::ClientToServer, 0) => {
            let handshake = decode_handshake(body).map_err(|error| error.to_string())?;
            Ok(fields(json!({
                "protocol_version": handshake.protocol_version,
                "server_address": handshake.server_address,
                "server_port": handshake.server_port,
                "next_state": handshake.next_state,
            })))
        }
        (ProtocolState::Status, Direction::ServerToClient, 0) => {
            let (text, _) = read_string(body, 0)?;
            let response = serde_json::from_str(&text).unwrap_or(Value::String(text));
            Ok(fields(json!({ "response": response })))
        }
        (ProtocolState::Status, _, 1) => {
            let timestamp = i64::from_be_bytes(
                body.try_into()
                    .map_err(|_| "ping payload must be eight bytes")?,
            );
            Ok(fields(json!({ "payload": timestamp })))
        }
        (ProtocolState::Login, Direction::ClientToServer, 0) => {
            let (username, consumed) = read_string(body, 0)?;
            Ok(fields(json!({
                "username": username,
                "version_specific_bytes": hex(&body[consumed..]),
            })))
        }
        (ProtocolState::Login, Direction::ServerToClient, 3) => {
            let (threshold, _) = decode_var_i32(body)
                .map_err(|error| error.to_string())?
                .ok_or("truncated compression threshold")?;
            Ok(fields(json!({ "threshold": threshold })))
        }
        (ProtocolState::Login, Direction::ServerToClient, 4)
            if protocol_version.is_some_and(|version| version >= 393) =>
        {
            let (message_id, prefix) = decode_var_i32(body)
                .map_err(|error| error.to_string())?
                .ok_or("truncated login plugin message id")?;
            let (channel, consumed) = read_string(body, prefix)?;
            let data = Bytes::copy_from_slice(&body[consumed..]);
            Ok(plugin_decode(
                channel,
                json!({ "message_id": message_id, "data": hex(&data) }),
                consumed,
            ))
        }
        (ProtocolState::Login, Direction::ClientToServer, 2)
            if protocol_version.is_some_and(|version| version >= 393) =>
        {
            let (message_id, prefix) = decode_var_i32(body)
                .map_err(|error| error.to_string())?
                .ok_or("truncated login plugin response id")?;
            let successful = *body.get(prefix).ok_or("truncated login plugin result")? != 0;
            Ok(fields(json!({
                "message_id": message_id,
                "successful": successful,
                "data": hex(body.get(prefix + 1..).unwrap_or_default()),
            })))
        }
        (ProtocolState::Play, _, _)
            if legacy_plugin_message(direction, packet_id, protocol_version) =>
        {
            let (channel, consumed) = read_string(body, 0)?;
            Ok(plugin_decode(
                channel,
                json!({ "data": hex(&body[consumed..]) }),
                consumed,
            ))
        }
        _ => Ok(CommonPacketDecode::default()),
    }
}

fn fields(value: Value) -> CommonPacketDecode {
    CommonPacketDecode {
        fields: Some(value),
        ..CommonPacketDecode::default()
    }
}

fn plugin_decode(channel: String, value: Value, payload_offset: usize) -> CommonPacketDecode {
    let loader = loader_for_channel(&channel).map(str::to_owned);
    CommonPacketDecode {
        fields: Some(value),
        channel: Some(channel),
        loader,
        error: None,
        payload_offset,
    }
}

fn legacy_plugin_message(
    direction: Direction,
    packet_id: i32,
    protocol_version: Option<i32>,
) -> bool {
    match (protocol_version, direction) {
        (Some(4 | 5 | 47), Direction::ClientToServer) => packet_id == 0x17,
        (Some(4 | 5 | 47), Direction::ServerToClient) => packet_id == 0x3f,
        (Some(107..=340), Direction::ClientToServer) => packet_id == 0x09,
        (Some(107..=340), Direction::ServerToClient) => packet_id == 0x18,
        _ => false,
    }
}

fn loader_for_channel(channel: &str) -> Option<&'static str> {
    let lower = channel.to_ascii_lowercase();
    if lower.starts_with("neoforge:") || lower.contains("neoforge") {
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

fn read_string(input: &[u8], offset: usize) -> Result<(String, usize), String> {
    let remaining = input.get(offset..).ok_or("truncated string")?;
    let (length, prefix) = decode_var_i32(remaining)
        .map_err(|error| error.to_string())?
        .ok_or("truncated string length")?;
    let length = usize::try_from(length).map_err(|_| "negative string length")?;
    if length > 1_048_576 {
        return Err("string exceeds decoding limit".into());
    }
    let start = offset.checked_add(prefix).ok_or("string offset overflow")?;
    let end = start.checked_add(length).ok_or("string length overflow")?;
    let value = input.get(start..end).ok_or("truncated string value")?;
    let value = String::from_utf8(value.to_vec()).map_err(|_| "string is not valid UTF-8")?;
    Ok((value, end))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_var_i32;

    #[test]
    fn decodes_fabric_login_plugin_channel() {
        let channel = b"fabric:registry/sync";
        let mut body = encode_var_i32(7).to_vec();
        body.extend_from_slice(&encode_var_i32(i32::try_from(channel.len()).unwrap()));
        body.extend_from_slice(channel);
        body.extend_from_slice(&[1, 2, 3]);
        let decoded = decode_common_packet(
            ProtocolState::Login,
            Direction::ServerToClient,
            4,
            &body,
            Some(767),
        );
        assert_eq!(decoded.channel.as_deref(), Some("fabric:registry/sync"));
        assert_eq!(decoded.loader.as_deref(), Some("fabric"));
    }
}
