use bytes::Bytes;
use mineburp_core::{Direction, ProtocolState};
use serde_json::{Value, json};

use crate::{Reader, decode_handshake, decode_var_i32};

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
            decode_login_start(body, protocol_version).map(fields)
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
                json!({ "message_id": message_id, "data_bytes": data.len() }),
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
                "data_bytes": body.get(prefix + 1..).unwrap_or_default().len(),
            })))
        }
        (ProtocolState::Play, _, _)
            if legacy_plugin_message(direction, packet_id, protocol_version) =>
        {
            let (channel, consumed) = read_string(body, 0)?;
            Ok(plugin_decode(
                channel,
                json!({ "data_bytes": body[consumed..].len() }),
                consumed,
            ))
        }
        _ => Ok(CommonPacketDecode::default()),
    }
}

/// Login Start, whose tail changed four times:
///
/// - before 1.19 (759): the name alone;
/// - 1.19 (759): an optional profile-key block (expiry, key, signature);
/// - 1.19.1–1.19.2 (760): that block, then an optional UUID;
/// - 1.19.3–1.20.1 (761–763): an optional UUID;
/// - 1.20.2 (764) on: a UUID, always.
///
/// With no version known, a UUID is read only when it is exactly what is left.
fn decode_login_start(body: &[u8], protocol_version: Option<i32>) -> Result<Value, String> {
    let (username, consumed) = read_string(body, 0)?;
    let mut reader = Reader::new(body);
    reader.take(consumed).ok_or("truncated username")?;
    let mut output = json!({ "username": username });
    let signature_block = |reader: &mut Reader<'_>, output: &mut Value| -> Result<(), String> {
        if reader.bool().ok_or("truncated profile key flag")? {
            let expires_at = reader.i64().ok_or("truncated profile key expiry")?;
            let key = reader.byte_array().ok_or("truncated profile public key")?;
            let signature = reader
                .byte_array()
                .ok_or("truncated profile key signature")?;
            output["profile_key"] = json!({
                "expires_at": expires_at,
                "public_key_bytes": key.len(),
                "signature_bytes": signature.len(),
            });
        }
        Ok(())
    };
    let optional_uuid = |reader: &mut Reader<'_>| -> Result<Option<uuid::Uuid>, String> {
        if reader.bool().ok_or("truncated UUID flag")? {
            return reader
                .uuid()
                .map(Some)
                .ok_or_else(|| "truncated UUID".into());
        }
        Ok(None)
    };
    let uuid = match protocol_version {
        Some(version) if version < 759 => None,
        Some(759) => {
            signature_block(&mut reader, &mut output)?;
            None
        }
        Some(760) => {
            signature_block(&mut reader, &mut output)?;
            optional_uuid(&mut reader)?
        }
        Some(761..=763) => optional_uuid(&mut reader)?,
        Some(_) => Some(reader.uuid().ok_or("truncated UUID")?),
        None if reader.remaining() == 16 => reader.uuid(),
        None => None,
    };
    if let Some(uuid) = uuid {
        output["uuid"] = Value::String(uuid.to_string());
    }
    if protocol_version.is_some() && !reader.is_empty() {
        output["trailing_bytes"] = Value::from(reader.remaining());
    }
    Ok(output)
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

    fn login_start(name: &str, tail: &[u8]) -> Vec<u8> {
        let mut body = encode_var_i32(i32::try_from(name.len()).unwrap()).to_vec();
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(tail);
        body
    }

    fn decode_login(body: &[u8], version: Option<i32>) -> Value {
        decode_common_packet(
            ProtocolState::Login,
            Direction::ClientToServer,
            0,
            body,
            version,
        )
        .fields
        .expect("login start decodes")
    }

    #[test]
    fn login_start_follows_every_protocol_layout() {
        let uuid = [0x11_u8; 16];
        let expected_uuid = uuid::Uuid::from_bytes(uuid).to_string();

        let legacy = decode_login(&login_start("Notch", &[]), Some(47));
        assert_eq!(legacy, json!({ "username": "Notch" }));

        // 1.19: a profile-key block, no UUID.
        let mut signed = vec![1];
        signed.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
        signed.extend_from_slice(&[3, 1, 2, 3]);
        signed.extend_from_slice(&[2, 9, 9]);
        let v759 = decode_login(&login_start("Notch", &signed), Some(759));
        assert_eq!(v759["profile_key"]["public_key_bytes"], 3);
        assert!(v759.get("uuid").is_none());

        // 1.19.2: no key, then a present UUID.
        let mut tail = vec![0, 1];
        tail.extend_from_slice(&uuid);
        let v760 = decode_login(&login_start("Notch", &tail), Some(760));
        assert_eq!(v760["uuid"], expected_uuid);

        // 1.19.3–1.20.1: an absent UUID is a single zero flag, not a UUID.
        let v762 = decode_login(&login_start("Notch", &[0]), Some(762));
        assert_eq!(v762, json!({ "username": "Notch" }));
        let mut present = vec![1];
        present.extend_from_slice(&uuid);
        assert_eq!(
            decode_login(&login_start("Notch", &present), Some(763))["uuid"],
            expected_uuid
        );

        // 1.20.2 on: always a UUID.
        let modern = decode_login(&login_start("Notch", &uuid), Some(767));
        assert_eq!(modern["uuid"], expected_uuid);
        let error = decode_common_packet(
            ProtocolState::Login,
            Direction::ClientToServer,
            0,
            &login_start("Notch", &[]),
            Some(767),
        )
        .error;
        assert!(
            error.is_some(),
            "a modern login start without its UUID is truncated"
        );
    }
}
