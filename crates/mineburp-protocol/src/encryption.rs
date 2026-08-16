use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::{ProtocolError, decode_var_i32, encode_var_i32};

const MAX_KEY_LENGTH: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key_der: Bytes,
    pub verify_token: Bytes,
    /// Version-specific fields appended by newer protocol revisions.
    pub trailing: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResponse {
    pub encrypted_secret: Bytes,
    pub encrypted_verify_token: Bytes,
}

#[derive(Debug, Error)]
pub enum EncryptionPacketError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("truncated encryption packet")]
    Truncated,
    #[error("encryption packet contains invalid UTF-8")]
    InvalidUtf8,
    #[error("encryption byte array length {0} is invalid")]
    InvalidLength(i32),
    #[error("the 1.19 signed nonce response variant is not supported")]
    SignedNonceUnsupported,
}

impl EncryptionRequest {
    pub fn decode(body: &[u8]) -> Result<Self, EncryptionPacketError> {
        let mut offset = 0;
        let server_id = read_string(body, &mut offset)?;
        let public_key_der = read_bytes(body, &mut offset)?;
        let verify_token = read_bytes(body, &mut offset)?;
        let trailing = Bytes::copy_from_slice(body.get(offset..).unwrap_or_default());
        Ok(Self {
            server_id,
            public_key_der,
            verify_token,
            trailing,
        })
    }

    pub fn encode(&self) -> Result<Bytes, EncryptionPacketError> {
        let mut output = BytesMut::new();
        write_string(&mut output, &self.server_id)?;
        write_bytes(&mut output, &self.public_key_der)?;
        write_bytes(&mut output, &self.verify_token)?;
        output.extend_from_slice(&self.trailing);
        Ok(output.freeze())
    }
}

impl EncryptionResponse {
    pub fn decode(body: &[u8], protocol_version: i32) -> Result<Self, EncryptionPacketError> {
        let mut offset = 0;
        let encrypted_secret = read_bytes(body, &mut offset)?;
        if (759..=760).contains(&protocol_version) {
            let uses_verify_token = *body.get(offset).ok_or(EncryptionPacketError::Truncated)? != 0;
            offset += 1;
            if !uses_verify_token {
                return Err(EncryptionPacketError::SignedNonceUnsupported);
            }
        }
        let encrypted_verify_token = read_bytes(body, &mut offset)?;
        Ok(Self {
            encrypted_secret,
            encrypted_verify_token,
        })
    }

    pub fn encode(&self, protocol_version: i32) -> Result<Bytes, EncryptionPacketError> {
        let mut output = BytesMut::new();
        write_bytes(&mut output, &self.encrypted_secret)?;
        if (759..=760).contains(&protocol_version) {
            output.put_u8(1);
        }
        write_bytes(&mut output, &self.encrypted_verify_token)?;
        Ok(output.freeze())
    }
}

fn read_string(input: &[u8], offset: &mut usize) -> Result<String, EncryptionPacketError> {
    let bytes = read_bytes(input, offset)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| EncryptionPacketError::InvalidUtf8)
}

fn read_bytes(input: &[u8], offset: &mut usize) -> Result<Bytes, EncryptionPacketError> {
    let remaining = input
        .get(*offset..)
        .ok_or(EncryptionPacketError::Truncated)?;
    let Some((length, prefix)) = decode_var_i32(remaining)? else {
        return Err(EncryptionPacketError::Truncated);
    };
    let length =
        usize::try_from(length).map_err(|_| EncryptionPacketError::InvalidLength(length))?;
    if length > MAX_KEY_LENGTH {
        return Err(EncryptionPacketError::InvalidLength(
            i32::try_from(length).unwrap_or(i32::MAX),
        ));
    }
    let start = offset
        .checked_add(prefix)
        .ok_or(EncryptionPacketError::Truncated)?;
    let end = start
        .checked_add(length)
        .ok_or(EncryptionPacketError::Truncated)?;
    let bytes = input
        .get(start..end)
        .ok_or(EncryptionPacketError::Truncated)?;
    *offset = end;
    Ok(Bytes::copy_from_slice(bytes))
}

fn write_string(output: &mut BytesMut, value: &str) -> Result<(), EncryptionPacketError> {
    write_bytes(output, value.as_bytes())
}

fn write_bytes(output: &mut BytesMut, value: &[u8]) -> Result<(), EncryptionPacketError> {
    let length =
        i32::try_from(value.len()).map_err(|_| EncryptionPacketError::InvalidLength(i32::MAX))?;
    output.extend_from_slice(&encode_var_i32(length));
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_preserves_version_tail() {
        let request = EncryptionRequest {
            server_id: String::new(),
            public_key_der: Bytes::from_static(&[1, 2, 3]),
            verify_token: Bytes::from_static(&[4, 5, 6, 7]),
            trailing: Bytes::from_static(&[1]),
        };
        assert_eq!(
            EncryptionRequest::decode(&request.encode().unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn response_round_trip_supports_legacy_and_nonce_flag_versions() {
        let response = EncryptionResponse {
            encrypted_secret: Bytes::from_static(&[1; 8]),
            encrypted_verify_token: Bytes::from_static(&[2; 8]),
        };
        for protocol in [47, 759, 760, 767] {
            let encoded = response.encode(protocol).unwrap();
            assert_eq!(
                EncryptionResponse::decode(&encoded, protocol).unwrap(),
                response
            );
        }
    }
}
