use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::{ProtocolError, decode_var_i32, encode_var_i32};

const MAX_KEY_LENGTH: usize = 8 * 1024;
/// 1.7.x (protocols 4 and 5) prefixed encryption byte arrays with a big-endian
/// `i16`; 1.8 moved them to `VarInt`.
const LAST_SHORT_PREFIX_PROTOCOL: i32 = 5;
/// 1.20.5 appended `should_authenticate` to the request.
const SHOULD_AUTHENTICATE_PROTOCOL: i32 = 766;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key_der: Bytes,
    pub verify_token: Bytes,
    /// Version-specific fields appended by newer protocol revisions, kept raw
    /// so a re-encoded request carries exactly what the server sent.
    pub trailing: Bytes,
    /// Whether the client must join the session server (1.20.5+). A server in
    /// offline mode that still encrypts sends `false`; older protocols always
    /// authenticate. Encoding writes it into the first trailing byte.
    pub should_authenticate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResponse {
    pub encrypted_secret: Bytes,
    pub encrypted_verify_token: Bytes,
    /// The profile-key signature a 1.19–1.19.2 client sends in place of the
    /// verify token. The signature covers the server hash, the shared secret,
    /// and the request nonce, so it authenticates this exact exchange.
    pub signature: Option<Bytes>,
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
}

impl EncryptionRequest {
    /// Decodes a request without knowing the protocol version. 1.7.x requests
    /// need [`Self::decode_for`]; a lone trailing `0` is read as
    /// `should_authenticate = false`.
    pub fn decode(body: &[u8]) -> Result<Self, EncryptionPacketError> {
        Self::decode_inner(body, None)
    }

    /// Decodes a request in the layout `protocol_version` uses.
    pub fn decode_for(body: &[u8], protocol_version: i32) -> Result<Self, EncryptionPacketError> {
        Self::decode_inner(body, Some(protocol_version))
    }

    fn decode_inner(body: &[u8], version: Option<i32>) -> Result<Self, EncryptionPacketError> {
        let prefix = ArrayPrefix::for_version(version);
        let mut offset = 0;
        let server_id = read_string(body, &mut offset)?;
        let public_key_der = prefix.read(body, &mut offset)?;
        let verify_token = prefix.read(body, &mut offset)?;
        let trailing = Bytes::copy_from_slice(body.get(offset..).unwrap_or_default());
        let should_authenticate = match version {
            Some(version) if version >= SHOULD_AUTHENTICATE_PROTOCOL => {
                trailing.first() != Some(&0)
            }
            Some(_) => true,
            None => trailing.as_ref() != [0],
        };
        Ok(Self {
            server_id,
            public_key_der,
            verify_token,
            trailing,
            should_authenticate,
        })
    }

    pub fn encode(&self) -> Result<Bytes, EncryptionPacketError> {
        self.encode_inner(None)
    }

    /// Encodes the request in the layout `protocol_version` uses.
    pub fn encode_for(&self, protocol_version: i32) -> Result<Bytes, EncryptionPacketError> {
        self.encode_inner(Some(protocol_version))
    }

    fn encode_inner(&self, version: Option<i32>) -> Result<Bytes, EncryptionPacketError> {
        let prefix = ArrayPrefix::for_version(version);
        let mut output = BytesMut::new();
        write_string(&mut output, &self.server_id)?;
        prefix.write(&mut output, &self.public_key_der)?;
        prefix.write(&mut output, &self.verify_token)?;
        let mut trailing = self.trailing.to_vec();
        let flag = u8::from(self.should_authenticate);
        let carries_flag = match version {
            Some(version) => version >= SHOULD_AUTHENTICATE_PROTOCOL,
            // Without a version, only a tail that already holds a flag (or a
            // request that needs one to say `false`) is written as one.
            None => matches!(trailing.as_slice(), [0 | 1]) || !self.should_authenticate,
        };
        if carries_flag {
            match trailing.first_mut() {
                Some(first) => *first = flag,
                None => trailing.push(flag),
            }
        }
        output.extend_from_slice(&trailing);
        Ok(output.freeze())
    }
}

impl EncryptionResponse {
    pub fn decode(body: &[u8], protocol_version: i32) -> Result<Self, EncryptionPacketError> {
        let mut offset = 0;
        if protocol_version <= LAST_SHORT_PREFIX_PROTOCOL {
            let encrypted_secret = ArrayPrefix::Short.read(body, &mut offset)?;
            let encrypted_verify_token = ArrayPrefix::Short.read(body, &mut offset)?;
            return Ok(Self {
                encrypted_secret,
                encrypted_verify_token,
                signature: None,
            });
        }
        let encrypted_secret = read_bytes(body, &mut offset)?;
        // 1.19 and 1.19.2 prefix a flag: the client either echoes the verify
        // token or proves itself with a profile-key signature over the nonce.
        let (encrypted_verify_token, signature) = if (759..=760).contains(&protocol_version) {
            let uses_verify_token = *body.get(offset).ok_or(EncryptionPacketError::Truncated)? != 0;
            offset += 1;
            if uses_verify_token {
                (read_bytes(body, &mut offset)?, None)
            } else {
                (Bytes::new(), Some(read_bytes(body, &mut offset)?))
            }
        } else {
            (read_bytes(body, &mut offset)?, None)
        };
        Ok(Self {
            encrypted_secret,
            encrypted_verify_token,
            signature,
        })
    }

    pub fn encode(&self, protocol_version: i32) -> Result<Bytes, EncryptionPacketError> {
        let mut output = BytesMut::new();
        if protocol_version <= LAST_SHORT_PREFIX_PROTOCOL {
            ArrayPrefix::Short.write(&mut output, &self.encrypted_secret)?;
            ArrayPrefix::Short.write(&mut output, &self.encrypted_verify_token)?;
            return Ok(output.freeze());
        }
        write_bytes(&mut output, &self.encrypted_secret)?;
        if (759..=760).contains(&protocol_version) {
            if let Some(signature) = &self.signature {
                output.put_u8(0);
                write_bytes(&mut output, signature)?;
            } else {
                output.put_u8(1);
                write_bytes(&mut output, &self.encrypted_verify_token)?;
            }
        } else {
            write_bytes(&mut output, &self.encrypted_verify_token)?;
        }
        Ok(output.freeze())
    }
}

/// How a byte array's length is written.
#[derive(Debug, Clone, Copy)]
enum ArrayPrefix {
    VarInt,
    Short,
}

impl ArrayPrefix {
    fn for_version(version: Option<i32>) -> Self {
        if version.is_some_and(|version| version <= LAST_SHORT_PREFIX_PROTOCOL) {
            Self::Short
        } else {
            Self::VarInt
        }
    }

    fn read(self, input: &[u8], offset: &mut usize) -> Result<Bytes, EncryptionPacketError> {
        match self {
            Self::VarInt => read_bytes(input, offset),
            Self::Short => {
                let end = offset
                    .checked_add(2)
                    .ok_or(EncryptionPacketError::Truncated)?;
                let prefix: [u8; 2] = input
                    .get(*offset..end)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(EncryptionPacketError::Truncated)?;
                let length = i16::from_be_bytes(prefix);
                let length = usize::try_from(length)
                    .map_err(|_| EncryptionPacketError::InvalidLength(i32::from(length)))?;
                let bytes = input
                    .get(end..end + length)
                    .ok_or(EncryptionPacketError::Truncated)?;
                *offset = end + length;
                Ok(Bytes::copy_from_slice(bytes))
            }
        }
    }

    fn write(self, output: &mut BytesMut, value: &[u8]) -> Result<(), EncryptionPacketError> {
        match self {
            Self::VarInt => write_bytes(output, value),
            Self::Short => {
                let length = i16::try_from(value.len())
                    .map_err(|_| EncryptionPacketError::InvalidLength(i32::MAX))?;
                output.put_i16(length);
                output.extend_from_slice(value);
                Ok(())
            }
        }
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
            should_authenticate: true,
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
            signature: None,
        };
        for protocol in [47, 759, 760, 767] {
            let encoded = response.encode(protocol).unwrap();
            assert_eq!(
                EncryptionResponse::decode(&encoded, protocol).unwrap(),
                response
            );
        }
    }

    #[test]
    fn a_signed_nonce_response_decodes_with_its_signature() {
        let mut body = BytesMut::new();
        write_bytes(&mut body, &[1, 2, 3, 4]).unwrap();
        body.put_u8(0);
        let signature = [0xa5_u8; 256];
        write_bytes(&mut body, &signature).unwrap();
        let response = EncryptionResponse::decode(&body, 760).unwrap();
        assert_eq!(response.encrypted_secret.as_ref(), &[1, 2, 3, 4]);
        assert!(response.encrypted_verify_token.is_empty());
        assert_eq!(response.signature.as_deref(), Some(signature.as_slice()));
        // The flag form still decodes against the same version.
        let flagged = EncryptionResponse {
            encrypted_secret: Bytes::from_static(&[1, 2, 3, 4]),
            encrypted_verify_token: Bytes::from_static(&[9]),
            signature: None,
        };
        assert_eq!(
            EncryptionResponse::decode(&flagged.encode(759).unwrap(), 759).unwrap(),
            flagged
        );
    }

    fn request(trailing: &'static [u8], should_authenticate: bool) -> EncryptionRequest {
        EncryptionRequest {
            server_id: String::new(),
            public_key_der: Bytes::from_static(&[1, 2, 3]),
            verify_token: Bytes::from_static(&[4, 5, 6, 7]),
            trailing: Bytes::from_static(trailing),
            should_authenticate,
        }
    }

    #[test]
    fn should_authenticate_is_read_from_modern_requests() {
        let offline = request(&[0], false);
        let encoded = offline.encode_for(767).unwrap();
        assert_eq!(encoded.last(), Some(&0));
        let decoded = EncryptionRequest::decode_for(&encoded, 767).unwrap();
        assert!(!decoded.should_authenticate);
        assert!(
            !EncryptionRequest::decode(&encoded)
                .unwrap()
                .should_authenticate
        );

        // Flipping the field rewrites the flag byte rather than appending one.
        let mut online = decoded.clone();
        online.should_authenticate = true;
        let reencoded = online.encode_for(767).unwrap();
        assert_eq!(reencoded.len(), encoded.len());
        assert!(
            EncryptionRequest::decode_for(&reencoded, 767)
                .unwrap()
                .should_authenticate
        );

        // A request from before 1.20.5 has no flag and always authenticates.
        let legacy = request(&[], true).encode_for(765).unwrap();
        let decoded = EncryptionRequest::decode_for(&legacy, 765).unwrap();
        assert!(decoded.should_authenticate);
        assert!(decoded.trailing.is_empty());
    }

    #[test]
    fn protocol_1_7_uses_short_array_prefixes() {
        let legacy = request(&[], true);
        let encoded = legacy.encode_for(5).unwrap();
        // Empty server id, then i16 lengths.
        assert_eq!(&encoded[..4], &[0, 0, 3, 1]);
        assert_eq!(EncryptionRequest::decode_for(&encoded, 5).unwrap(), legacy);

        let response = EncryptionResponse {
            encrypted_secret: Bytes::from(vec![7; 128]),
            encrypted_verify_token: Bytes::from(vec![8; 128]),
            signature: None,
        };
        let encoded = response.encode(4).unwrap();
        assert_eq!(&encoded[..2], &[0, 128]);
        assert_eq!(EncryptionResponse::decode(&encoded, 4).unwrap(), response);
        assert!(matches!(
            EncryptionResponse::decode(&[0xff, 0xff], 4),
            Err(EncryptionPacketError::InvalidLength(-1))
        ));
    }
}
