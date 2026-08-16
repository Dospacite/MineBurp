use std::io::{Read, Write};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use thiserror::Error;

use crate::{decode_var_i32, encode_var_i32};

const DEFAULT_MAX_FRAME_LENGTH: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("VarInt is longer than five bytes")]
    VarIntTooLong,
    #[error("VarLong is longer than ten bytes")]
    VarLongTooLong,
    #[error("negative frame length {0}")]
    NegativeFrameLength(i32),
    #[error("frame length {actual} exceeds configured limit {limit}")]
    FrameTooLarge { actual: usize, limit: usize },
    #[error("compressed packet declared an invalid size {0}")]
    InvalidUncompressedLength(i32),
    #[error("packet is missing its packet id")]
    MissingPacketId,
    #[error("zlib error: {0}")]
    Compression(#[from] std::io::Error),
    #[error("packet body cannot be represented in a protocol VarInt")]
    LengthOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub id: i32,
    pub body: Bytes,
    pub compressed: bool,
    pub wire_length: usize,
}

impl PacketFrame {
    #[must_use]
    pub fn logical_bytes(&self) -> Bytes {
        let id = encode_var_i32(self.id);
        let mut output = BytesMut::with_capacity(id.len() + self.body.len());
        output.extend_from_slice(&id);
        output.extend_from_slice(&self.body);
        output.freeze()
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn from_logical_bytes(input: Bytes) -> Result<Self, ProtocolError> {
        let Some((id, id_length)) = decode_var_i32(&input)? else {
            return Err(ProtocolError::MissingPacketId);
        };
        Ok(Self {
            id,
            body: input.slice(id_length..),
            compressed: false,
            wire_length: input.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FrameCodec {
    max_frame_length: usize,
    compression_threshold: Option<i32>,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_LENGTH)
    }
}

impl FrameCodec {
    #[must_use]
    pub const fn new(max_frame_length: usize) -> Self {
        Self {
            max_frame_length,
            compression_threshold: None,
        }
    }

    #[must_use]
    pub const fn compression_threshold(&self) -> Option<i32> {
        self.compression_threshold
    }

    pub const fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = threshold;
    }

    pub fn try_decode(&self, input: &mut BytesMut) -> Result<Option<PacketFrame>, ProtocolError> {
        let Some((frame_length, prefix_length)) = decode_var_i32(input)? else {
            return Ok(None);
        };
        if frame_length < 0 {
            return Err(ProtocolError::NegativeFrameLength(frame_length));
        }
        let frame_length = usize::try_from(frame_length)
            .map_err(|_| ProtocolError::NegativeFrameLength(frame_length))?;
        if frame_length > self.max_frame_length {
            return Err(ProtocolError::FrameTooLarge {
                actual: frame_length,
                limit: self.max_frame_length,
            });
        }
        if input.len() < prefix_length + frame_length {
            return Ok(None);
        }

        input.advance(prefix_length);
        let framed = input.split_to(frame_length).freeze();
        let (logical, compressed) = if self.compression_threshold.is_some() {
            let Some((uncompressed_length, data_prefix)) = decode_var_i32(&framed)? else {
                return Err(ProtocolError::InvalidUncompressedLength(-1));
            };
            if uncompressed_length < 0 {
                return Err(ProtocolError::InvalidUncompressedLength(
                    uncompressed_length,
                ));
            }
            if uncompressed_length == 0 {
                (framed.slice(data_prefix..), false)
            } else {
                let expected = usize::try_from(uncompressed_length)
                    .map_err(|_| ProtocolError::InvalidUncompressedLength(uncompressed_length))?;
                if expected > self.max_frame_length {
                    return Err(ProtocolError::FrameTooLarge {
                        actual: expected,
                        limit: self.max_frame_length,
                    });
                }
                let mut decoder = ZlibDecoder::new(&framed[data_prefix..]);
                let mut output = Vec::with_capacity(expected);
                decoder.read_to_end(&mut output)?;
                if output.len() != expected {
                    return Err(ProtocolError::InvalidUncompressedLength(
                        uncompressed_length,
                    ));
                }
                (Bytes::from(output), true)
            }
        } else {
            (framed, false)
        };

        let Some((id, id_length)) = decode_var_i32(&logical)? else {
            return Err(ProtocolError::MissingPacketId);
        };
        Ok(Some(PacketFrame {
            id,
            body: logical.slice(id_length..),
            compressed,
            wire_length: prefix_length + frame_length,
        }))
    }

    pub fn encode(&self, frame: &PacketFrame) -> Result<Bytes, ProtocolError> {
        let logical = frame.logical_bytes();
        let payload = if let Some(threshold) = self.compression_threshold {
            let should_compress = threshold >= 0
                && logical.len()
                    >= usize::try_from(threshold).map_err(|_| ProtocolError::LengthOverflow)?;
            if should_compress {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
                encoder.write_all(&logical)?;
                let compressed = encoder.finish()?;
                let logical_length =
                    i32::try_from(logical.len()).map_err(|_| ProtocolError::LengthOverflow)?;
                let prefix = encode_var_i32(logical_length);
                let mut payload = BytesMut::with_capacity(prefix.len() + compressed.len());
                payload.extend_from_slice(&prefix);
                payload.extend_from_slice(&compressed);
                payload.freeze()
            } else {
                let mut payload = BytesMut::with_capacity(logical.len() + 1);
                payload.put_u8(0);
                payload.extend_from_slice(&logical);
                payload.freeze()
            }
        } else {
            logical
        };

        let payload_length =
            i32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
        let prefix = encode_var_i32(payload_length);
        let mut output = BytesMut::with_capacity(prefix.len() + payload.len());
        output.extend_from_slice(&prefix);
        output.extend_from_slice(&payload);
        Ok(output.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_frame_round_trip() {
        let codec = FrameCodec::default();
        let frame = PacketFrame {
            id: 0x2a,
            body: Bytes::from_static(b"mineburp"),
            compressed: false,
            wire_length: 0,
        };
        let encoded = codec.encode(&frame).unwrap();
        let decoded = codec
            .try_decode(&mut BytesMut::from(encoded.as_ref()))
            .unwrap()
            .unwrap();
        assert_eq!(decoded.id, frame.id);
        assert_eq!(decoded.body, frame.body);
        assert!(!decoded.compressed);
    }

    #[test]
    fn compressed_frame_round_trip() {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(Some(8));
        let frame = PacketFrame {
            id: 1,
            body: Bytes::from(vec![7; 4_096]),
            compressed: false,
            wire_length: 0,
        };
        let encoded = codec.encode(&frame).unwrap();
        let decoded = codec
            .try_decode(&mut BytesMut::from(encoded.as_ref()))
            .unwrap()
            .unwrap();
        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.body, frame.body);
        assert!(decoded.compressed);
    }

    #[test]
    fn waits_for_complete_frame() {
        let codec = FrameCodec::default();
        let mut partial = BytesMut::from(&[5, 0, 1][..]);
        assert!(codec.try_decode(&mut partial).unwrap().is_none());
        assert_eq!(&partial[..], &[5, 0, 1]);
    }
}
