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

/// How a decoded frame departed from the canonical encoding vanilla writes.
///
/// The proxy re-encodes every frame it forwards, which normalises all of these
/// away; recording them keeps malformed-framing tests visible in the history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent observations, any combination of which can hold"
)]
pub struct FrameDiagnostics {
    /// The frame length `VarInt` used more bytes than its value needs.
    pub overlong_length_prefix: bool,
    /// The compressed-format data length `VarInt` used more bytes than needed.
    pub overlong_data_length: bool,
    /// The packet id `VarInt` used more bytes than needed.
    pub overlong_packet_id: bool,
    /// Sent uncompressed (data length 0) although it reaches the threshold.
    pub uncompressed_above_threshold: bool,
    /// Sent compressed although it is smaller than the threshold.
    pub compressed_below_threshold: bool,
}

impl FrameDiagnostics {
    #[must_use]
    pub const fn is_canonical(self) -> bool {
        !(self.overlong_length_prefix
            || self.overlong_data_length
            || self.overlong_packet_id
            || self.uncompressed_above_threshold
            || self.compressed_below_threshold)
    }
}

/// Upper bound on the buffer reserved up front for a decompressed packet; the
/// declared size is attacker-controlled, so anything beyond grows on demand.
const MAX_PREALLOCATION: usize = 256 * 1024;

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

    /// Sets the threshold a Set Compression packet announced.
    ///
    /// A negative threshold is how vanilla switches compression off, so it is
    /// stored as `None` rather than as a framing that expects a data length.
    pub const fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = match threshold {
            Some(value) if value < 0 => None,
            other => other,
        };
    }

    pub fn try_decode(&self, input: &mut BytesMut) -> Result<Option<PacketFrame>, ProtocolError> {
        Ok(self
            .try_decode_with_diagnostics(input)?
            .map(|(frame, _)| frame))
    }

    /// Decodes one frame and reports how its framing departed from canonical.
    pub fn try_decode_with_diagnostics(
        &self,
        input: &mut BytesMut,
    ) -> Result<Option<(PacketFrame, FrameDiagnostics)>, ProtocolError> {
        let mut diagnostics = FrameDiagnostics::default();
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

        diagnostics.overlong_length_prefix = is_overlong(frame_length, prefix_length);
        input.advance(prefix_length);
        let framed = input.split_to(frame_length).freeze();
        let (logical, compressed) = if let Some(threshold) = self.compression_threshold {
            let threshold = usize::try_from(threshold).unwrap_or(0);
            let Some((uncompressed_length, data_prefix)) = decode_var_i32(&framed)? else {
                return Err(ProtocolError::InvalidUncompressedLength(-1));
            };
            if uncompressed_length < 0 {
                return Err(ProtocolError::InvalidUncompressedLength(
                    uncompressed_length,
                ));
            }
            diagnostics.overlong_data_length = is_overlong(
                usize::try_from(uncompressed_length).unwrap_or(0),
                data_prefix,
            );
            if uncompressed_length == 0 {
                let logical = framed.slice(data_prefix..);
                diagnostics.uncompressed_above_threshold = logical.len() >= threshold;
                (logical, false)
            } else {
                let expected = usize::try_from(uncompressed_length)
                    .map_err(|_| ProtocolError::InvalidUncompressedLength(uncompressed_length))?;
                if expected > self.max_frame_length {
                    return Err(ProtocolError::FrameTooLarge {
                        actual: expected,
                        limit: self.max_frame_length,
                    });
                }
                // Inflate at most one byte past the declared size: a stream that
                // keeps going is rejected without ever being fully expanded.
                let mut decoder = ZlibDecoder::new(&framed[data_prefix..]).take(
                    u64::try_from(expected)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                );
                let mut output = Vec::with_capacity(expected.min(MAX_PREALLOCATION));
                decoder.read_to_end(&mut output)?;
                diagnostics.compressed_below_threshold = expected < threshold;
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
        diagnostics.overlong_packet_id = encode_var_i32(id).len() != id_length;
        Ok(Some((
            PacketFrame {
                id,
                body: logical.slice(id_length..),
                compressed,
                wire_length: prefix_length + frame_length,
            },
            diagnostics,
        )))
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

/// True when a non-negative value was written with more `VarInt` bytes than it
/// needs.
fn is_overlong(value: usize, encoded_length: usize) -> bool {
    i32::try_from(value).is_ok_and(|value| encode_var_i32(value).len() != encoded_length)
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

    fn compressed_frame(declared: i32, zlib: &[u8]) -> BytesMut {
        let mut payload = encode_var_i32(declared).to_vec();
        payload.extend_from_slice(zlib);
        let mut framed = encode_var_i32(i32::try_from(payload.len()).unwrap()).to_vec();
        framed.extend_from_slice(&payload);
        BytesMut::from(framed.as_slice())
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn a_decompression_bomb_is_rejected_without_inflating_it() {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(Some(0));
        // 16 MiB of zeros claiming to be one byte.
        let bomb = zlib(&vec![0; 16 * 1024 * 1024]);
        let error = codec
            .try_decode(&mut compressed_frame(1, &bomb))
            .expect_err("a stream longer than its declared size is rejected");
        assert!(matches!(error, ProtocolError::InvalidUncompressedLength(1)));
    }

    #[test]
    fn a_declared_size_over_the_limit_is_rejected_before_inflating() {
        let mut codec = FrameCodec::new(1024);
        codec.set_compression_threshold(Some(0));
        let error = codec
            .try_decode(&mut compressed_frame(4096, &zlib(&[0; 16])))
            .unwrap_err();
        assert!(matches!(error, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn a_short_stream_is_rejected() {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(Some(0));
        let error = codec
            .try_decode(&mut compressed_frame(100, &zlib(&[1; 10])))
            .unwrap_err();
        assert!(matches!(
            error,
            ProtocolError::InvalidUncompressedLength(100)
        ));
    }

    #[test]
    fn a_negative_threshold_disables_compression() {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(Some(-1));
        assert_eq!(codec.compression_threshold(), None);
        let frame = PacketFrame {
            id: 3,
            body: Bytes::from_static(b"plain"),
            compressed: false,
            wire_length: 0,
        };
        let encoded = codec.encode(&frame).unwrap();
        assert_eq!(&encoded[..], &[6, 3, b'p', b'l', b'a', b'i', b'n']);
        let decoded = codec
            .try_decode(&mut BytesMut::from(encoded.as_ref()))
            .unwrap()
            .unwrap();
        assert_eq!(decoded.body, frame.body);
    }

    #[test]
    fn error_paths_are_reported() {
        let codec = FrameCodec::new(8);
        let negative = encode_var_i32(-5);
        assert!(matches!(
            codec.try_decode(&mut BytesMut::from(negative.as_ref())),
            Err(ProtocolError::NegativeFrameLength(-5))
        ));
        assert!(matches!(
            codec.try_decode(&mut BytesMut::from(&[9_u8][..])),
            Err(ProtocolError::FrameTooLarge {
                actual: 9,
                limit: 8
            })
        ));
        assert!(matches!(
            codec.try_decode(&mut BytesMut::from(&[0xff_u8; 6][..])),
            Err(ProtocolError::VarIntTooLong)
        ));
        assert!(matches!(
            codec.try_decode(&mut BytesMut::from(&[0_u8][..])),
            Err(ProtocolError::MissingPacketId)
        ));
        let mut compressing = FrameCodec::default();
        compressing.set_compression_threshold(Some(64));
        let negative_size = compressed_frame(-2, &[]);
        assert!(matches!(
            compressing.try_decode(&mut negative_size.clone()),
            Err(ProtocolError::InvalidUncompressedLength(-2))
        ));
    }

    #[test]
    fn canonical_frames_report_no_diagnostics() {
        let mut codec = FrameCodec::default();
        codec.set_compression_threshold(Some(8));
        for body in [vec![1_u8; 2], vec![2_u8; 512]] {
            let frame = PacketFrame {
                id: 0x40,
                body: Bytes::from(body),
                compressed: false,
                wire_length: 0,
            };
            let encoded = codec.encode(&frame).unwrap();
            let (_, diagnostics) = codec
                .try_decode_with_diagnostics(&mut BytesMut::from(encoded.as_ref()))
                .unwrap()
                .unwrap();
            assert!(diagnostics.is_canonical(), "{diagnostics:?}");
        }
    }

    #[test]
    fn non_canonical_framing_is_flagged() {
        let codec = FrameCodec::default();
        // Length 2 written as two bytes, id 1 written as two bytes.
        let mut overlong = BytesMut::from(&[0x83, 0x00, 0x81, 0x00, 0x07][..]);
        let (frame, diagnostics) = codec
            .try_decode_with_diagnostics(&mut overlong)
            .unwrap()
            .unwrap();
        assert_eq!((frame.id, frame.body.as_ref()), (1, &[7_u8][..]));
        assert!(diagnostics.overlong_length_prefix);
        assert!(diagnostics.overlong_packet_id);

        let mut compressing = FrameCodec::default();
        compressing.set_compression_threshold(Some(4));
        // Data length 0 although the packet reaches the threshold.
        let mut above = BytesMut::from(&[6, 0, 1, 2, 3, 4, 5][..]);
        let (_, diagnostics) = compressing
            .try_decode_with_diagnostics(&mut above)
            .unwrap()
            .unwrap();
        assert!(diagnostics.uncompressed_above_threshold);
        // Compressed although smaller than the threshold.
        let (_, diagnostics) = compressing
            .try_decode_with_diagnostics(&mut compressed_frame(2, &zlib(&[1, 2])))
            .unwrap()
            .unwrap();
        assert!(diagnostics.compressed_below_threshold);
        assert!(!diagnostics.is_canonical());
    }
}
