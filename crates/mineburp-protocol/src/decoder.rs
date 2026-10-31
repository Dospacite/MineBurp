//! Standalone, bounded transformations for the workbench's Decoder sidebar.
use crate::{Reader, decode_var_i32, decode_var_i64, encode_var_i32, encode_var_i64};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{
    Compression,
    read::{GzDecoder, ZlibDecoder},
    write::{GzEncoder, ZlibEncoder},
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const LIMIT: usize = 1024 * 1024;
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoderOperation {
    HexToText,
    TextToHex,
    Base64ToHex,
    HexToBase64,
    NormalizeHex,
    VarIntDecode,
    VarIntEncode,
    VarLongDecode,
    VarLongEncode,
    StringDecode,
    StringEncode,
    UuidDecode,
    UuidEncode,
    U16BeDecode,
    U16LeDecode,
    U32BeDecode,
    U32LeDecode,
    U64BeDecode,
    U64LeDecode,
    U16BeEncode,
    U16LeEncode,
    U32BeEncode,
    U32LeEncode,
    U64BeEncode,
    U64LeEncode,
    ZlibDecompress,
    ZlibCompress,
    GzipDecompress,
    GzipCompress,
    NbtDecode,
    NbtEncode,
    NamedNbtDecode,
    NamedNbtEncode,
    JsonPretty,
}
#[derive(Debug, Serialize)]
pub struct DecoderResult {
    pub output: String,
    pub consumed: Option<usize>,
    pub trailing_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !compact.len().is_multiple_of(2) || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Use complete hexadecimal byte pairs separated by whitespace".into());
    }
    compact
        .as_bytes()
        .chunks(2)
        .map(|c| {
            u8::from_str_radix(std::str::from_utf8(c).map_err(|e| e.to_string())?, 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}
fn inflate(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(LIMIT + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > LIMIT {
        return Err("Decompressed output exceeds 1 MiB".into());
    }
    Ok(bytes)
}
fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| "Invalid or out-of-range decimal integer".into())
}

#[allow(clippy::too_many_lines)]
pub fn transform(operation: DecoderOperation, input: &str) -> Result<DecoderResult, String> {
    use DecoderOperation as O;
    if input.len() > LIMIT * 3 {
        return Err("Decoder input exceeds 3 MiB".into());
    }
    let mut consumed = None;
    let mut trailing_hex = String::new();
    let mut decoded = |bytes: &[u8], n: usize, value: String| {
        consumed = Some(n);
        trailing_hex = hex(&bytes[n..]);
        value
    };
    let output = match operation {
        O::TextToHex => hex(input.as_bytes()),
        O::Base64ToHex => hex(&STANDARD
            .decode(input.split_whitespace().collect::<String>())
            .map_err(|e| e.to_string())?),
        O::VarIntEncode => hex(&encode_var_i32(number(input)?)),
        O::VarLongEncode => hex(&encode_var_i64(number(input)?)),
        O::StringEncode => {
            let len = i32::try_from(input.len()).map_err(|e| e.to_string())?;
            let mut bytes = encode_var_i32(len).to_vec();
            bytes.extend_from_slice(input.as_bytes());
            hex(&bytes)
        }
        O::UuidEncode => hex(uuid::Uuid::parse_str(input.trim())
            .map_err(|e| e.to_string())?
            .as_bytes()),
        O::U16BeEncode => hex(&number::<u16>(input)?.to_be_bytes()),
        O::U16LeEncode => hex(&number::<u16>(input)?.to_le_bytes()),
        O::U32BeEncode => hex(&number::<u32>(input)?.to_be_bytes()),
        O::U32LeEncode => hex(&number::<u32>(input)?.to_le_bytes()),
        O::U64BeEncode => hex(&number::<u64>(input)?.to_be_bytes()),
        O::U64LeEncode => hex(&number::<u64>(input)?.to_le_bytes()),
        O::NbtEncode | O::NamedNbtEncode => hex(&crate::nbt_text::from_text(
            input,
            matches!(operation, O::NamedNbtEncode),
            None,
        )?),
        O::JsonPretty => serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(input).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
        _ => {
            let bytes = unhex(input)?;
            if bytes.len() > LIMIT {
                return Err("Binary input exceeds 1 MiB".into());
            }
            match operation {
                O::HexToText => String::from_utf8(bytes).map_err(|e| e.to_string())?,
                O::HexToBase64 => STANDARD.encode(bytes),
                O::NormalizeHex => hex(&bytes),
                O::VarIntDecode => {
                    let (n, len) = decode_var_i32(&bytes)
                        .map_err(|e| e.to_string())?
                        .ok_or("Incomplete VarInt")?;
                    decoded(&bytes, len, n.to_string())
                }
                O::VarLongDecode => {
                    let (n, len) = decode_var_i64(&bytes)
                        .map_err(|e| e.to_string())?
                        .ok_or("Incomplete VarLong")?;
                    decoded(&bytes, len, n.to_string())
                }
                O::StringDecode => {
                    let mut reader = Reader::new(&bytes);
                    let text = reader.string(LIMIT).ok_or("Invalid Minecraft string")?;
                    decoded(&bytes, bytes.len() - reader.rest().len(), text)
                }
                O::UuidDecode => {
                    let uuid =
                        uuid::Uuid::from_slice(bytes.get(..16).ok_or("UUID needs 16 bytes")?)
                            .map_err(|e| e.to_string())?;
                    decoded(&bytes, 16, uuid.to_string())
                }
                O::U16BeDecode
                | O::U16LeDecode
                | O::U32BeDecode
                | O::U32LeDecode
                | O::U64BeDecode
                | O::U64LeDecode => {
                    let size = match operation {
                        O::U16BeDecode | O::U16LeDecode => 2,
                        O::U32BeDecode | O::U32LeDecode => 4,
                        _ => 8,
                    };
                    let part = bytes
                        .get(..size)
                        .ok_or("Not enough bytes for this integer")?;
                    let little =
                        matches!(operation, O::U16LeDecode | O::U32LeDecode | O::U64LeDecode);
                    let value = if little {
                        part.iter()
                            .rev()
                            .fold(0u64, |n, b| (n << 8) | u64::from(*b))
                    } else {
                        part.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b))
                    };
                    decoded(&bytes, size, value.to_string())
                }
                O::ZlibDecompress => hex(&inflate(ZlibDecoder::new(bytes.as_slice()))?),
                O::GzipDecompress => hex(&inflate(GzDecoder::new(bytes.as_slice()))?),
                O::ZlibCompress => {
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&bytes).map_err(|e| e.to_string())?;
                    hex(&encoder.finish().map_err(|e| e.to_string())?)
                }
                O::GzipCompress => {
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&bytes).map_err(|e| e.to_string())?;
                    hex(&encoder.finish().map_err(|e| e.to_string())?)
                }
                O::NbtDecode | O::NamedNbtDecode => {
                    crate::nbt_text::to_text(&bytes, matches!(operation, O::NamedNbtDecode))
                        .ok_or("Invalid, incomplete, or non-roundtrippable NBT")?
                }
                _ => return Err("Unsupported transformation".into()),
            }
        }
    };
    if output.len() > LIMIT * 3 {
        return Err("Decoder output exceeds 3 MiB".into());
    }
    Ok(DecoderResult {
        output,
        consumed,
        trailing_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_trailing_bytes_and_integer_precision() {
        let result = transform(DecoderOperation::VarIntDecode, "ac 02 ff").unwrap();
        assert_eq!(result.output, "300");
        assert_eq!(result.consumed, Some(2));
        assert_eq!(result.trailing_hex, "ff");
        assert_eq!(
            transform(DecoderOperation::U64BeDecode, "ff ff ff ff ff ff ff ff")
                .unwrap()
                .output,
            "18446744073709551615"
        );
        assert_eq!(
            transform(DecoderOperation::VarLongEncode, "-1")
                .unwrap()
                .output,
            "ff ff ff ff ff ff ff ff ff 01"
        );
        assert!(transform(DecoderOperation::NormalizeHex, "😀").is_err());
    }
    #[test]
    fn string_nbt_and_compression_roundtrips() {
        for (encode, decode, input) in [
            (
                DecoderOperation::StringEncode,
                DecoderOperation::StringDecode,
                "hello",
            ),
            (
                DecoderOperation::NbtEncode,
                DecoderOperation::NbtDecode,
                "{\"answer\":42}",
            ),
        ] {
            let wire = transform(encode, input).unwrap().output;
            let output = transform(decode, &wire).unwrap().output;
            assert!(!output.is_empty());
        }
        let zipped = transform(DecoderOperation::ZlibCompress, "01 02 03")
            .unwrap()
            .output;
        assert_eq!(
            transform(DecoderOperation::ZlibDecompress, &zipped)
                .unwrap()
                .output,
            "01 02 03"
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![0; LIMIT + 1]).unwrap();
        assert!(
            transform(
                DecoderOperation::ZlibDecompress,
                &hex(&encoder.finish().unwrap())
            )
            .is_err()
        );
    }
}
