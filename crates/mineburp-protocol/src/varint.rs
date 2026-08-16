#![allow(clippy::cast_possible_truncation)]

use bytes::{BufMut, BytesMut};

use crate::ProtocolError;

pub fn decode_var_i32(input: &[u8]) -> Result<Option<(i32, usize)>, ProtocolError> {
    let mut value = 0_u32;
    for index in 0..5 {
        let Some(byte) = input.get(index).copied() else {
            return Ok(None);
        };
        value |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(Some((value.cast_signed(), index + 1)));
        }
    }
    Err(ProtocolError::VarIntTooLong)
}

pub fn decode_var_i64(input: &[u8]) -> Result<Option<(i64, usize)>, ProtocolError> {
    let mut value = 0_u64;
    for index in 0..10 {
        let Some(byte) = input.get(index).copied() else {
            return Ok(None);
        };
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(Some((value.cast_signed(), index + 1)));
        }
    }
    Err(ProtocolError::VarLongTooLong)
}

#[must_use]
pub fn encode_var_i32(value: i32) -> BytesMut {
    let mut output = BytesMut::with_capacity(5);
    let mut value = value.cast_unsigned();
    loop {
        if value & !0x7f == 0 {
            output.put_u8(value as u8);
            return output;
        }
        output.put_u8(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
}

#[must_use]
pub fn encode_var_i64(value: i64) -> BytesMut {
    let mut output = BytesMut::with_capacity(10);
    let mut value = value.cast_unsigned();
    loop {
        if value & !0x7f == 0 {
            output.put_u8(value as u8);
            return output;
        }
        output.put_u8(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_known_values_round_trip() {
        for value in [0, 1, 127, 128, 255, 2_097_151, i32::MAX, -1, i32::MIN] {
            let encoded = encode_var_i32(value);
            let decoded = decode_var_i32(&encoded).unwrap().unwrap();
            assert_eq!(decoded, (value, encoded.len()));
        }
    }

    #[test]
    fn partial_varint_waits_for_more_data() {
        assert_eq!(decode_var_i32(&[0x80]).unwrap(), None);
    }
}
