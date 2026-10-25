//! A cursor over a packet body.
//!
//! Every read is bounds checked and returns `None` rather than panicking, which
//! is what lets a decoder be written as a straight sequence of reads: the first
//! field that does not fit ends the attempt and the packet falls through to the
//! next decoder.

use crate::varint::{decode_var_i32, decode_var_i64};

/// Hard ceiling on any string's byte length, whatever budget a field claims.
const MAX_STRING_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    #[must_use]
    pub const fn position(&self) -> usize {
        self.cursor
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.cursor)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        self.input.get(self.cursor..).unwrap_or_default()
    }

    /// Consumes `count` bytes.
    pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.cursor.checked_add(count)?;
        let slice = self.input.get(self.cursor..end)?;
        self.cursor = end;
        Some(slice)
    }

    pub fn var_i32(&mut self) -> Option<i32> {
        let (value, length) = decode_var_i32(self.rest()).ok().flatten()?;
        self.cursor += length;
        Some(value)
    }

    pub fn var_i64(&mut self) -> Option<i64> {
        let (value, length) = decode_var_i64(self.rest()).ok().flatten()?;
        self.cursor += length;
        Some(value)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|slice| slice[0])
    }

    pub fn i8(&mut self) -> Option<i8> {
        self.u8().map(u8::cast_signed)
    }

    pub fn i16(&mut self) -> Option<i16> {
        Some(i16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    pub fn i32(&mut self) -> Option<i32> {
        Some(i32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    pub fn f32(&mut self) -> Option<f32> {
        Some(f32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    pub fn f64(&mut self) -> Option<f64> {
        Some(f64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A protocol boolean: strictly `0` or `1`, which is a useful part of a
    /// decoder's evidence rather than a formality.
    pub fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// A length-prefixed UTF-8 string, rejected when it exceeds the character
    /// budget the protocol gives that field.
    ///
    /// The rule is vanilla's `readUtf`: at most three bytes per character on
    /// the wire, and the budget counts UTF-16 code units, so an emoji spends
    /// two of them.
    pub fn string(&mut self, max_characters: usize) -> Option<String> {
        let start = self.cursor;
        let length = usize::try_from(self.var_i32()?).ok()?;
        if length > MAX_STRING_BYTES || length > max_characters.saturating_mul(3) {
            self.cursor = start;
            return None;
        }
        let Some(bytes) = self.take(length) else {
            self.cursor = start;
            return None;
        };
        let Ok(value) = std::str::from_utf8(bytes) else {
            self.cursor = start;
            return None;
        };
        if value.encode_utf16().count() > max_characters {
            self.cursor = start;
            return None;
        }
        Some(value.to_owned())
    }

    /// A namespaced identifier such as `minecraft:brand`.
    pub fn identifier(&mut self) -> Option<String> {
        let start = self.cursor;
        let value = self.string(256)?;
        if is_identifier(&value) {
            return Some(value);
        }
        self.cursor = start;
        None
    }

    pub fn uuid(&mut self) -> Option<uuid::Uuid> {
        let bytes: [u8; 16] = self.take(16)?.try_into().ok()?;
        Some(uuid::Uuid::from_bytes(bytes))
    }

    /// A `VarInt`-prefixed byte array.
    pub fn byte_array(&mut self) -> Option<&'a [u8]> {
        let start = self.cursor;
        let length = usize::try_from(self.var_i32()?).ok()?;
        let Some(bytes) = self.take(length) else {
            self.cursor = start;
            return None;
        };
        Some(bytes)
    }

    /// Reads a `VarInt` length prefix whose value stays inside `limit`, which is
    /// what stops a random four bytes from claiming a million-element array.
    pub fn counted(&mut self, limit: i32) -> Option<usize> {
        let count = self.var_i32()?;
        if !(0..=limit).contains(&count) {
            return None;
        }
        usize::try_from(count).ok()
    }
}

/// Decodes Minecraft's packed block position, rejecting coordinates outside a
/// world's actual limits.
#[must_use]
pub fn unpack_position(value: i64) -> Option<(i32, i32, i32)> {
    const HORIZONTAL_LIMIT: i32 = 30_000_000;
    let x = i32::try_from(value >> 38).ok()?;
    let y = i32::try_from((value << 52) >> 52).ok()?;
    let z = i32::try_from((value << 26) >> 38).ok()?;
    if x.abs() > HORIZONTAL_LIMIT || z.abs() > HORIZONTAL_LIMIT || !(-512..=1_024).contains(&y) {
        return None;
    }
    Some((x, y, z))
}

#[must_use]
pub fn is_identifier(value: &str) -> bool {
    let Some((namespace, path)) = value.split_once(':') else {
        return false;
    };
    !namespace.is_empty()
        && !path.is_empty()
        && namespace.len() <= 64
        && namespace.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-.".contains(&byte)
        })
        && path.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-./".contains(&byte)
        })
}

/// True when a coordinate is a number a client could actually be standing at.
#[must_use]
pub fn plausible_coordinate(value: f64) -> bool {
    value.is_finite() && value.abs() <= 30_000_000.0
}

#[must_use]
pub fn plausible_altitude(value: f64) -> bool {
    value.is_finite() && (-2_048.0..=2_048.0).contains(&value)
}

#[must_use]
pub fn plausible_pitch(value: f32) -> bool {
    value.is_finite() && (-90.5..=90.5).contains(&value)
}

#[must_use]
pub fn plausible_yaw(value: f32) -> bool {
    value.is_finite() && value.abs() <= 1_080.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_that_does_not_fit_leaves_the_cursor_alone() {
        let mut reader = Reader::new(&[0x40, b'a', b'b']);
        assert_eq!(reader.string(64), None);
        assert_eq!(
            reader.position(),
            0,
            "a failed read must not consume the length prefix"
        );
    }

    #[test]
    fn string_budgets_count_utf16_units() {
        let emoji = "\u{1F600}";
        let mut bytes = vec![4];
        bytes.extend_from_slice(emoji.as_bytes());
        assert_eq!(Reader::new(&bytes).string(2).as_deref(), Some(emoji));
        assert_eq!(
            Reader::new(&bytes).string(1),
            None,
            "one emoji is two UTF-16 units"
        );
        // Three bytes per character is the wire ceiling.
        let mut long = vec![7];
        long.extend_from_slice(b"abcdefg");
        assert_eq!(Reader::new(&long).string(2), None);
    }

    fn pack(x: i64, y: i64, z: i64) -> i64 {
        ((x & 0x3ff_ffff) << 38) | ((z & 0x3ff_ffff) << 12) | (y & 0xfff)
    }

    #[test]
    fn positions_outside_a_world_are_rejected() {
        assert_eq!(unpack_position(pack(5, 64, -7)), Some((5, 64, -7)));
        assert_eq!(
            unpack_position(pack(5, 2_000, 7)),
            None,
            "no world reaches y = 2000"
        );
    }
}
