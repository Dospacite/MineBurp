//! Minimal network-NBT reader.
//!
//! Modern Minecraft sends chat, disconnect reasons, and other text components as
//! NBT rather than JSON, so the inspector needs just enough of the format to
//! turn a component into readable text. This is a reader only: nothing here
//! writes NBT back onto the wire.

use serde_json::{Map, Value};
use thiserror::Error;

const MAX_DEPTH: usize = 32;
const MAX_COLLECTION: usize = 1 << 20;
/// Total values one read may produce, counting every list and array element.
/// Like vanilla's `NbtAccounter` it bounds the work a payload can demand no
/// matter how its nesting is arranged.
const MAX_NODES: usize = 1 << 20;

#[derive(Debug, Error)]
pub enum NbtError {
    #[error("truncated NBT payload")]
    Truncated,
    #[error("unknown NBT tag {0}")]
    UnknownTag(u8),
    #[error("NBT nesting exceeds the decoding limit")]
    TooDeep,
    #[error("NBT collection length {0} exceeds the decoding limit")]
    TooLarge(usize),
    #[error("invalid modified UTF-8 in an NBT string")]
    InvalidUtf8,
    #[error("NBT list of TAG_End cannot hold {0} elements")]
    InvalidList(usize),
    #[error("NBT payload exceeds the decoding budget")]
    BudgetExceeded,
}

/// Remaining node allowance for one read.
struct Budget(usize);

impl Budget {
    fn spend(&mut self, nodes: usize) -> Result<(), NbtError> {
        self.0 = self.0.checked_sub(nodes).ok_or(NbtError::BudgetExceeded)?;
        Ok(())
    }
}

/// Reads one NBT value and reports how many bytes it consumed.
///
/// Both the 1.20.2+ nameless network form and the older named root form are
/// accepted, because passive capture can hold either.
pub fn read_nbt(input: &[u8]) -> Result<(Value, usize), NbtError> {
    let tag = *input.first().ok_or(NbtError::Truncated)?;
    if tag == 0 {
        return Ok((Value::Null, 1));
    }
    let nameless = read_payload(tag, input, 1, 0, &mut Budget(MAX_NODES));
    // An empty root name makes the two forms ambiguous, so prefer whichever
    // parse accounts for the whole slice before falling back to either.
    if let Ok((_, consumed)) = &nameless
        && *consumed == input.len()
    {
        return nameless;
    }
    let named = read_named_root(tag, input);
    if let Ok((_, consumed)) = &named
        && *consumed == input.len()
    {
        return named;
    }
    match (nameless, named) {
        (Ok(value), _) | (Err(_), Ok(value)) => Ok(value),
        // The nameless form is the modern one, so its error is the useful one.
        (Err(error), Err(_)) => Err(error),
    }
}

fn read_named_root(tag: u8, input: &[u8]) -> Result<(Value, usize), NbtError> {
    let name_length = usize::from(u16::from_be_bytes(fixed(input, 1)?));
    let start = 3usize.checked_add(name_length).ok_or(NbtError::Truncated)?;
    if start > input.len() {
        return Err(NbtError::Truncated);
    }
    read_payload(tag, input, start, 0, &mut Budget(MAX_NODES))
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per NBT tag reads clearest flat"
)]
fn read_payload(
    tag: u8,
    input: &[u8],
    offset: usize,
    depth: usize,
    budget: &mut Budget,
) -> Result<(Value, usize), NbtError> {
    if depth > MAX_DEPTH {
        return Err(NbtError::TooDeep);
    }
    budget.spend(1)?;
    match tag {
        0 => Ok((Value::Null, offset)),
        1 => Ok((
            Value::from(i8::from_be_bytes(fixed(input, offset)?)),
            offset + 1,
        )),
        2 => Ok((
            Value::from(i16::from_be_bytes(fixed(input, offset)?)),
            offset + 2,
        )),
        3 => Ok((
            Value::from(i32::from_be_bytes(fixed(input, offset)?)),
            offset + 4,
        )),
        4 => Ok((
            Value::from(i64::from_be_bytes(fixed(input, offset)?)),
            offset + 8,
        )),
        5 => Ok((
            Value::from(f32::from_be_bytes(fixed(input, offset)?)),
            offset + 4,
        )),
        6 => Ok((
            Value::from(f64::from_be_bytes(fixed(input, offset)?)),
            offset + 8,
        )),
        7 => {
            let length = read_length(input, offset)?;
            let end = offset
                .checked_add(4)
                .and_then(|start| start.checked_add(length))
                .ok_or(NbtError::Truncated)?;
            let bytes = input.get(offset + 4..end).ok_or(NbtError::Truncated)?;
            budget.spend(length)?;
            Ok((
                Value::Array(
                    bytes
                        .iter()
                        .map(|byte| Value::from(i8::from_be_bytes([*byte])))
                        .collect(),
                ),
                end,
            ))
        }
        8 => {
            let (text, end) = read_string(input, offset)?;
            Ok((Value::String(text), end))
        }
        9 => {
            let item_tag = *input.get(offset).ok_or(NbtError::Truncated)?;
            let length = read_length(input, offset + 1)?;
            // An element of TAG_End occupies no bytes, so a list of them could
            // claim a million values from five bytes; vanilla rejects it too.
            if item_tag == 0 && length > 0 {
                return Err(NbtError::InvalidList(length));
            }
            let mut cursor = offset + 5;
            let mut items = Vec::with_capacity(length.min(4_096));
            for _ in 0..length {
                let (value, next) = read_payload(item_tag, input, cursor, depth + 1, budget)?;
                items.push(value);
                cursor = next;
            }
            Ok((Value::Array(items), cursor))
        }
        10 => {
            let mut object = Map::new();
            let mut cursor = offset;
            loop {
                let field_tag = *input.get(cursor).ok_or(NbtError::Truncated)?;
                if field_tag == 0 {
                    return Ok((Value::Object(object), cursor + 1));
                }
                let (name, after_name) = read_string(input, cursor + 1)?;
                let (value, next) = read_payload(field_tag, input, after_name, depth + 1, budget)?;
                object.insert(name, value);
                cursor = next;
            }
        }
        11 | 12 => {
            let width = if tag == 11 { 4 } else { 8 };
            let length = read_length(input, offset)?;
            let end = length
                .checked_mul(width)
                .and_then(|bytes| bytes.checked_add(offset + 4))
                .ok_or(NbtError::Truncated)?;
            if end > input.len() {
                return Err(NbtError::Truncated);
            }
            budget.spend(length)?;
            let mut cursor = offset + 4;
            let mut items = Vec::with_capacity(length.min(4_096));
            for _ in 0..length {
                let value = if width == 4 {
                    Value::from(i32::from_be_bytes(fixed(input, cursor)?))
                } else {
                    Value::from(i64::from_be_bytes(fixed(input, cursor)?))
                };
                items.push(value);
                cursor += width;
            }
            Ok((Value::Array(items), cursor))
        }
        other => Err(NbtError::UnknownTag(other)),
    }
}

fn fixed<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], NbtError> {
    let end = offset.checked_add(N).ok_or(NbtError::Truncated)?;
    input
        .get(offset..end)
        .ok_or(NbtError::Truncated)?
        .try_into()
        .map_err(|_| NbtError::Truncated)
}

fn read_length(input: &[u8], offset: usize) -> Result<usize, NbtError> {
    let value = i32::from_be_bytes(fixed(input, offset)?);
    let length = usize::try_from(value).map_err(|_| NbtError::Truncated)?;
    if length > MAX_COLLECTION {
        return Err(NbtError::TooLarge(length));
    }
    Ok(length)
}

fn read_string(input: &[u8], offset: usize) -> Result<(String, usize), NbtError> {
    let length = usize::from(u16::from_be_bytes(fixed(input, offset)?));
    let start = offset + 2;
    let end = start.checked_add(length).ok_or(NbtError::Truncated)?;
    let bytes = input.get(start..end).ok_or(NbtError::Truncated)?;
    Ok((decode_modified_utf8(bytes)?, end))
}

/// Decodes Java's modified UTF-8, which is what `DataOutput#writeUTF` puts in
/// NBT: NUL is the two bytes `C0 80`, and a character outside the BMP — any
/// emoji — is a surrogate pair written as two three-byte sequences rather than
/// one four-byte sequence. Plain ASCII, the common case, is borrowed as is.
fn decode_modified_utf8(bytes: &[u8]) -> Result<String, NbtError> {
    if bytes.is_ascii() {
        return Ok(String::from_utf8_lossy(bytes).into_owned());
    }
    let mut units = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let continuation = |index: usize| -> Result<u16, NbtError> {
        match bytes.get(index) {
            Some(byte) if byte & 0xc0 == 0x80 => Ok(u16::from(byte & 0x3f)),
            _ => Err(NbtError::InvalidUtf8),
        }
    };
    while let Some(&byte) = bytes.get(index) {
        let unit = match byte {
            0x00..=0x7f => {
                index += 1;
                u16::from(byte)
            }
            0xc0..=0xdf => {
                let unit = (u16::from(byte & 0x1f) << 6) | continuation(index + 1)?;
                index += 2;
                unit
            }
            0xe0..=0xef => {
                let unit = (u16::from(byte & 0x0f) << 12)
                    | (continuation(index + 1)? << 6)
                    | continuation(index + 2)?;
                index += 3;
                unit
            }
            _ => return Err(NbtError::InvalidUtf8),
        };
        units.push(unit);
    }
    // Java strings may hold an unpaired surrogate; show it rather than fail.
    Ok(String::from_utf16_lossy(&units))
}

/// Flattens a chat component — NBT-derived or JSON — into readable plain text.
pub fn component_to_text(value: &Value) -> String {
    let mut output = String::new();
    write_component(value, &mut output, 0);
    output.trim().to_owned()
}

fn write_component(value: &Value, output: &mut String, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::String(text) => output.push_str(text),
        Value::Number(number) => output.push_str(&number.to_string()),
        Value::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
        Value::Array(items) => {
            for item in items {
                write_component(item, output, depth + 1);
            }
        }
        Value::Object(object) => {
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                output.push_str(text);
            }
            if let Some(key) = object.get("translate").and_then(Value::as_str) {
                let arguments = object.get("with").and_then(Value::as_array);
                output.push_str(&translate(key, arguments, depth));
            }
            for nested in ["extra", "with"] {
                if nested == "with" && object.contains_key("translate") {
                    continue;
                }
                if let Some(items) = object.get(nested).and_then(Value::as_array) {
                    for item in items {
                        write_component(item, output, depth + 1);
                    }
                }
            }
        }
        Value::Null => {}
    }
}

/// Renders a translation key with its arguments substituted positionally.
///
/// The client-side language file is not available here, so `%s` ordering is
/// reproduced generically: `key(arg, arg)` still shows the operator what the
/// server actually sent.
fn translate(key: &str, arguments: Option<&Vec<Value>>, depth: usize) -> String {
    let rendered: Vec<String> = arguments
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let mut text = String::new();
                    write_component(item, &mut text, depth + 1);
                    text
                })
                .collect()
        })
        .unwrap_or_default();
    if rendered.is_empty() {
        return key.to_owned();
    }
    // `chat.type.text` is the common "<player> message" shape; render it that
    // way so a captured chat line reads like the client shows it.
    if key.starts_with("chat.type") && rendered.len() >= 2 {
        return format!("<{}> {}", rendered[0], rendered[1]);
    }
    format!("{key}({})", rendered.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_nameless_compound() {
        // { text: "hi" }
        let bytes = [
            0x0a, 0x08, 0x00, 0x04, b't', b'e', b'x', b't', 0x00, 0x02, b'h', b'i', 0x00,
        ];
        let (value, consumed) = read_nbt(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(component_to_text(&value), "hi");
    }

    #[test]
    fn renders_a_chat_translation() {
        let value = serde_json::json!({
            "translate": "chat.type.text",
            "with": ["Notch", {"text": "hello world"}]
        });
        assert_eq!(component_to_text(&value), "<Notch> hello world");
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(read_nbt(&[0x0a, 0x08, 0x00, 0x04, b't']).is_err());
    }

    #[test]
    fn a_list_of_tag_end_with_elements_is_rejected() {
        // A list of 40 lists, each claiming a million TAG_End elements: the
        // shape that used to allocate gigabytes from a couple hundred bytes.
        let mut bytes = vec![0x09, 0x09];
        bytes.extend_from_slice(&40_i32.to_be_bytes());
        for _ in 0..40 {
            bytes.push(0x00);
            bytes.extend_from_slice(&1_000_000_i32.to_be_bytes());
        }
        let started = std::time::Instant::now();
        assert!(matches!(read_nbt(&bytes), Err(NbtError::InvalidList(_))));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // An empty list of TAG_End is how vanilla writes an empty list.
        let empty = [0x09, 0x00, 0, 0, 0, 0];
        assert_eq!(read_nbt(&empty).unwrap(), (Value::Array(vec![]), 6));
    }

    #[test]
    fn the_node_budget_bounds_array_payloads() {
        let mut budget = Budget(4);
        let mut bytes = vec![];
        bytes.extend_from_slice(&8_i32.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        assert!(matches!(
            read_payload(7, &bytes, 0, 0, &mut budget),
            Err(NbtError::BudgetExceeded)
        ));
    }

    #[test]
    fn an_int_array_longer_than_its_input_is_truncated_not_allocated() {
        let mut bytes = vec![0x0b];
        bytes.extend_from_slice(&1_000_000_i32.to_be_bytes());
        assert!(matches!(read_nbt(&bytes), Err(NbtError::Truncated)));
    }

    #[test]
    fn strings_are_modified_utf8() {
        // "a", NUL as C0 80, then U+1F600 as a surrogate pair (ED A0 BD, ED B8 80).
        let encoded = [b'a', 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80];
        let mut bytes = vec![0x08];
        bytes.extend_from_slice(&u16::try_from(encoded.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&encoded);
        let (value, consumed) = read_nbt(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(value, Value::String("a\0\u{1F600}".into()));
        // A standard four-byte sequence is not modified UTF-8.
        let mut four = vec![0x08, 0x00, 0x04];
        four.extend_from_slice("\u{1F600}".as_bytes());
        assert!(read_nbt(&four).is_err());
    }
}
