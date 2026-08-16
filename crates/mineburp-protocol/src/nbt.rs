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
const MAX_STRING: usize = 1 << 20;

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
    #[error("invalid UTF-8 in an NBT string")]
    InvalidUtf8,
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
    let nameless = read_payload(tag, input, 1, 0);
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
    nameless.or(named)
}

fn read_named_root(tag: u8, input: &[u8]) -> Result<(Value, usize), NbtError> {
    let name_length = usize::from(u16::from_be_bytes(fixed(input, 1)?));
    let start = 3usize.checked_add(name_length).ok_or(NbtError::Truncated)?;
    if start > input.len() {
        return Err(NbtError::Truncated);
    }
    read_payload(tag, input, start, 0)
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
) -> Result<(Value, usize), NbtError> {
    if depth > MAX_DEPTH {
        return Err(NbtError::TooDeep);
    }
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
            let mut cursor = offset + 5;
            let mut items = Vec::with_capacity(length.min(4_096));
            for _ in 0..length {
                let (value, next) = read_payload(item_tag, input, cursor, depth + 1)?;
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
                let (value, next) = read_payload(field_tag, input, after_name, depth + 1)?;
                object.insert(name, value);
                cursor = next;
            }
        }
        11 | 12 => {
            let width = if tag == 11 { 4 } else { 8 };
            let length = read_length(input, offset)?;
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
    let length = u16::from_be_bytes(fixed(input, offset)?) as usize;
    if length > MAX_STRING {
        return Err(NbtError::TooLarge(length));
    }
    let start = offset + 2;
    let end = start.checked_add(length).ok_or(NbtError::Truncated)?;
    let bytes = input.get(start..end).ok_or(NbtError::Truncated)?;
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| NbtError::InvalidUtf8)?;
    Ok((text, end))
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
}
