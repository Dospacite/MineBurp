//! Automatic packet rewriting.
//!
//! An edit either works on raw bytes — an offset range, a byte sequence, a
//! pattern — or on a decoded field. The field edits are the safe ones: they go
//! through [`crate::layout`], so replacing a five-character server address with
//! a twenty-character one rewrites the length prefix in front of it instead of
//! leaving a frame that decodes as garbage. The byte edits do exactly what they
//! are told, which is what makes them useful for the cases no decoder covers.

use mineburp_core::{Direction, PacketEdit, ProtocolState};
use regex::bytes::{Regex, RegexBuilder};
use serde_json::Value;

use crate::layout::{encode_field, layout_logical};

#[derive(Debug, thiserror::Error)]
pub enum RewriteError {
    #[error("`{0}` is not valid hex")]
    Hex(String),
    #[error("byte range {offset}..{end} is outside a {length} byte frame")]
    Range {
        offset: usize,
        end: usize,
        length: usize,
    },
    #[error("invalid pattern: {0}")]
    Pattern(String),
    #[error("this packet has no field named `{0}`")]
    UnknownField(String),
    #[error("{0}")]
    Encoding(String),
}

/// Applies every edit in order, returning the rewritten frame.
///
/// Each edit sees the output of the one before it, so a field edit can be
/// followed by a byte edit over the result.
pub fn apply_edits(
    state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
    logical: &[u8],
    edits: &[PacketEdit],
) -> Result<Vec<u8>, RewriteError> {
    let mut frame = logical.to_vec();
    for edit in edits {
        frame = apply_edit(state, direction, protocol_version, &frame, edit)?;
    }
    Ok(frame)
}

fn apply_edit(
    state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
    frame: &[u8],
    edit: &PacketEdit,
) -> Result<Vec<u8>, RewriteError> {
    match edit {
        PacketEdit::Frame { bytes } => parse_hex(bytes),
        PacketEdit::Range {
            offset,
            length,
            bytes,
        } => splice(frame, *offset, *length, &parse_hex(bytes)?),
        PacketEdit::Bytes { find, replace, all } => {
            let needle = parse_hex(find)?;
            Ok(replace_sequence(frame, &needle, &parse_hex(replace)?, *all))
        }
        PacketEdit::Text {
            find,
            replace,
            all,
            case_insensitive,
        } => {
            if *case_insensitive {
                let pattern = RegexBuilder::new(&regex::escape(find))
                    .case_insensitive(true)
                    .build()
                    .map_err(|error| RewriteError::Pattern(error.to_string()))?;
                return Ok(replace_pattern(&pattern, frame, replace.as_bytes(), *all));
            }
            Ok(replace_sequence(
                frame,
                find.as_bytes(),
                replace.as_bytes(),
                *all,
            ))
        }
        PacketEdit::Regex {
            pattern,
            replace,
            all,
        } => {
            let compiled =
                Regex::new(pattern).map_err(|error| RewriteError::Pattern(error.to_string()))?;
            Ok(replace_pattern(&compiled, frame, replace.as_bytes(), *all))
        }
        PacketEdit::Field { name, value } => {
            let (span, _) = find_field(state, direction, protocol_version, frame, name)?;
            let encoded = encode_field(span.kind, &Value::String(value.clone()))
                .map_err(RewriteError::Encoding)?;
            splice(frame, span.offset, span.length, &encoded)
        }
        PacketEdit::FieldReplace {
            name,
            find,
            replace,
            regex,
        } => {
            let (span, current) = find_field(state, direction, protocol_version, frame, name)?;
            let updated = if *regex {
                let compiled =
                    Regex::new(find).map_err(|error| RewriteError::Pattern(error.to_string()))?;
                String::from_utf8_lossy(&replace_pattern(
                    &compiled,
                    current.as_bytes(),
                    replace.as_bytes(),
                    true,
                ))
                .into_owned()
            } else {
                current.replace(find.as_str(), replace)
            };
            let encoded =
                encode_field(span.kind, &Value::String(updated)).map_err(RewriteError::Encoding)?;
            splice(frame, span.offset, span.length, &encoded)
        }
    }
}

/// Finds a field by name, accepting the spaced or underscored spelling.
fn find_field(
    state: ProtocolState,
    direction: Direction,
    protocol_version: Option<i32>,
    frame: &[u8],
    name: &str,
) -> Result<(crate::layout::FieldSpan, String), RewriteError> {
    let wanted = normalise(name);
    let layout = layout_logical(state, direction, frame, protocol_version);
    let span = layout
        .fields
        .into_iter()
        .find(|field| normalise(&field.name) == wanted)
        .ok_or_else(|| RewriteError::UnknownField(name.to_owned()))?;
    let current = match &span.value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    Ok((span, current))
}

fn normalise(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn splice(
    frame: &[u8],
    offset: usize,
    length: usize,
    replacement: &[u8],
) -> Result<Vec<u8>, RewriteError> {
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= frame.len())
        .ok_or(RewriteError::Range {
            offset,
            end: offset.saturating_add(length),
            length: frame.len(),
        })?;
    let mut output = Vec::with_capacity(frame.len() - length + replacement.len());
    output.extend_from_slice(&frame[..offset]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&frame[end..]);
    Ok(output)
}

fn replace_sequence(frame: &[u8], find: &[u8], replace: &[u8], all: bool) -> Vec<u8> {
    if find.is_empty() {
        return frame.to_vec();
    }
    let mut output = Vec::with_capacity(frame.len());
    let mut cursor = 0;
    while cursor <= frame.len().saturating_sub(find.len()) {
        if frame[cursor..].starts_with(find) {
            output.extend_from_slice(replace);
            cursor += find.len();
            if !all {
                break;
            }
        } else {
            output.push(frame[cursor]);
            cursor += 1;
        }
    }
    output.extend_from_slice(&frame[cursor..]);
    output
}

fn replace_pattern(pattern: &Regex, frame: &[u8], replace: &[u8], all: bool) -> Vec<u8> {
    if all {
        pattern.replace_all(frame, replace).into_owned()
    } else {
        pattern.replace(frame, replace).into_owned()
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, RewriteError> {
    let digits: String = input.chars().filter(char::is_ascii_hexdigit).collect();
    if !digits.len().is_multiple_of(2) {
        return Err(RewriteError::Hex(input.to_owned()));
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16)
                .map_err(|_| RewriteError::Hex(input.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::encode_var_i32;

    fn handshake(address: &str) -> Vec<u8> {
        let mut frame = encode_var_i32(0).to_vec();
        frame.extend_from_slice(&encode_var_i32(767));
        frame.extend_from_slice(&encode_var_i32(i32::try_from(address.len()).unwrap()));
        frame.extend_from_slice(address.as_bytes());
        frame.extend_from_slice(&25_565_u16.to_be_bytes());
        frame.extend_from_slice(&encode_var_i32(2));
        frame
    }

    fn rewrite(frame: &[u8], edit: &PacketEdit) -> Vec<u8> {
        apply_edits(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            None,
            frame,
            std::slice::from_ref(edit),
        )
        .expect("the edit applies")
    }

    #[test]
    fn a_field_edit_rewrites_the_length_prefix_with_the_value() {
        let frame = handshake("short.example");
        let edited = rewrite(
            &frame,
            &PacketEdit::Field {
                name: "server address".into(),
                value: "a-considerably-longer.example".into(),
            },
        );
        let layout = layout_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &edited,
            None,
        );
        assert_eq!(layout.fields[2].value, "a-considerably-longer.example");
        assert_eq!(
            layout.fields[4].value, 2,
            "the fields after a resized one still decode"
        );
    }

    #[test]
    fn a_field_replace_rewrites_inside_the_value() {
        let frame = handshake("mc.example.net");
        let edited = rewrite(
            &frame,
            &PacketEdit::FieldReplace {
                name: "server_address".into(),
                find: "example".into(),
                replace: "elsewhere".into(),
                regex: false,
            },
        );
        let layout = layout_logical(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            &edited,
            None,
        );
        assert_eq!(layout.fields[2].value, "mc.elsewhere.net");
    }

    #[test]
    fn byte_and_range_edits_are_exact() {
        let frame = vec![0x00, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            rewrite(
                &frame,
                &PacketEdit::Range {
                    offset: 1,
                    length: 2,
                    bytes: "cafe".into()
                }
            ),
            vec![0x00, 0xca, 0xfe, 0xbe, 0xef]
        );
        assert_eq!(
            rewrite(
                &frame,
                &PacketEdit::Bytes {
                    find: "dead".into(),
                    replace: "00".into(),
                    all: true
                }
            ),
            vec![0x00, 0x00, 0xbe, 0xef]
        );
        assert_eq!(
            rewrite(
                &frame,
                &PacketEdit::Frame {
                    bytes: "01 02".into()
                }
            ),
            vec![0x01, 0x02]
        );
    }

    #[test]
    fn text_and_regex_edits_reach_into_the_payload() {
        let frame = handshake("mc.example.net");
        let text = rewrite(
            &frame,
            &PacketEdit::Text {
                find: "example".into(),
                replace: "REDACTED".into(),
                all: true,
                case_insensitive: false,
            },
        );
        assert!(
            String::from_utf8_lossy(&text).contains("REDACTED"),
            "the literal text is replaced even though the prefix now lies"
        );

        let pattern = rewrite(
            &frame,
            &PacketEdit::Regex {
                pattern: r"[a-z]+\.net".into(),
                replace: "x.net".into(),
                all: true,
            },
        );
        assert!(String::from_utf8_lossy(&pattern).contains("x.net"));
    }

    #[test]
    fn an_unknown_field_is_reported_rather_than_guessed() {
        let error = apply_edits(
            ProtocolState::Handshake,
            Direction::ClientToServer,
            None,
            &handshake("mc.example.net"),
            &[PacketEdit::Field {
                name: "nonexistent".into(),
                value: "1".into(),
            }],
        )
        .expect_err("an unknown field must not silently do nothing");
        assert!(error.to_string().contains("nonexistent"));
    }
}
