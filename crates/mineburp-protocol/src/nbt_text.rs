//! NBT as editable JSON.
//!
//! The Repeater shows an NBT span as JSON (`{"text": "hi", "bold": 1}`) and
//! writes the edited text back as binary NBT. JSON has no byte, short, or
//! float types, so the bytes being replaced act as a type template: a value
//! under a key or index that already existed keeps its original tag type, and
//! only new values have their type inferred (whole numbers become ints,
//! decimals doubles, objects compounds, arrays lists). SNBT suffixes such as
//! `5b`, `2s`, `3L`, `1.5f` and arrays such as `[B; 1, 2]` are also accepted,
//! to force a type.
//!
//! Rendering only succeeds when the text parses back to the same value, so a
//! field that cannot be shown faithfully stays a hex field. The one
//! normalisation is an empty list's element type, which the text cannot
//! carry and the game ignores.

use std::fmt::Write as _;

const MAX_DEPTH: usize = 64;
/// A compound or list whose one-line form is longer than this is broken over
/// several lines.
const LINE_WIDTH: usize = 72;

#[derive(Debug, Clone, PartialEq)]
enum Tag {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    ByteArray(Vec<i8>),
    String(String),
    List(Vec<Tag>),
    Compound(Vec<(String, Tag)>),
    IntArray(Vec<i32>),
    LongArray(Vec<i64>),
}

impl Tag {
    fn id(&self) -> u8 {
        match self {
            Self::Byte(_) => 1,
            Self::Short(_) => 2,
            Self::Int(_) => 3,
            Self::Long(_) => 4,
            Self::Float(_) => 5,
            Self::Double(_) => 6,
            Self::ByteArray(_) => 7,
            Self::String(_) => 8,
            Self::List(_) => 9,
            Self::Compound(_) => 10,
            Self::IntArray(_) => 11,
            Self::LongArray(_) => 12,
        }
    }
}

/// A decoded root: its name (named form only) and value (`None` for `TAG_End`).
struct Root {
    name: Option<String>,
    value: Option<Tag>,
}

fn read_root(bytes: &[u8], named: bool) -> Option<Root> {
    let mut reader = Reader {
        input: bytes,
        position: 0,
    };
    let tag = reader.u8().ok()?;
    if tag == 0 {
        return (bytes.len() == 1).then_some(Root {
            name: None,
            value: None,
        });
    }
    let name = if named {
        Some(reader.string().ok()?)
    } else {
        None
    };
    let value = reader.payload(tag, 0).ok()?;
    (reader.position == bytes.len()).then_some(Root {
        name,
        value: Some(value),
    })
}

fn write_root(root: &Root) -> Result<Vec<u8>, String> {
    let Some(value) = &root.value else {
        return Ok(vec![0]);
    };
    let mut output = vec![value.id()];
    if let Some(name) = &root.name {
        write_string(&mut output, name)?;
    }
    write_payload(&mut output, value)?;
    Ok(output)
}

/// Renders one binary NBT value as JSON text.
///
/// `named` is the pre-1.20.2 form, whose root carries a name; a non-empty
/// name is written as a `"name": value` prefix. A lone `TAG_End` (an absent
/// optional value) renders as empty text. Returns `None` when the bytes are
/// not exactly one NBT value or would not survive the round trip.
pub(crate) fn to_text(bytes: &[u8], named: bool) -> Option<String> {
    let root = read_root(bytes, named)?;
    let Some(value) = &root.value else {
        return Some(String::new());
    };
    let mut text = String::new();
    if let Some(name) = root.name.as_deref().filter(|name| !name.is_empty()) {
        write_quoted(&mut text, name);
        text.push_str(": ");
    }
    write_tag(&mut text, value, 0);
    let expected = write_root(&root).ok()?;
    (from_text(&text, named, Some(bytes)).ok()? == expected).then_some(text)
}

/// Parses JSON (or SNBT) text and writes it as binary NBT, the inverse of
/// [`to_text`]. `original` is the NBT being replaced, used as the type
/// template; without it every type is inferred.
pub(crate) fn from_text(
    text: &str,
    named: bool,
    original: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let template = original.and_then(|bytes| read_root(bytes, named));
    let mut parser = Parser { text, position: 0 };
    parser.whitespace();
    if parser.at_end() {
        return Ok(vec![0]);
    }
    let name = if named { parser.root_name() } else { None };
    let loose = parser.value(0)?;
    parser.whitespace();
    if !parser.at_end() {
        return Err(parser.error("unexpected text after the value"));
    }
    let value = resolve(
        loose,
        template.as_ref().and_then(|root| root.value.as_ref()),
    )?;
    write_root(&Root {
        // A named root keeps its name unless the text gives a new one.
        name: named.then(|| {
            name.or_else(|| template.and_then(|root| root.name))
                .unwrap_or_default()
        }),
        value: Some(value),
    })
}

// --- binary reading ---

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], ()> {
        let end = self.position.checked_add(count).ok_or(())?;
        let bytes = self.input.get(self.position..end).ok_or(())?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ()> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    fn u8(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }

    /// A collection length, refused when the bytes left cannot hold it.
    fn length(&mut self, width: usize) -> Result<usize, ()> {
        let length = usize::try_from(i32::from_be_bytes(self.array()?)).map_err(|_| ())?;
        if length.saturating_mul(width) > self.input.len() - self.position {
            return Err(());
        }
        Ok(length)
    }

    fn string(&mut self) -> Result<String, ()> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        decode_modified_utf8(self.take(length)?)
    }

    fn payload(&mut self, tag: u8, depth: usize) -> Result<Tag, ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        Ok(match tag {
            1 => Tag::Byte(i8::from_be_bytes(self.array()?)),
            2 => Tag::Short(i16::from_be_bytes(self.array()?)),
            3 => Tag::Int(i32::from_be_bytes(self.array()?)),
            4 => Tag::Long(i64::from_be_bytes(self.array()?)),
            5 => Tag::Float(f32::from_be_bytes(self.array()?)),
            6 => Tag::Double(f64::from_be_bytes(self.array()?)),
            7 => {
                let length = self.length(1)?;
                Tag::ByteArray(
                    self.take(length)?
                        .iter()
                        .map(|byte| byte.cast_signed())
                        .collect(),
                )
            }
            8 => Tag::String(self.string()?),
            9 => {
                let item = self.u8()?;
                let length = self.length(1)?;
                if item == 0 && length > 0 {
                    return Err(());
                }
                let mut items = Vec::with_capacity(length.min(1_024));
                for _ in 0..length {
                    items.push(self.payload(item, depth + 1)?);
                }
                Tag::List(items)
            }
            10 => {
                let mut entries = Vec::new();
                loop {
                    let field = self.u8()?;
                    if field == 0 {
                        break;
                    }
                    let name = self.string()?;
                    entries.push((name, self.payload(field, depth + 1)?));
                }
                Tag::Compound(entries)
            }
            11 => {
                let length = self.length(4)?;
                Tag::IntArray(
                    (0..length)
                        .map(|_| self.array().map(i32::from_be_bytes))
                        .collect::<Result<_, _>>()?,
                )
            }
            12 => {
                let length = self.length(8)?;
                Tag::LongArray(
                    (0..length)
                        .map(|_| self.array().map(i64::from_be_bytes))
                        .collect::<Result<_, _>>()?,
                )
            }
            _ => return Err(()),
        })
    }
}

/// Java's modified UTF-8, strictly: a raw NUL or an overlong form would be
/// written back differently, so either makes the string undecodable here.
fn decode_modified_utf8(bytes: &[u8]) -> Result<String, ()> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        let continuation = |offset: usize| -> Result<u16, ()> {
            let byte = *bytes.get(index + offset).ok_or(())?;
            if byte & 0xc0 != 0x80 {
                return Err(());
            }
            Ok(u16::from(byte & 0x3f))
        };
        if first == 0 {
            return Err(());
        } else if first < 0x80 {
            units.push(u16::from(first));
            index += 1;
        } else if first & 0xe0 == 0xc0 {
            let unit = (u16::from(first & 0x1f) << 6) | continuation(1)?;
            if unit != 0 && unit < 0x80 {
                return Err(());
            }
            units.push(unit);
            index += 2;
        } else if first & 0xf0 == 0xe0 {
            let unit = (u16::from(first & 0x0f) << 12) | (continuation(1)? << 6) | continuation(2)?;
            if unit < 0x800 {
                return Err(());
            }
            units.push(unit);
            index += 3;
        } else {
            return Err(());
        }
    }
    String::from_utf16(&units).map_err(|_| ())
}

// --- binary writing ---

fn write_string(output: &mut Vec<u8>, text: &str) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(text.len());
    for unit in text.encode_utf16() {
        match unit {
            0x01..=0x7f => bytes.push(u8::try_from(unit).unwrap_or_default()),
            0 | 0x80..=0x7ff => {
                bytes.push(0xc0 | u8::try_from(unit >> 6).unwrap_or_default());
                bytes.push(0x80 | u8::try_from(unit & 0x3f).unwrap_or_default());
            }
            _ => {
                bytes.push(0xe0 | u8::try_from(unit >> 12).unwrap_or_default());
                bytes.push(0x80 | u8::try_from((unit >> 6) & 0x3f).unwrap_or_default());
                bytes.push(0x80 | u8::try_from(unit & 0x3f).unwrap_or_default());
            }
        }
    }
    let length =
        u16::try_from(bytes.len()).map_err(|_| "an NBT string is longer than 65535 bytes")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&bytes);
    Ok(())
}

fn write_length(output: &mut Vec<u8>, length: usize) -> Result<(), String> {
    let length = i32::try_from(length).map_err(|_| "an NBT collection is too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn write_payload(output: &mut Vec<u8>, tag: &Tag) -> Result<(), String> {
    match tag {
        Tag::Byte(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::Short(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::Int(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::Long(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::Float(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::Double(value) => output.extend_from_slice(&value.to_be_bytes()),
        Tag::ByteArray(values) => {
            write_length(output, values.len())?;
            output.extend(values.iter().map(|value| value.cast_unsigned()));
        }
        Tag::String(text) => write_string(output, text)?,
        Tag::List(values) => {
            output.push(values.first().map_or(0, Tag::id));
            write_length(output, values.len())?;
            for value in values {
                write_payload(output, value)?;
            }
        }
        Tag::Compound(entries) => {
            for (name, value) in entries {
                output.push(value.id());
                write_string(output, name)?;
                write_payload(output, value)?;
            }
            output.push(0);
        }
        Tag::IntArray(values) => {
            write_length(output, values.len())?;
            for value in values {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
        Tag::LongArray(values) => {
            write_length(output, values.len())?;
            for value in values {
                output.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
    Ok(())
}

// --- text writing ---

fn write_quoted(output: &mut String, text: &str) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

fn write_float(output: &mut String, value: f64, debug: &str) {
    if value.is_nan() {
        output.push_str("NaN");
    } else if value.is_infinite() {
        output.push_str(if value > 0.0 { "Infinity" } else { "-Infinity" });
    } else {
        output.push_str(debug);
    }
}

fn scalar(tag: &Tag) -> bool {
    !matches!(tag, Tag::List(_) | Tag::Compound(_))
}

fn write_numbers<T: std::fmt::Display>(output: &mut String, values: &[T]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        let _ = write!(output, "{value}");
    }
    output.push(']');
}

fn write_compact(output: &mut String, tag: &Tag) {
    match tag {
        Tag::Byte(value) => {
            let _ = write!(output, "{value}");
        }
        Tag::Short(value) => {
            let _ = write!(output, "{value}");
        }
        Tag::Int(value) => {
            let _ = write!(output, "{value}");
        }
        Tag::Long(value) => {
            let _ = write!(output, "{value}");
        }
        Tag::Float(value) => write_float(output, f64::from(*value), &format!("{value:?}")),
        Tag::Double(value) => write_float(output, *value, &format!("{value:?}")),
        Tag::ByteArray(values) => write_numbers(output, values),
        Tag::IntArray(values) => write_numbers(output, values),
        Tag::LongArray(values) => write_numbers(output, values),
        Tag::String(text) => write_quoted(output, text),
        Tag::List(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push_str(", ");
                }
                write_compact(output, value);
            }
            output.push(']');
        }
        Tag::Compound(entries) => {
            output.push('{');
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push_str(", ");
                }
                write_quoted(output, key);
                output.push_str(": ");
                write_compact(output, value);
            }
            output.push('}');
        }
    }
}

/// Writes a value one line per entry once it no longer fits on one line.
/// Lists of plain values stay on one line however long they get.
fn write_tag(output: &mut String, tag: &Tag, indent: usize) {
    let mut compact = String::new();
    write_compact(&mut compact, tag);
    let fits = compact.len() + indent * 2 <= LINE_WIDTH;
    let breakable = match tag {
        Tag::Compound(entries) => !entries.is_empty(),
        Tag::List(values) => !values.iter().all(scalar),
        _ => false,
    };
    if fits || !breakable {
        output.push_str(&compact);
        return;
    }
    let pad = "  ".repeat(indent + 1);
    match tag {
        Tag::Compound(entries) => {
            output.push_str("{\n");
            for (index, (key, value)) in entries.iter().enumerate() {
                output.push_str(&pad);
                write_quoted(output, key);
                output.push_str(": ");
                write_tag(output, value, indent + 1);
                output.push_str(if index + 1 < entries.len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            output.push_str(&"  ".repeat(indent));
            output.push('}');
        }
        Tag::List(values) => {
            output.push_str("[\n");
            for (index, value) in values.iter().enumerate() {
                output.push_str(&pad);
                write_tag(output, value, indent + 1);
                output.push_str(if index + 1 < values.len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            output.push_str(&"  ".repeat(indent));
            output.push(']');
        }
        _ => output.push_str(&compact),
    }
}

// --- text parsing ---

/// A parsed value whose NBT type may still depend on the template.
#[derive(Debug)]
enum Loose {
    /// A number without a type suffix. `whole` is set when it has no
    /// fraction or exponent.
    Number {
        whole: Option<i64>,
        float: f64,
        text: String,
    },
    Bool(bool),
    String(String),
    List(Vec<Loose>),
    Compound(Vec<(String, Loose)>),
    /// A suffixed number or a typed array: the type was given explicitly.
    Typed(Tag),
}

struct Parser<'a> {
    text: &'a str,
    position: usize,
}

fn bare_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || "_-.+".contains(character)
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.text[self.position..]
    }

    fn at_end(&self) -> bool {
        self.position >= self.text.len()
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn whitespace(&mut self) {
        let rest = self.rest();
        self.position += rest.len() - rest.trim_start().len();
    }

    fn error(&self, message: &str) -> String {
        let consumed = &self.text[..self.position];
        let line = consumed.matches('\n').count() + 1;
        let column = consumed
            .rsplit('\n')
            .next()
            .map_or(0, |tail| tail.chars().count())
            + 1;
        format!("NBT line {line}, column {column}: {message}")
    }

    fn expect(&mut self, character: char) -> Result<(), String> {
        self.whitespace();
        if self.peek() == Some(character) {
            self.position += character.len_utf8();
            Ok(())
        } else {
            Err(self.error(&format!("expected `{character}`")))
        }
    }

    /// A `"name":` prefix on a named root, if there is one.
    fn root_name(&mut self) -> Option<String> {
        let start = self.position;
        let name = match self.peek() {
            Some('"' | '\'') => self.quoted().ok(),
            _ => Some(self.bare_token().to_owned()).filter(|token| !token.is_empty()),
        };
        self.whitespace();
        if name.is_some() && self.peek() == Some(':') {
            self.position += 1;
            return name;
        }
        self.position = start;
        None
    }

    fn bare_token(&mut self) -> &str {
        let start = self.position;
        let length = self
            .rest()
            .find(|character: char| !bare_character(character))
            .unwrap_or(self.text.len() - start);
        self.position += length;
        &self.text[start..self.position]
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.rest().get(..4).unwrap_or_default();
        let code = u32::from_str_radix(digits, 16)
            .map_err(|_| self.error("`\\u` needs four hex digits"))?;
        self.position += 4;
        Ok(code)
    }

    fn quoted(&mut self) -> Result<String, String> {
        let Some(quote) = self.peek() else {
            return Err(self.error("expected a string"));
        };
        self.position += 1;
        let mut output = String::new();
        loop {
            let Some(character) = self.peek() else {
                return Err(self.error("unterminated string"));
            };
            self.position += character.len_utf8();
            match character {
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(self.error("unterminated string"));
                    };
                    self.position += escaped.len_utf8();
                    match escaped {
                        'n' => output.push('\n'),
                        'r' => output.push('\r'),
                        't' => output.push('\t'),
                        'b' => output.push('\u{8}'),
                        'f' => output.push('\u{c}'),
                        'u' => {
                            let mut code = self.hex4()?;
                            // JSON writes characters outside the basic plane
                            // as a surrogate pair.
                            if (0xd800..0xdc00).contains(&code) && self.rest().starts_with("\\u") {
                                self.position += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                }
                            }
                            output.push(
                                char::from_u32(code)
                                    .ok_or_else(|| self.error("`\\u` is not a character"))?,
                            );
                        }
                        '\\' | '"' | '\'' | '/' => output.push(escaped),
                        _ => return Err(self.error(&format!("unknown escape `\\{escaped}`"))),
                    }
                }
                end if end == quote => return Ok(output),
                other => output.push(other),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Loose, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting is too deep"));
        }
        self.whitespace();
        match self.peek() {
            Some('{') => self.compound(depth),
            Some('[') => self.list(depth),
            Some('"' | '\'') => self.quoted().map(Loose::String),
            Some(_) => {
                let start = self.position;
                let token = self.bare_token().to_owned();
                if token.is_empty() {
                    return Err(self.error("expected a value"));
                }
                bare_value(&token).map_err(|message| {
                    self.position = start;
                    self.error(&message)
                })
            }
            None => Err(self.error("expected a value")),
        }
    }

    fn compound(&mut self, depth: usize) -> Result<Loose, String> {
        self.position += 1;
        let mut entries: Vec<(String, Loose)> = Vec::new();
        loop {
            self.whitespace();
            if self.peek() == Some('}') {
                self.position += 1;
                return Ok(Loose::Compound(entries));
            }
            let key = if let Some('"' | '\'') = self.peek() {
                self.quoted()?
            } else {
                let token = self.bare_token().to_owned();
                if token.is_empty() {
                    return Err(self.error("expected a key or `}`"));
                }
                token
            };
            if entries.iter().any(|(existing, _)| *existing == key) {
                return Err(self.error(&format!("key `{key}` appears twice")));
            }
            self.expect(':')?;
            let value = self.value(depth + 1)?;
            entries.push((key, value));
            self.whitespace();
            match self.peek() {
                Some(',') => self.position += 1,
                Some('}') => {}
                _ => return Err(self.error("expected `,` or `}`")),
            }
        }
    }

    fn list(&mut self, depth: usize) -> Result<Loose, String> {
        self.position += 1;
        self.whitespace();
        let array = self
            .rest()
            .strip_prefix(['B', 'I', 'L'])
            .filter(|tail| tail.trim_start().starts_with(';'))
            .map(|_| self.rest().as_bytes()[0]);
        let mut items: Vec<Loose> = Vec::new();
        if array.is_some() {
            self.position += 1;
            self.expect(';')?;
        }
        loop {
            self.whitespace();
            if self.peek() == Some(']') {
                self.position += 1;
                break;
            }
            items.push(self.value(depth + 1)?);
            self.whitespace();
            match self.peek() {
                Some(',') => self.position += 1,
                Some(']') => {}
                _ => return Err(self.error("expected `,` or `]`")),
            }
        }
        let Some(kind) = array else {
            return Ok(Loose::List(items));
        };
        let template = match kind {
            b'B' => Tag::ByteArray(Vec::new()),
            b'I' => Tag::IntArray(Vec::new()),
            _ => Tag::LongArray(Vec::new()),
        };
        resolve(Loose::List(items), Some(&template)).map(Loose::Typed)
    }
}

/// An unquoted token: a number, a boolean, or otherwise a string.
fn bare_value(token: &str) -> Result<Loose, String> {
    match token {
        "true" => return Ok(Loose::Bool(true)),
        "false" => return Ok(Loose::Bool(false)),
        "null" => return Err("`null` has no NBT form; remove the key instead".into()),
        _ => {}
    }
    let numeric = |body: &str| {
        body.trim_start_matches(['-', '+'])
            .starts_with(|character: char| character.is_ascii_digit() || character == '.')
    };
    let special = |body: &str| match body {
        "NaN" => Some(f64::NAN),
        "Infinity" | "+Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    };
    let out_of_range = |kind: &str| format!("`{token}` does not fit in a {kind}");
    if let Some(suffix) = token.chars().last()
        && token.len() > 1
    {
        let body = &token[..token.len() - 1];
        if numeric(body) || special(body).is_some() {
            let tag = match suffix.to_ascii_lowercase() {
                'b' => Some(
                    body.parse::<i64>()
                        .ok()
                        .and_then(|value| i8::try_from(value).ok())
                        .map(Tag::Byte)
                        .ok_or_else(|| out_of_range("byte"))?,
                ),
                's' => Some(
                    body.parse::<i64>()
                        .ok()
                        .and_then(|value| i16::try_from(value).ok())
                        .map(Tag::Short)
                        .ok_or_else(|| out_of_range("short"))?,
                ),
                'l' => Some(Tag::Long(
                    body.parse::<i64>().map_err(|_| out_of_range("long"))?,
                )),
                'f' => {
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "NaN and the infinities are exact in both widths"
                    )]
                    let value =
                        special(body).map_or_else(|| body.parse::<f32>(), |value| Ok(value as f32));
                    Some(Tag::Float(
                        value.map_err(|_| format!("`{token}` is not a float"))?,
                    ))
                }
                'd' => Some(Tag::Double(
                    special(body)
                        .map_or_else(|| body.parse::<f64>(), Ok)
                        .map_err(|_| format!("`{token}` is not a double"))?,
                )),
                _ => None,
            };
            if let Some(tag) = tag {
                return Ok(Loose::Typed(tag));
            }
        }
    }
    if let Some(float) = special(token) {
        return Ok(Loose::Number {
            whole: None,
            float,
            text: token.to_owned(),
        });
    }
    if numeric(token) {
        if let Ok(whole) = token.parse::<i64>() {
            #[expect(
                clippy::cast_precision_loss,
                reason = "only used when the target is a float type"
            )]
            let float = whole as f64;
            return Ok(Loose::Number {
                whole: Some(whole),
                float,
                text: token.to_owned(),
            });
        }
        if let Ok(float) = token.parse::<f64>() {
            return Ok(Loose::Number {
                whole: None,
                float,
                text: token.to_owned(),
            });
        }
    }
    Ok(Loose::String(token.to_owned()))
}

// --- typing against the template ---

fn type_name(id: u8) -> &'static str {
    match id {
        1 => "byte",
        2 => "short",
        3 => "int",
        4 => "long",
        5 => "float",
        6 => "double",
        7 => "byte array",
        8 => "string",
        9 => "list",
        10 => "compound",
        11 => "int array",
        _ => "long array",
    }
}

/// Converts a number to the template's numeric type.
#[expect(
    clippy::cast_possible_truncation,
    reason = "narrowing to a float field is the point"
)]
fn number_as(whole: Option<i64>, float: f64, text: &str, template: u8) -> Result<Tag, String> {
    let integer = |kind: &str| {
        whole.ok_or_else(|| format!("`{text}` must be a whole number: the field is a {kind}"))
    };
    let range = |kind: &str| format!("`{text}` does not fit in a {kind}");
    Ok(match template {
        1 => Tag::Byte(i8::try_from(integer("byte")?).map_err(|_| range("byte"))?),
        2 => Tag::Short(i16::try_from(integer("short")?).map_err(|_| range("short"))?),
        3 => Tag::Int(i32::try_from(integer("int")?).map_err(|_| range("int"))?),
        4 => Tag::Long(integer("long")?),
        5 => Tag::Float(float as f32),
        6 => Tag::Double(float),
        _ => match whole {
            Some(whole) => i32::try_from(whole).map_or(Tag::Long(whole), Tag::Int),
            None => Tag::Double(float),
        },
    })
}

/// The element template for a list with no template of its own: all plain
/// numbers become doubles if any has a fraction, and longs if any needs it.
fn inferred_element(items: &[Loose]) -> Option<Tag> {
    let numbers: Option<Vec<Option<i64>>> = items
        .iter()
        .map(|item| match item {
            Loose::Number { whole, .. } => Some(*whole),
            _ => None,
        })
        .collect();
    let numbers = numbers?;
    if numbers.iter().any(Option::is_none) {
        Some(Tag::Double(0.0))
    } else if numbers
        .iter()
        .flatten()
        .any(|value| i32::try_from(*value).is_err())
    {
        Some(Tag::Long(0))
    } else {
        None
    }
}

/// Every key the compounds of a list hold, typed by the first that has it.
fn sibling_keys(items: &[Tag]) -> Option<Tag> {
    let mut keys: Vec<(String, Tag)> = Vec::new();
    for item in items {
        let Tag::Compound(entries) = item else {
            return None;
        };
        for (key, value) in entries {
            if !keys.iter().any(|(name, _)| name == key) {
                keys.push((key.clone(), value.clone()));
            }
        }
    }
    (!keys.is_empty()).then_some(Tag::Compound(keys))
}

fn resolve(loose: Loose, template: Option<&Tag>) -> Result<Tag, String> {
    let template_id = template.map_or(0, Tag::id);
    match loose {
        Loose::Typed(tag) => Ok(tag),
        Loose::String(text) => Ok(Tag::String(text)),
        Loose::Number { whole, float, text } => number_as(whole, float, &text, template_id),
        Loose::Bool(flag) => {
            let value = i64::from(flag);
            #[expect(clippy::cast_precision_loss, reason = "0 or 1")]
            let float = value as f64;
            number_as(
                Some(value),
                float,
                if flag { "true" } else { "false" },
                if (1..=6).contains(&template_id) {
                    template_id
                } else {
                    1
                },
            )
        }
        Loose::Compound(entries) => {
            let known = match template {
                Some(Tag::Compound(entries)) => entries.as_slice(),
                _ => &[],
            };
            entries
                .into_iter()
                .map(|(key, value)| {
                    let template = known
                        .iter()
                        .find(|(name, _)| *name == key)
                        .map(|(_, value)| value);
                    let value = resolve(value, template)
                        .map_err(|error| format!("{error} (in `{key}`)"))?;
                    Ok((key, value))
                })
                .collect::<Result<_, String>>()
                .map(Tag::Compound)
        }
        Loose::List(items) => resolve_list(items, template),
    }
}

fn resolve_list(items: Vec<Loose>, template: Option<&Tag>) -> Result<Tag, String> {
    let originals = match template {
        Some(Tag::List(values)) => values.as_slice(),
        _ => &[],
    };
    let element = match template {
        Some(Tag::ByteArray(_)) => Some(Tag::Byte(0)),
        Some(Tag::IntArray(_)) => Some(Tag::Int(0)),
        Some(Tag::LongArray(_)) => Some(Tag::Long(0)),
        Some(Tag::List(values)) => values.first().cloned(),
        _ => None,
    }
    .or_else(|| inferred_element(&items));
    // Compounds in one list rarely share every key: a text component's
    // `extra` mixes `{"": "plain"}` wrappers with styled parts. Each item is
    // typed by the item it replaces, and a key that item lacks by the first
    // sibling that has it, so `"bold": 0` stays a byte wherever it is added.
    let siblings = sibling_keys(originals);
    let values: Vec<Tag> = items
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            let own = originals.get(index).or(element.as_ref());
            let merged = match (own, &siblings) {
                (Some(Tag::Compound(entries)), Some(Tag::Compound(shared))) => {
                    let mut entries = entries.clone();
                    for (key, value) in shared {
                        if !entries.iter().any(|(name, _)| name == key) {
                            entries.push((key.clone(), value.clone()));
                        }
                    }
                    Some(Tag::Compound(entries))
                }
                (None, Some(shared)) => Some(shared.clone()),
                _ => None,
            };
            resolve(item, merged.as_ref().or(own))
                .map_err(|error| format!("{error} (in item {index})"))
        })
        .collect::<Result<_, _>>()?;
    let wanted = match template {
        Some(Tag::ByteArray(_)) => Some(1),
        Some(Tag::IntArray(_)) => Some(3),
        Some(Tag::LongArray(_)) => Some(4),
        _ => None,
    };
    if let Some(wanted) = wanted {
        if let Some(wrong) = values.iter().find(|value| value.id() != wanted) {
            return Err(format!(
                "a {} holds only {}s, not a {}",
                type_name(template.map_or(0, Tag::id)),
                type_name(wanted),
                type_name(wrong.id())
            ));
        }
        return Ok(match wanted {
            1 => Tag::ByteArray(
                values
                    .into_iter()
                    .filter_map(|value| match value {
                        Tag::Byte(value) => Some(value),
                        _ => None,
                    })
                    .collect(),
            ),
            3 => Tag::IntArray(
                values
                    .into_iter()
                    .filter_map(|value| match value {
                        Tag::Int(value) => Some(value),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => Tag::LongArray(
                values
                    .into_iter()
                    .filter_map(|value| match value {
                        Tag::Long(value) => Some(value),
                        _ => None,
                    })
                    .collect(),
            ),
        });
    }
    if let Some(first) = values.first()
        && let Some(wrong) = values.iter().find(|value| value.id() != first.id())
    {
        return Err(format!(
            "list items must all have the same type: a {} and a {}",
            type_name(first.id()),
            type_name(wrong.id())
        ));
    }
    Ok(Tag::List(values))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compound(entries: &[(&str, Tag)]) -> Vec<u8> {
        let mut bytes = vec![10];
        write_payload(
            &mut bytes,
            &Tag::Compound(
                entries
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), value.clone()))
                    .collect(),
            ),
        )
        .unwrap();
        bytes
    }

    #[test]
    fn compound_lists_type_each_item_by_the_item_it_replaces() {
        // A text component's `extra`: a `{"": ...}` wrapper for plain text
        // followed by a styled part whose flags are bytes. Typing every item
        // by the first one turned `bold` into an int and the whole component
        // failed its round trip, so it was shown as hex.
        let plain = Tag::Compound(vec![(String::new(), Tag::String("hi ".into()))]);
        let styled = Tag::Compound(vec![
            ("bold".into(), Tag::Byte(1)),
            ("text".into(), Tag::String("there".into())),
        ]);
        let bytes = compound(&[("extra", Tag::List(vec![plain, styled]))]);
        let text = to_text(&bytes, false).expect("renders as text");
        assert!(text.contains(r#""bold": 1"#), "{text}");

        // A key added to an item that lacked it takes its sibling's type.
        let edited = text.replace(r#"{"": "hi "}"#, r#"{"": "hi ", "bold": 0}"#);
        let encoded = from_text(&edited, false, Some(&bytes)).unwrap();
        let expected = compound(&[(
            "extra",
            Tag::List(vec![
                Tag::Compound(vec![
                    (String::new(), Tag::String("hi ".into())),
                    ("bold".into(), Tag::Byte(0)),
                ]),
                Tag::Compound(vec![
                    ("bold".into(), Tag::Byte(1)),
                    ("text".into(), Tag::String("there".into())),
                ]),
            ]),
        )]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn nbt_renders_as_json_and_round_trips() {
        let bytes = compound(&[
            ("byte", Tag::Byte(-3)),
            ("short", Tag::Short(300)),
            ("int", Tag::Int(70_000)),
            ("long", Tag::Long(-5_000_000_000)),
            ("float", Tag::Float(1.5)),
            ("double", Tag::Double(-0.1)),
            ("bytes", Tag::ByteArray(vec![1, -2])),
            ("text", Tag::String("say \"hi\"\n\u{0}\u{1F600}".into())),
            ("list", Tag::List(vec![Tag::Int(1), Tag::Int(2)])),
            ("empty", Tag::List(Vec::new())),
            ("nested", Tag::Compound(vec![("a b".into(), Tag::Byte(1))])),
            ("ints", Tag::IntArray(vec![1, -1])),
            ("longs", Tag::LongArray(vec![9])),
        ]);
        let text = to_text(&bytes, false).expect("renders");
        assert!(text.contains("\"byte\": -3,"), "{text}");
        assert!(text.contains("\"float\": 1.5,"), "{text}");
        assert!(text.contains("\"a b\": 1"), "{text}");
        assert_eq!(from_text(&text, false, Some(&bytes)).unwrap(), bytes);
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(parsed["short"], 300);
    }

    #[test]
    fn edits_keep_the_original_types() {
        let bytes = compound(&[
            ("count", Tag::Byte(1)),
            ("damage", Tag::Float(0.5)),
            ("id", Tag::String("minecraft:stone".into())),
            ("bold", Tag::Byte(0)),
        ]);
        let text = to_text(&bytes, false).unwrap();
        assert_eq!(
            text,
            r#"{"count": 1, "damage": 0.5, "id": "minecraft:stone", "bold": 0}"#
        );
        let edited =
            r#"{"count": 64, "damage": 2, "id": "minecraft:diamond", "bold": true, "new": 1.5}"#;
        let expected = compound(&[
            ("count", Tag::Byte(64)),
            ("damage", Tag::Float(2.0)),
            ("id", Tag::String("minecraft:diamond".into())),
            ("bold", Tag::Byte(1)),
            ("new", Tag::Double(1.5)),
        ]);
        assert_eq!(from_text(edited, false, Some(&bytes)).unwrap(), expected);
        assert!(
            from_text(r#"{"count": 300}"#, false, Some(&bytes))
                .unwrap_err()
                .contains("byte")
        );
    }

    #[test]
    fn suffixes_force_a_type() {
        let expected = compound(&[("a", Tag::Short(5)), ("b", Tag::ByteArray(vec![1, 2]))]);
        assert_eq!(
            from_text("{a: 5s, b: [B; 1, 2]}", false, None).unwrap(),
            expected
        );
    }

    #[test]
    fn new_lists_infer_one_element_type() {
        let expected = compound(&[("a", Tag::List(vec![Tag::Double(1.0), Tag::Double(2.5)]))]);
        assert_eq!(
            from_text(r#"{"a": [1, 2.5]}"#, false, None).unwrap(),
            expected
        );
        assert!(from_text(r#"{"a": [1, "x"]}"#, false, None).is_err());
    }

    #[test]
    fn named_roots_keep_their_name() {
        let mut bytes = vec![10];
        write_string(&mut bytes, "root").unwrap();
        write_payload(&mut bytes, &Tag::Compound(vec![("x".into(), Tag::Int(1))])).unwrap();
        let text = to_text(&bytes, true).unwrap();
        assert_eq!(text, r#""root": {"x": 1}"#);
        assert_eq!(from_text(&text, true, Some(&bytes)).unwrap(), bytes);
        // Dropping the prefix keeps the name the bytes had.
        assert_eq!(from_text(r#"{"x": 1}"#, true, Some(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn an_absent_value_is_empty_text() {
        assert_eq!(to_text(&[0], false).unwrap(), "");
        assert_eq!(from_text("  ", false, None).unwrap(), vec![0]);
    }

    #[test]
    fn surrogate_pair_escapes_decode() {
        let expected = {
            let mut bytes = vec![8];
            write_string(&mut bytes, "\u{1F600}").unwrap();
            bytes
        };
        assert_eq!(from_text(r#""😀""#, false, None).unwrap(), expected);
    }

    #[test]
    fn mistakes_are_reported_with_a_position() {
        let error = from_text("{\"a\": 1,\n \"b\": [1, \"x\"]}", false, None).unwrap_err();
        assert!(error.contains("same type"), "{error}");
        assert!(
            from_text("{\"a\": null}", false, None)
                .unwrap_err()
                .contains("null")
        );
        let error = from_text("{\"a\": 1,\n \"b\" 2}", false, None).unwrap_err();
        assert!(error.contains("line 2"), "{error}");
        assert!(from_text("{\"a\": 1} x", false, None).is_err());
    }

    #[test]
    fn bytes_that_do_not_round_trip_are_refused() {
        // A NUL written as a single byte is not modified UTF-8.
        assert!(to_text(&[8, 0, 1, 0], false).is_none());
        assert!(to_text(&[10, 1, 0], false).is_none(), "truncated input");
    }
}
