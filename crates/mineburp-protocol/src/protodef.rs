//! Data-driven packet decoding from `minecraft-data` protocol descriptions.
//!
//! `minecraft-data` describes every packet of every release in `ProtoDef`, a small
//! type language: containers, switches, arrays, mappers, bitfields, and a
//! handful of Minecraft-specific natives. This module interprets those
//! descriptions as *data*. Nothing in a description can execute; the worst a
//! malformed one can do is fail to decode, and the worst a hostile packet can do
//! is exhaust a budget.
//!
//! Every value is read with bounds checked against the bytes actually present,
//! and three budgets cap the work any one packet can cause: a node budget over
//! every value produced, a recursion depth, and a cap on the byte spans
//! recorded. A count larger than the remaining bytes is rejected before
//! anything is allocated for it, which is what makes a four-byte "array of a
//! million elements" cost nothing.
//!
//! Decoding produces two views of one walk:
//!
//! * a field tree for the inspector, with long buffers shortened, and
//! * a [`FieldSpan`] for every primitive with its exact byte range, so the
//!   Repeater and the replacement rules can re-encode any value of any packet
//!   and splice it back in.
//!
//! The descriptions are bundled per protocol by `mineburp-packet-table` and
//! matched exactly — a neighbouring release's description is a different
//! protocol, not an approximation of this one.

use std::{
    collections::HashMap,
    io::Read as _,
    sync::{Arc, Mutex, OnceLock},
};

use mineburp_core::{Direction, ProtocolState};
use serde_json::{Map, Value};

use crate::layout::{FieldKind, FieldSpan};

const BUNDLE: &[u8] = include_bytes!("../data/protocol-definitions.zst");
/// The decompressed bundle is a few megabytes; anything far past that is not
/// the file the generator wrote.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Recursion through nested types. Real descriptions nest a few dozen deep at
/// most (an item inside a component inside an item); this is far above that
/// and far below anything that threatens the stack.
const MAX_DEPTH: usize = 96;
/// Values produced per packet. A full chunk or registry packet is well inside
/// this; a crafted packet that tries to multiply its output is not.
const MAX_NODES: usize = 250_000;
/// Byte spans recorded per packet. Past this the layout is reported partial.
const MAX_SPANS: usize = 50_000;
const MAX_NBT_DEPTH: usize = 64;
/// Loops with an in-band terminator rather than a count.
const MAX_LOOP_ITEMS: usize = 4_096;
/// Buffers longer than this are shortened in the field tree (never in spans).
const PREVIEW_BYTES: usize = 64;
/// NBT arrays longer than this are summarised in the field tree.
const PREVIEW_ITEMS: usize = 64;

/// The result of decoding one packet body against its description.
#[derive(Debug, Clone)]
pub struct DefinitionDecode {
    /// `minecraft-data`'s own name for the packet.
    pub packet: String,
    /// The decoded fields, keys in `snake_case` and in wire order. On an error
    /// this holds whatever decoded before it.
    pub fields: Value,
    /// Every primitive's byte range, offsets relative to the start of the
    /// body (after the packet id).
    pub spans: Vec<FieldSpan>,
    /// Bytes the description accounted for.
    pub consumed: usize,
    /// Why the body does not match its description, if it does not.
    pub error: Option<String>,
}

impl DefinitionDecode {
    /// True when the body decoded cleanly and the description accounted for
    /// every byte.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.error.is_none()
    }
}

// --- the bundle ---

struct Bundle {
    text: String,
    index: HashMap<i32, (usize, usize)>,
}

fn bundle() -> Option<&'static Bundle> {
    static CELL: OnceLock<Option<Bundle>> = OnceLock::new();
    CELL.get_or_init(|| load_bundle(BUNDLE)).as_ref()
}

fn load_bundle(bytes: &[u8]) -> Option<Bundle> {
    let decoder = zstd::stream::Decoder::new(bytes).ok()?;
    let mut plain = String::new();
    decoder
        .take(MAX_BUNDLE_BYTES)
        .read_to_string(&mut plain)
        .ok()?;
    let rest = plain.strip_prefix("MBPD1\n")?;
    let (header, body) = rest.split_once('\n')?;
    let header: Value = serde_json::from_str(header).ok()?;
    let mut index = HashMap::new();
    for (protocol, range) in header.get("versions")?.as_object()? {
        let protocol = protocol.parse().ok()?;
        let start = usize::try_from(range.get(0)?.as_u64()?).ok()?;
        let length = usize::try_from(range.get(1)?.as_u64()?).ok()?;
        if start.checked_add(length)? > body.len() {
            return None;
        }
        index.insert(protocol, (start, length));
    }
    let offset = plain.len() - body.len();
    let text = plain.split_off(offset);
    Some(Bundle { text, index })
}

/// The protocols a field description is bundled for.
#[must_use]
pub fn definition_protocols() -> Vec<i32> {
    let mut protocols: Vec<i32> = bundle()
        .map(|bundle| bundle.index.keys().copied().collect())
        .unwrap_or_default();
    protocols.sort_unstable();
    protocols
}

/// True when this exact protocol has a bundled field description.
#[must_use]
pub fn has_definition(protocol: Option<i32>) -> bool {
    protocol
        .is_some_and(|protocol| bundle().is_some_and(|bundle| bundle.index.contains_key(&protocol)))
}

fn definition(protocol: i32) -> Option<Arc<Value>> {
    static PARSED: OnceLock<Mutex<HashMap<i32, Arc<Value>>>> = OnceLock::new();
    let cache = PARSED.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(found) = cache.lock().ok()?.get(&protocol) {
        return Some(Arc::clone(found));
    }
    let bundle = bundle()?;
    let (start, length) = *bundle.index.get(&protocol)?;
    let parsed: Value = serde_json::from_str(bundle.text.get(start..start + length)?).ok()?;
    let parsed = Arc::new(parsed);
    cache.lock().ok()?.insert(protocol, Arc::clone(&parsed));
    Some(parsed)
}

fn state_key(state: ProtocolState) -> Option<&'static str> {
    Some(match state {
        ProtocolState::Handshake => "handshaking",
        ProtocolState::Status => "status",
        ProtocolState::Login => "login",
        ProtocolState::Configuration => "configuration",
        ProtocolState::Play => "play",
        _ => return None,
    })
}

/// Finds a packet's `minecraft-data` name and type from its id.
fn packet_type(
    side: &Map<String, Value>,
    global: &Map<String, Value>,
    packet_id: i32,
) -> Option<(String, Value)> {
    let packet = side.get("packet")?;
    let fields = packet.get(1)?.as_array()?;
    let mut name = None;
    let mut switch = None;
    for field in fields {
        let ty = field.get("type")?;
        match ty.get(0).and_then(Value::as_str) {
            Some("mapper") if name.is_none() => {
                let mappings = ty.get(1)?.get("mappings")?.as_object()?;
                name = mappings
                    .iter()
                    .find(|(key, _)| parse_number(key) == Some(i64::from(packet_id)))
                    .and_then(|(_, value)| value.as_str())
                    .map(str::to_owned);
            }
            Some("switch") => switch = ty.get(1)?.get("fields")?.as_object(),
            _ => {}
        }
    }
    let name = name?;
    let type_name = switch
        .and_then(|fields| fields.get(&name))
        .and_then(Value::as_str)
        .map_or_else(|| format!("packet_{name}"), str::to_owned);
    // Shared packets (`packet_common_*`) live with the global types, and an
    // empty packet such as the bundle delimiter is typed as plain `void`.
    let ty = side
        .get(&type_name)
        .or_else(|| global.get(&type_name))
        .cloned()
        .unwrap_or(Value::String(type_name));
    // `minecraft-data` marks the bundle delimiter `native`: it has no fields,
    // node-minecraft-protocol just handles it in code.
    let ty = if ty.as_str() == Some("native") {
        Value::String("void".into())
    } else {
        ty
    };
    Some((name, ty))
}

/// Decodes one packet body against the description bundled for its protocol.
///
/// Returns `None` when there is no description for the protocol, state, and
/// id — not when the body fails to match one, which is reported as an error on
/// the result instead, alongside whatever decoded before the failure.
#[must_use]
pub fn decode_packet(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol: Option<i32>,
) -> Option<DefinitionDecode> {
    decode_packet_until(state, direction, packet_id, body, protocol, None)
}

/// Stops decoding once the requested span has been read. Presentation of
/// buffers and NBT is suppressed in this mode.
pub(crate) fn decode_packet_until(
    state: ProtocolState,
    direction: Direction,
    packet_id: i32,
    body: &[u8],
    protocol: Option<i32>,
    target: Option<&str>,
) -> Option<DefinitionDecode> {
    let root = definition(protocol?)?;
    let global = root.get("types")?.as_object()?;
    let side = root
        .get(state_key(state)?)?
        .get(match direction {
            Direction::ClientToServer => "toServer",
            Direction::ServerToClient => "toClient",
        })?
        .get("types")?
        .as_object()?;
    let (packet, ty) = packet_type(side, global, packet_id)?;
    let mut decoder = Decoder {
        target,
        input: body,
        position: 0,
        local: side,
        global,
        nodes: 0,
        spans: Vec::new(),
        spans_truncated: false,
        path: Vec::new(),
        scopes: Vec::new(),
        mask_top_bit_at: None,
    };
    let result = decoder.read(&ty, 0);
    let consumed = decoder.position;
    let (fields, mut error) = match result {
        Ok(value) => (value, None),
        Err(failure) => (
            failure.partial.unwrap_or(Value::Null),
            Some(format!("{} at byte {}", failure.message, failure.at)),
        ),
    };
    if error.is_none() && consumed < body.len() {
        error = Some(format!(
            "{} trailing byte(s) the description does not account for",
            body.len() - consumed
        ));
    }
    if error.is_none() && decoder.spans_truncated {
        error = Some(format!("more than {MAX_SPANS} fields"));
    }
    Some(DefinitionDecode {
        packet,
        fields: snake_keys(fields),
        spans: decoder.spans,
        consumed,
        error,
    })
}

// --- the interpreter ---

#[derive(Debug)]
struct Failure {
    message: String,
    at: usize,
    /// What decoded before the failure, folded up from the innermost scope.
    partial: Option<Value>,
}

type Decoded<T> = Result<T, Failure>;

enum PathPart {
    Field(String),
    Index(usize),
}

struct Decoder<'a> {
    target: Option<&'a str>,
    input: &'a [u8],
    position: usize,
    local: &'a Map<String, Value>,
    global: &'a Map<String, Value>,
    nodes: usize,
    spans: Vec<FieldSpan>,
    spans_truncated: bool,
    path: Vec<PathPart>,
    /// One map per open container, innermost last. Switches and counts look
    /// fields up here, including in enclosing containers via `..`.
    scopes: Vec<Map<String, Value>>,
    /// The `topBitSetTerminatedArray` continuation bit lives in the first byte
    /// of each element; the element's own read of that byte must not see it.
    mask_top_bit_at: Option<usize>,
}

/// The default for an absent type expression, borrowable for any lifetime.
static NULL: Value = Value::Null;
/// A switch with no matching branch and no default reads nothing.
static VOID: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| Value::String("void".into()));

impl<'a> Decoder<'a> {
    fn display_hex(&self, bytes: &[u8]) -> String {
        if self.target.is_some() {
            String::new()
        } else {
            to_hex(bytes)
        }
    }

    fn fail<T>(&self, message: impl Into<String>) -> Decoded<T> {
        Err(Failure {
            message: message.into(),
            at: self.position,
            partial: None,
        })
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take(&mut self, count: usize) -> Decoded<&[u8]> {
        if count > self.remaining() {
            return self.fail(format!(
                "needs {count} byte(s) but only {} remain",
                self.remaining()
            ));
        }
        let start = self.position;
        self.position += count;
        Ok(&self.input[start..start + count])
    }

    fn tick(&mut self) -> Decoded<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return self.fail(format!("more than {MAX_NODES} values"));
        }
        Ok(())
    }

    fn path_name(&self) -> String {
        let mut name = String::new();
        for part in &self.path {
            match part {
                PathPart::Field(field) => {
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.push_str(&snake_case(field));
                }
                PathPart::Index(index) => {
                    name.push('[');
                    name.push_str(&index.to_string());
                    name.push(']');
                }
            }
        }
        if name.is_empty() {
            "value".into()
        } else {
            name
        }
    }

    fn span(&mut self, kind: FieldKind, start: usize, value: Value) {
        if self.spans.len() >= MAX_SPANS {
            self.spans_truncated = true;
            return;
        }
        let name = self.path_name();
        if self
            .target
            .is_some_and(|target| crate::rewrite::normalise(&name) != target)
        {
            return;
        }
        self.spans.push(FieldSpan {
            name,
            kind,
            offset: start,
            length: self.position - start,
            value,
        });
    }

    /// A boolean byte. The game reads any nonzero byte as true, but a span
    /// of kind `bool` writes back 0 or 1; a byte that is neither is shown as
    /// the number it is, so the frame rebuilt from the spans keeps it.
    fn flag_span(&mut self, start: usize, byte: u8) {
        if byte <= 1 {
            self.span(FieldKind::Bool, start, Value::Bool(byte == 1));
        } else {
            self.span(FieldKind::U8, start, Value::from(byte));
        }
    }

    fn with_field<T>(
        &mut self,
        name: &str,
        read: impl FnOnce(&mut Self) -> Decoded<T>,
    ) -> Decoded<T> {
        self.path.push(PathPart::Field(name.to_owned()));
        let result = read(self);
        self.path.pop();
        result
    }

    /// Looks a named type up. The definitions outlive the decoder, so the
    /// result is borrowed for `'a` rather than from `self` — nothing is cloned
    /// per lookup, which matters when a packet repeats a large type thousands
    /// of times.
    fn resolve(&self, name: &str) -> Option<&'a Value> {
        let local: &'a Map<String, Value> = self.local;
        let global: &'a Map<String, Value> = self.global;
        local
            .get(name)
            .or_else(|| global.get(name))
            .filter(|definition| definition.as_str() != Some("native"))
    }

    fn read(&mut self, ty: &Value, depth: usize) -> Decoded<Value> {
        if self.target.is_some() && !self.spans.is_empty() {
            return self.fail("requested field found");
        }
        if depth > MAX_DEPTH {
            return self.fail("types nest too deeply");
        }
        self.tick()?;
        match ty {
            Value::String(name) => self.read_named(name, None, depth),
            Value::Array(parts) => match (parts.first(), parts.get(1)) {
                (Some(Value::String(name)), arguments) => self.read_named(name, arguments, depth),
                _ => self.fail("malformed type expression"),
            },
            _ => self.fail("malformed type expression"),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per native type reads clearest flat"
    )]
    fn read_named(
        &mut self,
        name: &str,
        arguments: Option<&Value>,
        depth: usize,
    ) -> Decoded<Value> {
        // A description may define its own type under any name, including one
        // that shadows a native; only an explicit `"native"` entry means the
        // built-in.
        if let Some(definition) = self.resolve(name) {
            return match arguments {
                Some(arguments) => {
                    let substituted = substitute(definition, arguments);
                    self.read(&substituted, depth + 1)
                }
                None => self.read(definition, depth + 1),
            };
        }
        let none = Value::Null;
        let arguments = arguments.unwrap_or(&none);
        match name {
            "varint" | "optvarint" => self.var_int().map(Value::from),
            "varlong" => self.var_long().map(Value::from),
            "bool" => {
                let start = self.position;
                let byte = self.take(1)?[0];
                let value = byte != 0;
                self.flag_span(start, byte);
                Ok(Value::Bool(value))
            }
            "u8" => {
                let value = self.small(false)?;
                Ok(Value::from(value))
            }
            "i8" => {
                let value = self.small(true)?;
                Ok(Value::from(value))
            }
            "u16" => self.fixed::<2>(FieldKind::U16, |bytes| {
                Value::from(u16::from_be_bytes(bytes))
            }),
            "i16" => self.fixed::<2>(FieldKind::I16, |bytes| {
                Value::from(i16::from_be_bytes(bytes))
            }),
            "u32" => self.fixed::<4>(FieldKind::Bytes, |bytes| {
                Value::from(u32::from_be_bytes(bytes))
            }),
            "i32" => self.fixed::<4>(FieldKind::I32, |bytes| {
                Value::from(i32::from_be_bytes(bytes))
            }),
            "u64" => self.fixed::<8>(FieldKind::Bytes, |bytes| {
                Value::from(u64::from_be_bytes(bytes))
            }),
            "i64" => self.fixed::<8>(FieldKind::I64, |bytes| {
                Value::from(i64::from_be_bytes(bytes))
            }),
            "f32" => self.fixed::<4>(FieldKind::F32, |bytes| {
                float(f64::from(f32::from_be_bytes(bytes)))
            }),
            "f64" => self.fixed::<8>(FieldKind::F64, |bytes| float(f64::from_be_bytes(bytes))),
            "void" => Ok(Value::Null),
            "UUID" => {
                let start = self.position;
                let bytes: [u8; 16] = self
                    .take(16)?
                    .try_into()
                    .map_err(|_| self.failure("short UUID"))?;
                let text = uuid::Uuid::from_bytes(bytes).hyphenated().to_string();
                self.span(
                    FieldKind::Bytes,
                    start,
                    Value::String(self.display_hex(&bytes)),
                );
                Ok(Value::String(text))
            }
            "pstring" => self.pstring(arguments, depth),
            "buffer" => self.buffer(arguments, depth),
            "restBuffer" => {
                let start = self.position;
                let bytes = self.take(self.remaining())?.to_vec();
                self.span(
                    FieldKind::Bytes,
                    start,
                    Value::String(self.display_hex(&bytes)),
                );
                Ok(if self.target.is_some() {
                    Value::Null
                } else {
                    preview(&bytes)
                })
            }
            "container" => {
                let fields = arguments
                    .as_array()
                    .ok_or_else(|| self.failure("container without fields"))?;
                self.container(fields, false, depth)
            }
            "switch" => {
                let branch = self.switch_branch(arguments)?;
                self.read(branch, depth + 1)
            }
            "option" => {
                let start = self.position;
                let byte = self.take(1)?[0];
                let present = byte != 0;
                self.with_field("present", |decoder| {
                    decoder.flag_span(start, byte);
                    Ok(())
                })?;
                if present {
                    self.read(arguments, depth + 1)
                } else {
                    Ok(Value::Null)
                }
            }
            "array" => self.array(arguments, depth),
            "count" => {
                let ty = arguments.get("type").unwrap_or(&NULL);
                self.read(ty, depth + 1)
            }
            "mapper" => {
                let ty = arguments
                    .get("type")
                    .ok_or_else(|| self.failure("mapper without a type"))?;
                let raw = self.read(ty, depth + 1)?;
                Ok(map_value(arguments.get("mappings"), &raw).unwrap_or(raw))
            }
            "bitfield" => {
                let fields = arguments
                    .as_array()
                    .ok_or_else(|| self.failure("bitfield without fields"))?;
                self.bitfield(fields).map(Value::Object)
            }
            "bitflags" => self.bitflags(arguments, depth),
            "entityMetadataLoop" => {
                let end = arguments
                    .get("endVal")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| self.failure("metadata loop without an end value"))?;
                let ty = arguments.get("type").unwrap_or(&NULL);
                let mut items = Vec::new();
                loop {
                    let next = *self
                        .input
                        .get(self.position)
                        .ok_or_else(|| self.failure("metadata ended without its terminator"))?;
                    if u64::from(next) == end {
                        // The terminator gets a span so the layout tiles the
                        // whole frame and the Repeater writes it back.
                        let start = self.position;
                        self.position += 1;
                        self.path.push(PathPart::Field("end".into()));
                        self.span(
                            FieldKind::Bytes,
                            start,
                            Value::String(self.display_hex(&[next])),
                        );
                        self.path.pop();
                        break;
                    }
                    if items.len() >= MAX_LOOP_ITEMS {
                        return self.fail("metadata loop runs past its limit");
                    }
                    self.path.push(PathPart::Index(items.len()));
                    let item = self.read(ty, depth + 1);
                    self.path.pop();
                    match item {
                        Ok(item) => items.push(item),
                        Err(failure) => return Err(fold_array(failure, items)),
                    }
                }
                Ok(Value::Array(items))
            }
            "topBitSetTerminatedArray" => {
                let ty = arguments.get("type").unwrap_or(&NULL);
                let mut items = Vec::new();
                loop {
                    let first = *self
                        .input
                        .get(self.position)
                        .ok_or_else(|| self.failure("array ended without its terminator"))?;
                    if items.len() >= PREVIEW_ITEMS {
                        return self.fail("terminated array runs past its limit");
                    }
                    self.mask_top_bit_at = Some(self.position);
                    self.path.push(PathPart::Index(items.len()));
                    let item = self.read(ty, depth + 1);
                    self.path.pop();
                    self.mask_top_bit_at = None;
                    match item {
                        Ok(item) => items.push(item),
                        Err(failure) => return Err(fold_array(failure, items)),
                    }
                    if first & 0x80 == 0 {
                        break;
                    }
                }
                Ok(Value::Array(items))
            }
            "registryEntryHolder" => {
                let id = self.var_int()?;
                let mut object = Map::new();
                if id == 0 {
                    let otherwise = arguments
                        .get("otherwise")
                        .ok_or_else(|| self.failure("holder without an inline form"))?;
                    let field = otherwise
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("data")
                        .to_owned();
                    let ty = otherwise.get("type").unwrap_or(&NULL);
                    let value = self.with_field(&field, |decoder| decoder.read(ty, depth + 1))?;
                    object.insert(field, value);
                } else {
                    let field = arguments
                        .get("baseName")
                        .and_then(Value::as_str)
                        .unwrap_or("id")
                        .to_owned();
                    object.insert(
                        field,
                        Value::from(
                            id.checked_sub(1)
                                .ok_or_else(|| self.failure("invalid holder id"))?,
                        ),
                    );
                }
                Ok(Value::Object(object))
            }
            "registryEntryHolderSet" => {
                let count = self.var_int()?;
                let mut object = Map::new();
                if count == 0 {
                    let base = arguments
                        .get("base")
                        .ok_or_else(|| self.failure("holder set without a tag form"))?;
                    let field = base
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("name")
                        .to_owned();
                    let ty = base.get("type").unwrap_or(&NULL);
                    let value = self.with_field(&field, |decoder| decoder.read(ty, depth + 1))?;
                    object.insert(field, value);
                } else {
                    let otherwise = arguments
                        .get("otherwise")
                        .ok_or_else(|| self.failure("holder set without a list form"))?;
                    let field = otherwise
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("ids")
                        .to_owned();
                    let ty = otherwise.get("type").unwrap_or(&NULL);
                    let count = usize::try_from(
                        count
                            .checked_sub(1)
                            .ok_or_else(|| self.failure("invalid holder count"))?,
                    )
                    .unwrap_or(usize::MAX);
                    let items =
                        self.with_field(&field, |decoder| decoder.repeat(count, ty, depth + 1))?;
                    object.insert(field, Value::Array(items));
                }
                Ok(Value::Object(object))
            }
            "lpVec3" => self.low_precision_vector(),
            "nbt" => self.nbt(true, false),
            "optionalNbt" => self.nbt(true, true),
            "anonymousNbt" | "anonOptionalNbt" => self.nbt(false, true),
            "compressedNbt" => self.compressed_nbt(),
            other => self.fail(format!("unknown type `{other}`")),
        }
    }

    fn failure(&self, message: &str) -> Failure {
        Failure {
            message: message.to_owned(),
            at: self.position,
            partial: None,
        }
    }

    // --- primitives ---

    fn var_int(&mut self) -> Decoded<i32> {
        let start = self.position;
        let mut value: u32 = 0;
        for index in 0..5 {
            let byte = self.take(1)?[0];
            value |= u32::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                let value = value.cast_signed();
                self.span(FieldKind::VarInt, start, Value::from(value));
                return Ok(value);
            }
        }
        self.fail("VarInt is longer than five bytes")
    }

    fn var_long(&mut self) -> Decoded<i64> {
        let start = self.position;
        let mut value: u64 = 0;
        for index in 0..10 {
            let byte = self.take(1)?[0];
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                let value = value.cast_signed();
                self.span(FieldKind::VarLong, start, Value::from(value));
                return Ok(value);
            }
        }
        self.fail("VarLong is longer than ten bytes")
    }

    /// Reads a one-byte integer, honouring a pending terminated-array mask.
    fn small(&mut self, signed: bool) -> Decoded<i64> {
        let start = self.position;
        let byte = self.take(1)?[0];
        // The top bit of a terminated array's leading byte is the array's
        // continuation flag, not part of the value; the span says so, or an
        // edit written back as a plain byte would end the array early.
        let (value, kind) = if self.mask_top_bit_at == Some(start) {
            self.mask_top_bit_at = None;
            (i64::from(byte & 0x7f), FieldKind::FlaggedU7)
        } else if signed {
            (i64::from(byte.cast_signed()), FieldKind::I8)
        } else {
            (i64::from(byte), FieldKind::U8)
        };
        self.span(kind, start, Value::from(value));
        Ok(value)
    }

    fn fixed<const N: usize>(
        &mut self,
        kind: FieldKind,
        convert: impl Fn([u8; N]) -> Value,
    ) -> Decoded<Value> {
        let start = self.position;
        let bytes: [u8; N] = self
            .take(N)?
            .try_into()
            .map_err(|_| self.failure("short read"))?;
        let value = convert(bytes);
        let span_value = if kind == FieldKind::Bytes {
            Value::String(self.display_hex(&bytes))
        } else {
            value.clone()
        };
        self.span(kind, start, span_value);
        Ok(value)
    }

    /// Reads a length for a string, buffer, or array from `countType` or
    /// `count`, without recording a span for a `count` that names a field.
    fn length(&mut self, arguments: &Value, depth: usize) -> Decoded<usize> {
        let raw = if let Some(ty) = arguments.get("countType") {
            self.with_field("length", |decoder| decoder.read(ty, depth + 1))?
        } else {
            match arguments.get("count") {
                Some(Value::Number(number)) => Value::Number(number.clone()),
                Some(Value::String(path)) => self
                    .lookup(path)
                    .ok_or_else(|| self.failure(&format!("count field `{path}` is not decoded")))?,
                _ => return self.fail("length without countType or count"),
            }
        };
        let count = raw
            .as_i64()
            .ok_or_else(|| self.failure("length is not a whole number"))?;
        usize::try_from(count).map_err(|_| self.failure(&format!("negative length {count}")))
    }

    fn pstring(&mut self, arguments: &Value, depth: usize) -> Decoded<Value> {
        let start = self.position;
        let prefixed = arguments.get("countType").and_then(Value::as_str) == Some("varint");
        let length = self.length(arguments, depth)?;
        if prefixed {
            self.spans.pop();
        }
        if length > self.remaining() {
            return self.fail(format!(
                "string of {length} bytes but only {} remain",
                self.remaining()
            ));
        }
        let text_start = self.position;
        // Invalid UTF-8 is shown rather than refused: a malformed string is
        // exactly what an operator testing a server wants to see. Keep the
        // original bytes for the span, though, so re-encoding an unchanged
        // field does not replace them with the replacement characters.
        let bytes = self.take(length)?.to_vec();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if prefixed {
            self.span(FieldKind::String, start, Value::String(text.clone()));
        } else {
            let hex = self.display_hex(&bytes);
            self.span(FieldKind::Bytes, text_start, Value::String(hex));
        }
        Ok(Value::String(text))
    }

    fn buffer(&mut self, arguments: &Value, depth: usize) -> Decoded<Value> {
        let start = self.position;
        if arguments.get("rest").and_then(Value::as_bool) == Some(true) {
            let bytes = self.take(self.remaining())?.to_vec();
            self.span(
                FieldKind::Bytes,
                start,
                Value::String(self.display_hex(&bytes)),
            );
            return Ok(if self.target.is_some() {
                Value::Null
            } else {
                preview(&bytes)
            });
        }
        let prefixed = arguments.get("countType").and_then(Value::as_str) == Some("varint");
        let length = self.length(arguments, depth)?;
        if prefixed {
            self.spans.pop();
        }
        let data_start = self.position;
        let bytes = self.take(length)?.to_vec();
        if prefixed {
            self.span(
                FieldKind::PrefixedBytes,
                start,
                Value::String(self.display_hex(&bytes)),
            );
        } else {
            self.span(
                FieldKind::Bytes,
                data_start,
                Value::String(self.display_hex(&bytes)),
            );
        }
        Ok(if self.target.is_some() {
            Value::Null
        } else {
            preview(&bytes)
        })
    }

    fn repeat(&mut self, count: usize, ty: &Value, depth: usize) -> Decoded<Vec<Value>> {
        // Every element of every real type consumes at least one byte, so a
        // count past the bytes left is a lie told before anything is allocated.
        if count > self.remaining() {
            return self.fail(format!(
                "array of {count} element(s) but only {} byte(s) remain",
                self.remaining()
            ));
        }
        let mut items = Vec::with_capacity(count.min(1_024));
        for index in 0..count {
            self.path.push(PathPart::Index(index));
            let item = self.read(ty, depth + 1);
            self.path.pop();
            match item {
                Ok(item) => items.push(item),
                Err(failure) => return Err(fold_array(failure, items)),
            }
        }
        Ok(items)
    }

    fn array(&mut self, arguments: &Value, depth: usize) -> Decoded<Value> {
        let ty = arguments
            .get("type")
            .ok_or_else(|| self.failure("array without an element type"))?;
        let count = self.length(arguments, depth)?;
        // An element that reads no bytes at all (`void`, an empty container)
        // cannot amplify anything past the node budget, but still has to be
        // counted honestly.
        if count > self.remaining() && !zero_width(ty) {
            return self.fail(format!(
                "array of {count} element(s) but only {} byte(s) remain",
                self.remaining()
            ));
        }
        if count > MAX_NODES {
            return self.fail(format!(
                "array of {count} elements is past the value budget"
            ));
        }
        let mut items = Vec::with_capacity(count.min(1_024));
        for index in 0..count {
            self.path.push(PathPart::Index(index));
            let item = self.read(ty, depth + 1);
            self.path.pop();
            match item {
                Ok(item) => items.push(item),
                Err(failure) => return Err(fold_array(failure, items)),
            }
        }
        Ok(Value::Array(items))
    }

    // --- structure ---

    /// Reads a container. An inline (anonymous) container writes its fields
    /// into the enclosing scope instead of opening its own, which is how a
    /// switch further down can compare against them.
    fn container(&mut self, fields: &[Value], inline: bool, depth: usize) -> Decoded<Value> {
        if !inline {
            self.scopes.push(Map::new());
        }
        for field in fields {
            let ty = field.get("type").unwrap_or(&NULL);
            let anonymous = field.get("anon").and_then(Value::as_bool) == Some(true);
            let name = field.get("name").and_then(Value::as_str);
            let result = match name.filter(|_| !anonymous) {
                Some(name) => {
                    let name = name.to_owned();
                    let value = self.with_field(&name, |decoder| decoder.read(ty, depth + 1));
                    match value {
                        Ok(value) => {
                            self.scope_insert(name, value);
                            Ok(())
                        }
                        Err(mut failure) => {
                            if let Some(partial) = failure.partial.take() {
                                self.scope_insert(name, partial);
                            }
                            Err(failure)
                        }
                    }
                }
                None => self.inline(ty, depth + 1),
            };
            if let Err(mut failure) = result {
                if !inline {
                    let scope = self.scopes.pop().unwrap_or_default();
                    failure.partial = Some(Value::Object(scope));
                }
                return Err(failure);
            }
        }
        if inline {
            Ok(Value::Null)
        } else {
            Ok(Value::Object(self.scopes.pop().unwrap_or_default()))
        }
    }

    fn scope_insert(&mut self, name: String, value: Value) {
        if self.scopes.is_empty() {
            self.scopes.push(Map::new());
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, value);
        }
    }

    /// Reads an anonymous field, merging what it produces into the current
    /// scope.
    fn inline(&mut self, ty: &Value, depth: usize) -> Decoded<()> {
        if depth > MAX_DEPTH {
            return self.fail("types nest too deeply");
        }
        self.tick()?;
        let (name, arguments) = match ty {
            Value::String(name) => (name.as_str(), None),
            Value::Array(parts) => match parts.first() {
                Some(Value::String(name)) => (name.as_str(), parts.get(1)),
                _ => return self.fail("malformed type expression"),
            },
            _ => return self.fail("malformed type expression"),
        };
        if let Some(definition) = self.resolve(name) {
            return match arguments {
                Some(arguments) => {
                    let substituted = substitute(definition, arguments);
                    self.inline(&substituted, depth + 1)
                }
                None => self.inline(definition, depth + 1),
            };
        }
        let none = Value::Null;
        let arguments = arguments.unwrap_or(&none);
        match name {
            "container" => {
                let fields = arguments
                    .as_array()
                    .ok_or_else(|| self.failure("container without fields"))?;
                self.container(fields, true, depth).map(|_| ())
            }
            "switch" => {
                let branch = self.switch_branch(arguments)?;
                self.inline(branch, depth + 1)
            }
            "bitfield" => {
                let fields = arguments
                    .as_array()
                    .ok_or_else(|| self.failure("bitfield without fields"))?;
                for (key, value) in self.bitfield(fields)? {
                    self.scope_insert(key, value);
                }
                Ok(())
            }
            "void" => Ok(()),
            _ => {
                let value = self.read(ty, depth)?;
                if let Value::Object(fields) = value {
                    for (key, value) in fields {
                        self.scope_insert(key, value);
                    }
                }
                Ok(())
            }
        }
    }

    /// Chooses a switch's branch, borrowed from the switch itself.
    fn switch_branch<'v>(&self, arguments: &'v Value) -> Decoded<&'v Value> {
        let subject = if let Some(literal) = arguments.get("compareToValue") {
            literal.clone()
        } else {
            let path = arguments
                .get("compareTo")
                .and_then(Value::as_str)
                .ok_or_else(|| self.failure("switch without compareTo"))?;
            self.lookup(path).unwrap_or(Value::Null)
        };
        let fields = arguments.get("fields").and_then(Value::as_object);
        let key = switch_key(&subject);
        let chosen = fields.and_then(|fields| {
            fields.get(&key).or_else(|| {
                let number = subject
                    .as_i64()
                    .or_else(|| subject.as_bool().map(i64::from))?;
                fields
                    .iter()
                    .find(|(candidate, _)| parse_number(candidate) == Some(number))
                    .map(|(_, ty)| ty)
            })
        });
        Ok(chosen.or_else(|| arguments.get("default")).unwrap_or(&VOID))
    }

    /// Resolves a `compareTo`/`count` path: `..` climbs one container, `/`
    /// descends into a decoded value.
    fn lookup(&self, path: &str) -> Option<Value> {
        let mut scope = self.scopes.len().checked_sub(1)?;
        let mut parts = path.split('/').peekable();
        while parts.peek() == Some(&"..") {
            parts.next();
            scope = scope.checked_sub(1)?;
        }
        let first = parts.next()?;
        let mut value = self.scopes.get(scope)?.get(first)?;
        for part in parts {
            value = value.get(part)?;
        }
        Some(value.clone())
    }

    fn bitfield(&mut self, fields: &[Value]) -> Decoded<Map<String, Value>> {
        let mut layout = Vec::with_capacity(fields.len());
        let mut total: u32 = 0;
        for field in fields {
            let name = field
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("bits")
                .to_owned();
            let size = field
                .get("size")
                .and_then(Value::as_u64)
                .and_then(|size| u32::try_from(size).ok())
                .filter(|size| (1..=64).contains(size))
                .ok_or_else(|| self.failure("bitfield member has no usable size"))?;
            let signed = field.get("signed").and_then(Value::as_bool) == Some(true);
            total += size;
            layout.push((name, size, signed));
        }
        if total == 0 || !total.is_multiple_of(8) || total > 128 {
            return self.fail(format!("bitfield of {total} bits"));
        }
        let start = self.position;
        let width = usize::try_from(total / 8).unwrap_or(16);
        let bytes = self.take(width)?.to_vec();
        let mut raw: u128 = 0;
        for byte in &bytes {
            raw = (raw << 8) | u128::from(*byte);
        }
        let mut object = Map::new();
        let mut shift = total;
        for (name, size, signed) in layout {
            shift -= size;
            let mask = if size == 128 {
                u128::MAX
            } else {
                (1u128 << size) - 1
            };
            let bits = (raw >> shift) & mask;
            let value = if signed && size < 128 && bits >> (size - 1) & 1 == 1 {
                // Sign-extend from the field's own width.
                i128::try_from(bits).unwrap_or(0) - (1i128 << size)
            } else {
                i128::try_from(bits).unwrap_or(0)
            };
            object.insert(
                name,
                i64::try_from(value).map_or_else(|_| Value::String(value.to_string()), Value::from),
            );
        }
        let (kind, value) = match bytes.len() {
            1 => (FieldKind::U8, Value::from(bytes[0])),
            2 => (
                FieldKind::U16,
                Value::from(u16::from_be_bytes([bytes[0], bytes[1]])),
            ),
            4 => (
                FieldKind::I32,
                Value::from(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            ),
            8 => {
                let mut array = [0u8; 8];
                array.copy_from_slice(&bytes);
                (FieldKind::I64, Value::from(i64::from_be_bytes(array)))
            }
            _ => (FieldKind::Bytes, Value::String(self.display_hex(&bytes))),
        };
        self.span(kind, start, value);
        Ok(object)
    }

    fn bitflags(&mut self, arguments: &Value, depth: usize) -> Decoded<Value> {
        let ty = arguments
            .get("type")
            .ok_or_else(|| self.failure("bitflags without a type"))?;
        let raw = self.read(ty, depth + 1)?;
        let bits = raw
            .as_u64()
            .or_else(|| raw.as_i64().map(i64::cast_unsigned))
            .ok_or_else(|| self.failure("bitflags value is not a number"))?;
        let shift = arguments.get("shift").and_then(Value::as_bool) == Some(true);
        let mut object = Map::new();
        object.insert("_value".into(), Value::from(bits));
        match arguments.get("flags") {
            Some(Value::Array(names)) => {
                for (index, name) in names.iter().enumerate() {
                    if let Some(name) = name.as_str()
                        && index < 64
                    {
                        object.insert(name.to_owned(), Value::Bool(bits >> index & 1 == 1));
                    }
                }
            }
            Some(Value::Object(names)) => {
                for (name, value) in names {
                    let Some(value) = value.as_u64() else {
                        continue;
                    };
                    let mask = if shift {
                        1u64.checked_shl(u32::try_from(value).unwrap_or(64))
                            .unwrap_or(0)
                    } else {
                        value
                    };
                    object.insert(name.clone(), Value::Bool(mask != 0 && bits & mask == mask));
                }
            }
            _ => {}
        }
        Ok(Value::Object(object))
    }

    /// The low-precision vector 1.21.9 introduced for entity velocities: one
    /// zero byte for a still entity, otherwise three 15-bit components and a
    /// scale packed into six bytes, with a `VarInt` extending the scale.
    fn low_precision_vector(&mut self) -> Decoded<Value> {
        let start = self.position;
        let first = self.take(1)?[0];
        if first == 0 {
            self.span(FieldKind::Bytes, start, Value::String("00".into()));
            return Ok(serde_json::json!({ "x": 0.0, "y": 0.0, "z": 0.0 }));
        }
        let second = self.take(1)?[0];
        let rest = self.take(4)?;
        let high = u64::from(u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]));
        let packed = high << 16 | u64::from(second) << 8 | u64::from(first);
        let mut scale = u64::from(first & 3);
        if first & 4 == 4 {
            let extension = u64::from(self.var_int()?.cast_unsigned());
            self.spans.pop();
            scale |= extension << 2;
        }
        let unpack = |value: u64| {
            #[allow(clippy::cast_precision_loss, reason = "15-bit values are exact in f64")]
            let component = ((value & 32_767) as f64).min(32_766.0);
            component * 2.0 / 32_766.0 - 1.0
        };
        #[allow(clippy::cast_precision_loss, reason = "the scale is a small integer")]
        let scale = scale as f64;
        let bytes = self.input[start..self.position].to_vec();
        self.span(
            FieldKind::Bytes,
            start,
            Value::String(self.display_hex(&bytes)),
        );
        Ok(serde_json::json!({
            "x": float(unpack(packed >> 3) * scale),
            "y": float(unpack(packed >> 18) * scale),
            "z": float(unpack(packed >> 33) * scale),
        }))
    }

    // --- NBT ---

    /// Reads one NBT value. `named` is the pre-1.20.2 form with a root name;
    /// `optional` accepts a lone `TAG_End` as "absent".
    fn nbt(&mut self, named: bool, optional: bool) -> Decoded<Value> {
        let start = self.position;
        let kind = if named {
            FieldKind::NamedNbt
        } else {
            FieldKind::Nbt
        };
        if self.target.is_some() {
            let length = crate::nbt::skip_nbt(&self.input[start..], named)
                .ok_or_else(|| self.failure("invalid NBT"))?;
            self.take(length)?;
            self.span(kind, start, Value::Null);
            return Ok(Value::Null);
        }
        let tag = self.take(1)?[0];
        if tag == 0 {
            if optional || !named {
                self.span(kind, start, Value::String(String::new()));
                return Ok(Value::Null);
            }
            return self.fail("NBT root is TAG_End");
        }
        if named {
            let length = usize::from(u16::from_be_bytes(self.take2()?));
            self.take(length)?;
        }
        let value = self.nbt_payload(tag, 0)?;
        let bytes = &self.input[start..self.position];
        // Large blobs (chunk block entities, registries) stay hex: as text
        // they would be too big to edit and slow to render.
        let text = (self.target.is_none() && bytes.len() <= crate::layout::MAX_NBT_TEXT_BYTES)
            .then(|| crate::nbt_text::to_text(bytes, named))
            .flatten();
        if let Some(text) = text {
            self.span(kind, start, Value::String(text));
        } else {
            let hex = self.display_hex(bytes);
            self.span(FieldKind::Bytes, start, Value::String(hex));
        }
        Ok(value)
    }

    fn take2(&mut self) -> Decoded<[u8; 2]> {
        let bytes = self.take(2)?;
        Ok([bytes[0], bytes[1]])
    }

    fn nbt_length(&mut self, element_width: usize) -> Decoded<usize> {
        let bytes = self.take(4)?;
        let length = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let length = usize::try_from(length)
            .map_err(|_| self.failure(&format!("negative NBT length {length}")))?;
        if length.saturating_mul(element_width.max(1)) > self.remaining() {
            return self.fail(format!(
                "NBT collection of {length} element(s) but only {} byte(s) remain",
                self.remaining()
            ));
        }
        Ok(length)
    }

    fn nbt_string(&mut self) -> Decoded<String> {
        let length = usize::from(u16::from_be_bytes(self.take2()?));
        let bytes = self.take(length)?.to_vec();
        Ok(decode_modified_utf8(&bytes)
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn nbt_payload(&mut self, tag: u8, depth: usize) -> Decoded<Value> {
        if depth > MAX_NBT_DEPTH {
            return self.fail("NBT nests too deeply");
        }
        self.tick()?;
        Ok(match tag {
            1 => Value::from(self.take(1)?[0].cast_signed()),
            2 => Value::from(i16::from_be_bytes(self.take2()?)),
            3 => {
                let bytes = self.take(4)?;
                Value::from(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            4 => {
                let bytes = self.take(8)?;
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                Value::from(i64::from_be_bytes(array))
            }
            5 => {
                let bytes = self.take(4)?;
                float(f64::from(f32::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            6 => {
                let bytes = self.take(8)?;
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                float(f64::from_be_bytes(array))
            }
            7 => {
                let length = self.nbt_length(1)?;
                let bytes = self.take(length)?.to_vec();
                if length > PREVIEW_ITEMS {
                    Value::String(format!("[{length} bytes]"))
                } else {
                    Value::Array(
                        bytes
                            .iter()
                            .map(|byte| Value::from(byte.cast_signed()))
                            .collect(),
                    )
                }
            }
            8 => Value::String(self.nbt_string()?),
            9 => {
                let item = self.take(1)?[0];
                // A list of TAG_End consumes nothing per element, so any
                // non-zero length is a request for unbounded work. Vanilla
                // rejects it too. This is checked before the length is
                // bounded by the bytes left, so the error names the cause.
                if item == 0 {
                    let bytes = self.take(4)?;
                    if i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) > 0 {
                        return self.fail("NBT list of TAG_End with a non-zero length");
                    }
                    return Ok(Value::Array(Vec::new()));
                }
                let length = self.nbt_length(1)?;
                let mut items = Vec::with_capacity(length.min(1_024));
                for _ in 0..length {
                    items.push(self.nbt_payload(item, depth + 1)?);
                }
                Value::Array(items)
            }
            10 => {
                let mut object = Map::new();
                loop {
                    let field = self.take(1)?[0];
                    if field == 0 {
                        break;
                    }
                    let name = self.nbt_string()?;
                    let value = self.nbt_payload(field, depth + 1)?;
                    object.insert(name, value);
                }
                Value::Object(object)
            }
            11 => self.nbt_numbers(4)?,
            12 => self.nbt_numbers(8)?,
            other => return self.fail(format!("unknown NBT tag {other}")),
        })
    }

    fn nbt_numbers(&mut self, width: usize) -> Decoded<Value> {
        let length = self.nbt_length(width)?;
        let bytes = self.take(length * width)?.to_vec();
        if length > PREVIEW_ITEMS {
            let kind = if width == 4 { "ints" } else { "longs" };
            return Ok(Value::String(format!("[{length} {kind}]")));
        }
        Ok(Value::Array(
            bytes
                .chunks_exact(width)
                .map(|chunk| {
                    if width == 4 {
                        Value::from(i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    } else {
                        let mut array = [0u8; 8];
                        array.copy_from_slice(chunk);
                        Value::from(i64::from_be_bytes(array))
                    }
                })
                .collect(),
        ))
    }

    /// 1.7/1.8 item NBT: an `i16` length, then a gzip stream. Inflation is
    /// capped so a small packet cannot ask for a large allocation.
    fn compressed_nbt(&mut self) -> Decoded<Value> {
        const MAX_INFLATED: u64 = 256 * 1024;
        let start = self.position;
        let length = i16::from_be_bytes(self.take2()?);
        let Ok(length) = usize::try_from(length) else {
            self.span(FieldKind::Bytes, start, Value::String("ffff".into()));
            return Ok(Value::Null);
        };
        let compressed = self.take(length)?.to_vec();
        let mut inflated = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .take(MAX_INFLATED)
            .read_to_end(&mut inflated)
            .map_err(|_| self.failure("compressed NBT does not inflate"))?;
        let bytes = self.input[start..self.position].to_vec();
        self.span(
            FieldKind::Bytes,
            start,
            Value::String(self.display_hex(&bytes)),
        );
        let mut inner = Decoder {
            target: self.target,
            input: &inflated,
            position: 0,
            local: self.local,
            global: self.global,
            nodes: self.nodes,
            spans: Vec::new(),
            spans_truncated: false,
            path: Vec::new(),
            scopes: Vec::new(),
            mask_top_bit_at: None,
        };
        let value = inner.nbt(true, false).map_err(|failure| Failure {
            at: start,
            ..failure
        })?;
        self.nodes = inner.nodes;
        Ok(value)
    }
}

/// Puts an array's decoded elements into a failure's partial value.
fn fold_array(mut failure: Failure, mut items: Vec<Value>) -> Failure {
    if let Some(partial) = failure.partial.take() {
        items.push(partial);
    }
    failure.partial = Some(Value::Array(items));
    failure
}

/// Replaces `$name` placeholders in a parameterised type with its arguments.
fn substitute(definition: &Value, arguments: &Value) -> Value {
    match definition {
        Value::String(text) => text
            .strip_prefix('$')
            .and_then(|key| arguments.get(key))
            .cloned()
            .unwrap_or_else(|| definition.clone()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| substitute(item, arguments))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), substitute(value, arguments)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// True for element types that read no bytes, so their count cannot be bounded
/// by the bytes left.
fn zero_width(ty: &Value) -> bool {
    match ty {
        Value::String(name) => name == "void",
        Value::Array(parts) => {
            parts.first().and_then(Value::as_str) == Some("container")
                && parts
                    .get(1)
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        }
        _ => false,
    }
}

fn switch_key(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Null => "undefined".into(),
        other => other.to_string(),
    }
}

fn map_value(mappings: Option<&Value>, raw: &Value) -> Option<Value> {
    let mappings = mappings?.as_object()?;
    let key = switch_key(raw);
    if let Some(name) = mappings.get(&key) {
        return Some(name.clone());
    }
    let number = raw.as_i64()?;
    mappings
        .iter()
        .find(|(candidate, _)| parse_number(candidate) == Some(number))
        .map(|(_, name)| name.clone())
}

fn parse_number(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse().ok()
}

fn float(value: f64) -> Value {
    if value.is_finite() {
        Value::from(value)
    } else {
        Value::String(value.to_string())
    }
}

fn preview(bytes: &[u8]) -> Value {
    if bytes.len() <= PREVIEW_BYTES {
        return Value::String(to_hex(bytes));
    }
    Value::String(format!(
        "{} bytes: {}…",
        bytes.len(),
        to_hex(&bytes[..PREVIEW_BYTES])
    ))
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Decodes Java's modified UTF-8: NUL as two bytes, and characters outside the
/// basic plane as surrogate pairs of three bytes each. Plain UTF-8 is accepted
/// too, because some writers emit it.
fn decode_modified_utf8(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        if first < 0x80 {
            units.push(u16::from(first));
            index += 1;
        } else if first & 0xe0 == 0xc0 {
            let second = *bytes.get(index + 1)?;
            units.push(u16::from(first & 0x1f) << 6 | u16::from(second & 0x3f));
            index += 2;
        } else if first & 0xf0 == 0xe0 {
            let second = *bytes.get(index + 1)?;
            let third = *bytes.get(index + 2)?;
            units.push(
                u16::from(first & 0x0f) << 12
                    | u16::from(second & 0x3f) << 6
                    | u16::from(third & 0x3f),
            );
            index += 3;
        } else {
            return std::str::from_utf8(bytes).ok().map(str::to_owned);
        }
    }
    String::from_utf16(&units)
        .ok()
        .or_else(|| std::str::from_utf8(bytes).ok().map(str::to_owned))
}

/// `serverHost` → `server_host`, `playerUUID` → `player_uuid`.
pub(crate) fn snake_case(name: &str) -> String {
    let mut output = String::with_capacity(name.len() + 4);
    let mut previous_lower = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() {
            if previous_lower {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
            previous_lower = false;
        } else {
            output.push(character);
            previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        }
    }
    output
}

/// Rewrites a decoded tree's keys to `snake_case`. NBT compound keys are data
/// rather than field names, but they are already lower-case by convention, so
/// the rewrite leaves them as they are in practice.
fn snake_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let key =
                        if key.starts_with('_') || !key.chars().any(|c| c.is_ascii_uppercase()) {
                            key
                        } else {
                            snake_case(&key)
                        };
                    (key, snake_keys(value))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(snake_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(types: &Value, body: &[u8]) -> DefinitionDecode {
        let global = Map::new();
        let side = types.as_object().unwrap();
        let mut decoder = Decoder {
            target: None,
            input: body,
            position: 0,
            local: side,
            global: &global,
            nodes: 0,
            spans: Vec::new(),
            spans_truncated: false,
            path: Vec::new(),
            scopes: Vec::new(),
            mask_top_bit_at: None,
        };
        let ty = side.get("packet_test").unwrap();
        let result = decoder.read(ty, 0);
        let consumed = decoder.position;
        let (fields, error) = match result {
            Ok(value) => (value, None),
            Err(failure) => (
                failure.partial.unwrap_or(Value::Null),
                Some(failure.message),
            ),
        };
        DefinitionDecode {
            packet: "test".into(),
            fields: snake_keys(fields),
            spans: decoder.spans,
            consumed,
            error,
        }
    }

    fn types(packet: &Value) -> Value {
        serde_json::json!({
            "varint": "native", "u8": "native", "i8": "native", "bool": "native",
            "pstring": "native", "container": "native", "switch": "native",
            "array": "native", "option": "native", "bitflags": "native",
            "string": ["pstring", { "countType": "varint" }],
            "packet_test": packet,
        })
    }

    #[test]
    fn decodes_containers_switches_and_relative_paths_with_spans() {
        let packet = serde_json::json!(["container", [
            { "name": "action", "type": ["bitflags", { "type": "u8", "flags": ["add", "remove"] }] },
            { "name": "entries", "type": ["array", { "countType": "varint", "type": ["container", [
                { "name": "playerName", "type": "string" },
                { "name": "extra", "type": ["switch", {
                    "compareTo": "../action/add", "fields": { "true": "varint" }, "default": "void"
                }] }
            ]] }] }
        ]]);
        let body = [0x01, 0x01, 0x02, b'h', b'i', 0x2a];
        let decoded = decode(&types(&packet), &body);
        assert_eq!(decoded.error, None);
        assert_eq!(decoded.consumed, body.len());
        assert_eq!(decoded.fields["action"]["add"], Value::Bool(true));
        assert_eq!(decoded.fields["entries"][0]["player_name"], "hi");
        assert_eq!(decoded.fields["entries"][0]["extra"], 42);
        let name = decoded
            .spans
            .iter()
            .find(|span| span.name == "entries[0].player_name")
            .expect("the string has a span");
        assert_eq!(
            (name.offset, name.length, name.kind),
            (2, 3, FieldKind::String)
        );
    }

    #[test]
    fn anonymous_containers_share_their_parent_scope() {
        let packet = serde_json::json!(["container", [
            { "name": "count", "type": "varint" },
            { "anon": true, "type": ["switch", { "compareTo": "count", "fields": { "0": "void" },
                "default": ["container", [{ "name": "id", "type": "varint" }]] }] }
        ]]);
        let decoded = decode(&types(&packet), &[0x02, 0x07]);
        assert_eq!(decoded.fields["id"], 7);
        let decoded = decode(&types(&packet), &[0x00]);
        assert_eq!(decoded.error, None);
        assert!(decoded.fields.get("id").is_none());
    }

    #[test]
    fn a_count_past_the_remaining_bytes_is_refused_before_allocating() {
        let packet = serde_json::json!(["container", [
            { "name": "items", "type": ["array", { "countType": "varint", "type": "varint" }] }
        ]]);
        // A count of 2^28 in five bytes.
        let decoded = decode(&types(&packet), &[0x80, 0x80, 0x80, 0x80, 0x01]);
        assert!(decoded.error.unwrap().contains("remain"));
    }

    #[test]
    fn partial_decodes_keep_what_came_before_the_failure() {
        let packet = serde_json::json!(["container", [
            { "name": "first", "type": "varint" },
            { "name": "second", "type": "string" }
        ]]);
        let decoded = decode(&types(&packet), &[0x05, 0x09, b'x']);
        assert!(decoded.error.is_some());
        assert_eq!(decoded.fields["first"], 5);
    }

    #[test]
    fn nbt_lists_of_tag_end_with_a_length_are_rejected_immediately() {
        let packet = serde_json::json!(["container", [{ "name": "tag", "type": "anonymousNbt" }]]);
        let mut types = types(&packet);
        types["anonymousNbt"] = Value::String("native".into());
        // A compound holding a list of three TAG_Ends: small enough to pass the
        // remaining-bytes check, still unbounded work if it were accepted.
        let body = [
            0x0a, 0x09, 0x00, 0x01, b'a', 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        let decoded = decode(&types, &body);
        assert!(decoded.error.unwrap().contains("TAG_End"));
        // And a length past the bytes present is refused before allocating.
        let body = [
            0x0a, 0x09, 0x00, 0x01, b'a', 0x01, 0x7f, 0xff, 0xff, 0xff, 0x00,
        ];
        let decoded = decode(&types, &body);
        assert!(decoded.error.unwrap().contains("remain"));
    }

    #[test]
    fn nbt_fields_are_laid_out_as_editable_json() {
        let packet = serde_json::json!(["container", [
            { "name": "tag", "type": "anonymousNbt" },
            { "name": "extra", "type": "anonymousNbt" }
        ]]);
        let mut types = types(&packet);
        types["anonymousNbt"] = Value::String("native".into());
        // {a: 5b} followed by an absent value.
        let body = [0x0a, 0x01, 0x00, 0x01, b'a', 0x05, 0x00, 0x00];
        let decoded = decode(&types, &body);
        assert!(decoded.error.is_none());
        let kinds: Vec<_> = decoded
            .spans
            .iter()
            .map(|span| (span.kind, span.value.clone()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (FieldKind::Nbt, Value::String(r#"{"a": 5}"#.into())),
                (FieldKind::Nbt, Value::String(String::new())),
            ]
        );
        let encoded = crate::layout::encode_field_over(
            FieldKind::Nbt,
            &Value::String(r#"{"a": 7}"#.into()),
            Some(&body[..7]),
        );
        assert_eq!(
            encoded.unwrap(),
            vec![0x0a, 0x01, 0x00, 0x01, b'a', 0x07, 0x00]
        );
    }

    #[test]
    fn modified_utf8_decodes_surrogate_pairs_and_nul() {
        // U+1F600 as a CESU-8 surrogate pair, then NUL as C0 80.
        let bytes = [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0xc0, 0x80];
        assert_eq!(decode_modified_utf8(&bytes).unwrap(), "\u{1F600}\u{0}");
    }

    #[test]
    fn names_become_snake_case() {
        assert_eq!(snake_case("serverHost"), "server_host");
        assert_eq!(snake_case("playerUUID"), "player_uuid");
        assert_eq!(snake_case("UUID"), "uuid");
        assert_eq!(snake_case("x"), "x");
    }

    #[test]
    fn every_bundled_description_loads() {
        let protocols = definition_protocols();
        assert!(protocols.len() >= 40, "{protocols:?}");
        for protocol in protocols {
            assert!(
                definition(protocol).is_some(),
                "protocol {protocol} does not parse"
            );
        }
    }
}

#[cfg(test)]
mod coverage {
    use super::*;

    /// Walks every packet of every bundled release over an all-zero body.
    ///
    /// Zeros are a valid encoding of almost every field — empty strings, empty
    /// arrays, absent options, `TAG_End` — so a description the interpreter
    /// cannot walk shows up as an "unknown type" or a malformed expression
    /// rather than as a short read.
    #[test]
    fn every_bundled_packet_description_is_understood() {
        let zeros = vec![0u8; 512];
        let mut problems = Vec::new();
        for protocol in definition_protocols() {
            let root = definition(protocol).unwrap();
            for (state_name, state) in [
                ("handshaking", ProtocolState::Handshake),
                ("status", ProtocolState::Status),
                ("login", ProtocolState::Login),
                ("configuration", ProtocolState::Configuration),
                ("play", ProtocolState::Play),
            ] {
                for (side_name, direction) in [
                    ("toServer", Direction::ClientToServer),
                    ("toClient", Direction::ServerToClient),
                ] {
                    let Some(packet) = root
                        .get(state_name)
                        .and_then(|value| value.get(side_name))
                        .and_then(|value| value.get("types"))
                        .and_then(|value| value.get("packet"))
                    else {
                        continue;
                    };
                    let ids: Vec<i64> = packet
                        .get(1)
                        .and_then(Value::as_array)
                        .and_then(|fields| fields.first())
                        .and_then(|field| field.get("type"))
                        .and_then(|ty| ty.get(1))
                        .and_then(|ty| ty.get("mappings"))
                        .and_then(Value::as_object)
                        .map(|mappings| {
                            mappings
                                .keys()
                                .filter_map(|key| parse_number(key))
                                .collect()
                        })
                        .unwrap_or_default();
                    for id in ids {
                        let id = i32::try_from(id).unwrap();
                        let Some(decoded) =
                            decode_packet(state, direction, id, &zeros, Some(protocol))
                        else {
                            problems.push(format!(
                                "{protocol} {state_name} {side_name} {id:#x}: no type"
                            ));
                            continue;
                        };
                        if let Some(error) = decoded.error
                            && (error.contains("unknown")
                                || error.contains("malformed")
                                || error.contains("without")
                                || error.contains("no usable"))
                        {
                            problems.push(format!(
                                "{protocol} {state_name} {side_name} {}: {error}",
                                decoded.packet
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            problems.is_empty(),
            "{} problem(s):\n{}",
            problems.len(),
            problems.join("\n")
        );
    }
}

#[cfg(test)]
mod hostile {
    use super::*;

    /// Random bodies through every packet description of an old and a new
    /// release. Nothing may panic, and each decode must stay well inside its
    /// budgets; `MINEBURP_HOSTILE_ROUNDS` raises the count for a longer run.
    #[test]
    fn random_bodies_never_panic_or_run_away() {
        let rounds: usize = std::env::var("MINEBURP_HOSTILE_ROUNDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(6);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let protocols: Vec<i32> = if std::env::var("MINEBURP_HOSTILE_ROUNDS").is_ok() {
            definition_protocols()
        } else {
            vec![47, 774]
        };
        for protocol in protocols {
            for state_kind in [
                ProtocolState::Login,
                ProtocolState::Configuration,
                ProtocolState::Play,
            ] {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    for id in 0..0x90 {
                        for _ in 0..rounds {
                            let length = usize::try_from(next() % 2_048).unwrap();
                            let body: Vec<u8> = (0..length)
                                .map(|_| {
                                    let value = next();
                                    // Mostly small values, so decodes get deep.
                                    let bytes = value.to_le_bytes();
                                    if value % 3 == 0 {
                                        bytes[1]
                                    } else {
                                        bytes[0] % 4
                                    }
                                })
                                .collect();
                            let started = std::time::Instant::now();
                            let decoded =
                                decode_packet(state_kind, direction, id, &body, Some(protocol));
                            assert!(
                                started.elapsed() < std::time::Duration::from_secs(2),
                                "{protocol} {state_kind:?} {direction:?} {id:#x} took {:?}",
                                started.elapsed()
                            );
                            if let Some(decoded) = decoded {
                                assert!(decoded.consumed <= body.len());
                                assert!(
                                    decoded
                                        .spans
                                        .iter()
                                        .all(|span| span.offset + span.length <= body.len())
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod differential {
    use super::*;

    /// Compares the interpreter with node-minecraft-protocol over a corpus of
    /// bodies the reference parsed, one JSON object per line:
    /// `{protocol, state, toServer, id, name, hex, size}`. The corpus is large
    /// and generated, so the test only runs when pointed at one:
    ///
    /// `MINEBURP_DIFF_CORPUS=corpus.jsonl cargo test -p mineburp-protocol differential -- --ignored`
    #[test]
    #[ignore = "needs a generated corpus"]
    fn agrees_with_the_reference_implementation_on_consumed_bytes() {
        let Ok(path) = std::env::var("MINEBURP_DIFF_CORPUS") else {
            return;
        };
        let text = std::fs::read_to_string(path).unwrap();
        let mut total = 0usize;
        let mut mismatches: std::collections::BTreeMap<String, (usize, String)> =
            std::collections::BTreeMap::new();
        for line in text.lines() {
            let entry: Value = serde_json::from_str(line).unwrap();
            let protocol = i32::try_from(entry["protocol"].as_i64().unwrap()).unwrap();
            let state = match entry["state"].as_str().unwrap() {
                "handshaking" => ProtocolState::Handshake,
                "status" => ProtocolState::Status,
                "login" => ProtocolState::Login,
                "configuration" => ProtocolState::Configuration,
                _ => ProtocolState::Play,
            };
            let direction = if entry["toServer"].as_bool().unwrap() {
                Direction::ClientToServer
            } else {
                Direction::ServerToClient
            };
            let id = i32::try_from(entry["id"].as_i64().unwrap()).unwrap();
            let bytes = hex::decode(entry["hex"].as_str().unwrap()).unwrap();
            let size = usize::try_from(entry["size"].as_u64().unwrap()).unwrap();
            let (_, prefix) = crate::varint::decode_var_i32(&bytes).unwrap().unwrap();
            let body = &bytes[prefix..];
            total += 1;
            let decoded = decode_packet(state, direction, id, body, Some(protocol));
            let ours = decoded.as_ref().map(|decoded| decoded.consumed + prefix);
            // The reference is laxer than vanilla in places this interpreter
            // deliberately is not: it reads an unknown NBT tag as nothing,
            // treats a negative count as zero, accepts a list of TAG_End with
            // a length, and stops reading an NBT list whose length exceeds the
            // bytes present instead of failing.
            let deliberate = |error: &str| {
                error.contains("trailing")
                    || error.contains("unknown NBT tag")
                    || error.contains("negative")
                    || error.contains("TAG_End")
                    || error.contains("NBT collection")
            };
            if decoded
                .as_ref()
                .and_then(|decoded| decoded.error.as_deref())
                .is_some_and(deliberate)
            {
                continue;
            }
            let failed = decoded.as_ref().and_then(|decoded| decoded.error.clone());
            if ours != Some(size) || failed.is_some() {
                let key = format!(
                    "{protocol} {} {} {}",
                    entry["state"].as_str().unwrap(),
                    if direction == Direction::ClientToServer {
                        "sb"
                    } else {
                        "cb"
                    },
                    entry["name"].as_str().unwrap()
                );
                let detail = format!(
                    "reference read {size}, ours {ours:?} error {failed:?} hex {}",
                    entry["hex"].as_str().unwrap()
                );
                mismatches.entry(key).or_insert((0, detail)).0 += 1;
            }
        }
        let report: Vec<String> = mismatches
            .iter()
            .map(|(key, (count, detail))| format!("{count:>5} {key}: {detail}"))
            .collect();
        assert!(
            report.is_empty(),
            "{} of {total} disagree across {} packet(s):\n{}",
            mismatches.values().map(|(count, _)| count).sum::<usize>(),
            report.len(),
            report.join("\n")
        );
    }
}

#[cfg(test)]
mod holder_overflow_regression {
    #[test]
    fn minimum_holder_id_does_not_panic() {
        let decode = super::decode_packet(
            mineburp_core::ProtocolState::Play,
            mineburp_core::Direction::ServerToClient,
            0x68,
            &[0x80, 0x80, 0x80, 0x80, 0x08],
            Some(767),
        )
        .unwrap();
        assert!(decode.error.is_some());
    }
}
