use std::{collections::HashSet, io::Cursor};

use indexmap::IndexMap;
use mineburp_core::{Direction, ProtocolState};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{decode_var_i32, decode_var_i64};

const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_COLLECTION_LENGTH: usize = 1_000_000;
/// Total values one decode may produce. Array counts are already bounded by
/// the bytes left, but an item that reads nothing — an empty struct, a zero
/// length byte field — would otherwise let a count multiply output for free.
const MAX_DECODED_NODES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaPackManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub minecraft_versions: Vec<String>,
    #[serde(default)]
    pub loaders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaPack {
    pub manifest: SchemaPackManifest,
    pub schemas: Vec<SchemaDefinition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaDefinition {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: MatchDefinition,
    pub fields: Vec<FieldDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchDefinition {
    pub state: ProtocolState,
    pub direction: Direction,
    pub packet_id: Option<i32>,
    pub channel: Option<String>,
    pub protocol_min: Option<i32>,
    pub protocol_max: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub name: String,
    #[serde(flatten)]
    pub kind: TypeDefinition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TypeDefinition {
    Bool,
    U8,
    I8,
    U16Be,
    I16Be,
    U32Be,
    I32Be,
    I64Be,
    F32Be,
    F64Be,
    VarInt,
    VarLong,
    Uuid,
    String {
        max_length: Option<usize>,
    },
    Bytes {
        length: Option<usize>,
        rest: Option<bool>,
    },
    Array {
        count_field: Option<String>,
        count: Option<usize>,
        item: Box<TypeDefinition>,
    },
    Struct {
        fields: Vec<FieldDefinition>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct DecodeContext {
    pub max_depth: usize,
    pub max_collection_length: usize,
}

impl Default for DecodeContext {
    fn default() -> Self {
        Self {
            max_depth: MAX_SCHEMA_DEPTH,
            max_collection_length: MAX_COLLECTION_LENGTH,
        }
    }
}

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("schema pack id, name, and version are required")]
    InvalidManifest,
    #[error("invalid schema: {0}")]
    InvalidDefinition(String),
    #[error("duplicate schema name `{0}`")]
    DuplicateSchema(String),
    #[error("duplicate field `{0}`")]
    DuplicateField(String),
    #[error("schema nesting exceeds the configured depth")]
    TooDeep,
    #[error("collection length {0} exceeds the configured limit")]
    CollectionTooLarge(usize),
    #[error("truncated value while reading `{0}`")]
    Truncated(String),
    #[error("invalid UTF-8 in `{0}`")]
    InvalidUtf8(String),
    #[error("invalid length in `{0}`")]
    InvalidLength(String),
    #[error("array count field `{0}` is missing or is not an integer")]
    InvalidCountField(String),
    #[error("decoded output exceeds the decoding budget")]
    BudgetExceeded,
    #[error(transparent)]
    Protocol(#[from] crate::ProtocolError),
}

impl SchemaPack {
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.manifest.id.trim().is_empty()
            || self.manifest.name.trim().is_empty()
            || self.manifest.version.trim().is_empty()
        {
            return Err(SchemaError::InvalidManifest);
        }
        let mut names = HashSet::new();
        for schema in &self.schemas {
            if !names.insert(schema.name.as_str()) {
                return Err(SchemaError::DuplicateSchema(schema.name.clone()));
            }
            if let (Some(min), Some(max)) =
                (schema.matcher.protocol_min, schema.matcher.protocol_max)
                && min > max
            {
                return Err(SchemaError::InvalidDefinition(
                    "protocol_min exceeds protocol_max".into(),
                ));
            }
            validate_fields(&schema.fields, 0)?;
        }
        Ok(())
    }
}

impl SchemaDefinition {
    /// Whether this schema applies to a packet, without decoding it.
    ///
    /// Cheap enough to run over every captured packet, unlike the decode
    /// itself, which is deferred until a packet is opened.
    #[must_use]
    pub fn matches(
        &self,
        state: ProtocolState,
        direction: Direction,
        packet_id: i32,
        channel: Option<&str>,
        protocol_version: Option<i32>,
    ) -> bool {
        let matcher = &self.matcher;
        matcher.state == state
            && matcher.direction == direction
            && matcher
                .packet_id
                .is_none_or(|expected| expected == packet_id)
            && matcher
                .channel
                .as_deref()
                .is_none_or(|expected| Some(expected) == channel)
            && matcher
                .protocol_min
                .is_none_or(|minimum| protocol_version.is_some_and(|value| value >= minimum))
            && matcher
                .protocol_max
                .is_none_or(|maximum| protocol_version.is_some_and(|value| value <= maximum))
    }
}

fn validate_fields(fields: &[FieldDefinition], depth: usize) -> Result<(), SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::TooDeep);
    }
    let mut names = HashSet::new();
    let mut integers = HashSet::new();
    for field in fields {
        if !names.insert(field.name.as_str()) {
            return Err(SchemaError::DuplicateField(field.name.clone()));
        }
        if let TypeDefinition::Array {
            count_field: Some(name),
            ..
        } = &field.kind
            && !integers.contains(name.as_str())
        {
            return Err(SchemaError::InvalidCountField(name.clone()));
        }
        validate_counts(&field.kind, &integers)?;
        validate_type(&field.kind, depth + 1)?;
        if matches!(
            field.kind,
            TypeDefinition::U8
                | TypeDefinition::I8
                | TypeDefinition::U16Be
                | TypeDefinition::I16Be
                | TypeDefinition::U32Be
                | TypeDefinition::I32Be
                | TypeDefinition::I64Be
                | TypeDefinition::VarInt
                | TypeDefinition::VarLong
        ) {
            integers.insert(field.name.as_str());
        }
    }
    Ok(())
}

fn validate_counts(kind: &TypeDefinition, integers: &HashSet<&str>) -> Result<(), SchemaError> {
    if let TypeDefinition::Array {
        count_field, item, ..
    } = kind
    {
        if let Some(name) = count_field
            && !integers.contains(name.as_str())
        {
            return Err(SchemaError::InvalidCountField(name.clone()));
        }
        validate_counts(item, integers)?;
    }
    Ok(())
}

fn validate_type(kind: &TypeDefinition, depth: usize) -> Result<(), SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::TooDeep);
    }
    match kind {
        TypeDefinition::Array {
            count: None,
            count_field: None,
            ..
        } => Err(SchemaError::InvalidDefinition(
            "array requires count or count_field".into(),
        )),
        TypeDefinition::Bytes { length: None, rest } if *rest != Some(true) => Err(
            SchemaError::InvalidDefinition("bytes requires length or rest: true".into()),
        ),
        TypeDefinition::Struct { fields } => validate_fields(fields, depth + 1),
        TypeDefinition::Array { item, .. } => validate_type(item, depth + 1),
        _ => Ok(()),
    }
}

pub fn decode_schema(
    schema: &SchemaDefinition,
    input: &[u8],
    context: DecodeContext,
) -> Result<Value, SchemaError> {
    let mut cursor = Cursor::new(input);
    let mut values = IndexMap::new();
    let mut budget = MAX_DECODED_NODES;
    decode_fields(
        &schema.fields,
        &mut cursor,
        &mut values,
        context,
        0,
        &mut budget,
    )?;
    let mut object = Map::new();
    for (key, value) in values {
        object.insert(key, value);
    }
    let position = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    object.insert(
        "_remaining_bytes".into(),
        Value::from(u64::try_from(input.len().saturating_sub(position)).unwrap_or(u64::MAX)),
    );
    Ok(Value::Object(object))
}

fn decode_fields(
    fields: &[FieldDefinition],
    cursor: &mut Cursor<&[u8]>,
    values: &mut IndexMap<String, Value>,
    context: DecodeContext,
    depth: usize,
    budget: &mut usize,
) -> Result<(), SchemaError> {
    if depth > context.max_depth {
        return Err(SchemaError::TooDeep);
    }
    for field in fields {
        let value = decode_type(
            &field.name,
            &field.kind,
            cursor,
            values,
            context,
            depth + 1,
            budget,
        )?;
        values.insert(field.name.clone(), value);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn decode_type(
    name: &str,
    kind: &TypeDefinition,
    cursor: &mut Cursor<&[u8]>,
    values: &IndexMap<String, Value>,
    context: DecodeContext,
    depth: usize,
    budget: &mut usize,
) -> Result<Value, SchemaError> {
    if depth > context.max_depth {
        return Err(SchemaError::TooDeep);
    }
    *budget = budget.checked_sub(1).ok_or(SchemaError::BudgetExceeded)?;
    match kind {
        TypeDefinition::Bool => Ok(Value::Bool(read_exact::<1>(cursor, name)?[0] != 0)),
        TypeDefinition::U8 => Ok(Value::from(read_exact::<1>(cursor, name)?[0])),
        TypeDefinition::I8 => Ok(Value::from(i8::from_be_bytes(read_exact::<1>(
            cursor, name,
        )?))),
        TypeDefinition::U16Be => Ok(Value::from(u16::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::I16Be => Ok(Value::from(i16::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::U32Be => Ok(Value::from(u32::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::I32Be => Ok(Value::from(i32::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::I64Be => Ok(Value::from(i64::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::F32Be => Ok(Value::from(f32::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::F64Be => Ok(Value::from(f64::from_be_bytes(read_exact(cursor, name)?))),
        TypeDefinition::VarInt => {
            let remaining = remaining(cursor);
            let Some((value, length)) = decode_var_i32(remaining)? else {
                return Err(SchemaError::Truncated(name.into()));
            };
            cursor.set_position(cursor.position() + length as u64);
            Ok(Value::from(value))
        }
        TypeDefinition::VarLong => {
            let remaining = remaining(cursor);
            let Some((value, length)) = decode_var_i64(remaining)? else {
                return Err(SchemaError::Truncated(name.into()));
            };
            cursor.set_position(cursor.position() + length as u64);
            Ok(Value::from(value))
        }
        TypeDefinition::Uuid => {
            let bytes = read_exact::<16>(cursor, name)?;
            Ok(Value::String(uuid::Uuid::from_bytes(bytes).to_string()))
        }
        TypeDefinition::String { max_length } => {
            let remaining = remaining(cursor);
            let Some((length, prefix)) = decode_var_i32(remaining)? else {
                return Err(SchemaError::Truncated(name.into()));
            };
            let length =
                usize::try_from(length).map_err(|_| SchemaError::InvalidLength(name.into()))?;
            if max_length.is_some_and(|limit| length > limit)
                || length > context.max_collection_length
            {
                return Err(SchemaError::CollectionTooLarge(length));
            }
            cursor.set_position(cursor.position() + prefix as u64);
            let bytes = read_dynamic(cursor, length, name)?;
            String::from_utf8(bytes)
                .map(Value::String)
                .map_err(|_| SchemaError::InvalidUtf8(name.into()))
        }
        TypeDefinition::Bytes { length, rest } => {
            let length = if rest.unwrap_or(false) {
                remaining(cursor).len()
            } else {
                length.ok_or_else(|| SchemaError::InvalidLength(name.into()))?
            };
            if length > context.max_collection_length {
                return Err(SchemaError::CollectionTooLarge(length));
            }
            Ok(Value::String(hex_string(&read_dynamic(
                cursor, length, name,
            )?)))
        }
        TypeDefinition::Array {
            count_field,
            count,
            item,
        } => {
            let count = if let Some(count) = count {
                *count
            } else if let Some(field) = count_field {
                values
                    .get(field)
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| SchemaError::InvalidCountField(field.clone()))?
            } else {
                return Err(SchemaError::InvalidLength(name.into()));
            };
            // Every item reads at least its minimum width, so a count that
            // cannot fit in what is left is rejected before any work is done.
            let fits = count
                .checked_mul(minimum_width(item))
                .is_some_and(|needed| needed <= remaining(cursor).len());
            if count > context.max_collection_length || !fits {
                return Err(SchemaError::CollectionTooLarge(count));
            }
            let mut output = Vec::with_capacity(count.min(4_096));
            for index in 0..count {
                output.push(decode_type(
                    &format!("{name}[{index}]"),
                    item,
                    cursor,
                    values,
                    context,
                    depth + 1,
                    budget,
                )?);
            }
            Ok(Value::Array(output))
        }
        TypeDefinition::Struct { fields } => {
            let mut nested = IndexMap::new();
            decode_fields(fields, cursor, &mut nested, context, depth + 1, budget)?;
            Ok(Value::Object(nested.into_iter().collect()))
        }
    }
}

/// The fewest bytes one value of `kind` can occupy.
fn minimum_width(kind: &TypeDefinition) -> usize {
    match kind {
        TypeDefinition::Bool
        | TypeDefinition::U8
        | TypeDefinition::I8
        | TypeDefinition::VarInt
        | TypeDefinition::VarLong
        | TypeDefinition::String { .. } => 1,
        TypeDefinition::U16Be | TypeDefinition::I16Be => 2,
        TypeDefinition::U32Be | TypeDefinition::I32Be | TypeDefinition::F32Be => 4,
        TypeDefinition::I64Be | TypeDefinition::F64Be => 8,
        TypeDefinition::Uuid => 16,
        TypeDefinition::Bytes { length, rest } => {
            if rest.unwrap_or(false) {
                0
            } else {
                length.unwrap_or(0)
            }
        }
        TypeDefinition::Array { count, item, .. } => {
            count.unwrap_or(0).saturating_mul(minimum_width(item))
        }
        TypeDefinition::Struct { fields } => fields
            .iter()
            .map(|field| minimum_width(&field.kind))
            .fold(0, usize::saturating_add),
    }
}

fn read_exact<const N: usize>(
    cursor: &mut Cursor<&[u8]>,
    name: &str,
) -> Result<[u8; N], SchemaError> {
    let bytes = read_dynamic(cursor, N, name)?;
    bytes
        .try_into()
        .map_err(|_| SchemaError::Truncated(name.into()))
}

fn read_dynamic(
    cursor: &mut Cursor<&[u8]>,
    length: usize,
    name: &str,
) -> Result<Vec<u8>, SchemaError> {
    let position = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    let end = position
        .checked_add(length)
        .ok_or_else(|| SchemaError::InvalidLength(name.into()))?;
    let data = cursor
        .get_ref()
        .get(position..end)
        .ok_or_else(|| SchemaError::Truncated(name.into()))?
        .to_vec();
    cursor.set_position(end as u64);
    Ok(data)
}

fn remaining<'a>(cursor: &'a Cursor<&'a [u8]>) -> &'a [u8] {
    let position = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    cursor.get_ref().get(position..).unwrap_or_default()
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_declarative_payload() {
        let schema = SchemaDefinition {
            name: "example".into(),
            matcher: MatchDefinition {
                state: ProtocolState::Play,
                direction: Direction::ClientToServer,
                packet_id: None,
                channel: Some("example:message".into()),
                protocol_min: None,
                protocol_max: None,
            },
            fields: vec![
                FieldDefinition {
                    name: "enabled".into(),
                    kind: TypeDefinition::Bool,
                },
                FieldDefinition {
                    name: "message".into(),
                    kind: TypeDefinition::String {
                        max_length: Some(32),
                    },
                },
            ],
        };
        let decoded = decode_schema(
            &schema,
            &[1, 5, b'h', b'e', b'l', b'l', b'o'],
            DecodeContext::default(),
        )
        .unwrap();
        assert_eq!(decoded["enabled"], true);
        assert_eq!(decoded["message"], "hello");
    }

    fn schema(fields: Vec<FieldDefinition>) -> SchemaDefinition {
        SchemaDefinition {
            name: "bounded".into(),
            matcher: MatchDefinition {
                state: ProtocolState::Play,
                direction: Direction::ServerToClient,
                packet_id: None,
                channel: None,
                protocol_min: None,
                protocol_max: None,
            },
            fields,
        }
    }

    #[test]
    fn an_array_count_larger_than_the_input_is_rejected_up_front() {
        let definition = schema(vec![
            FieldDefinition {
                name: "count".into(),
                kind: TypeDefinition::VarInt,
            },
            FieldDefinition {
                name: "items".into(),
                kind: TypeDefinition::Array {
                    count_field: Some("count".into()),
                    count: None,
                    item: Box::new(TypeDefinition::I64Be),
                },
            },
        ]);
        // 100 longs claimed, 16 bytes present.
        let mut input = vec![100];
        input.extend_from_slice(&[0; 16]);
        assert!(matches!(
            decode_schema(&definition, &input, DecodeContext::default()),
            Err(SchemaError::CollectionTooLarge(100))
        ));
    }

    #[test]
    fn zero_width_items_cannot_amplify_output() {
        let empty = TypeDefinition::Struct { fields: vec![] };
        let inner = TypeDefinition::Array {
            count_field: None,
            count: Some(1_000_000),
            item: Box::new(empty),
        };
        let definition = schema(vec![FieldDefinition {
            name: "outer".into(),
            kind: TypeDefinition::Array {
                count_field: None,
                count: Some(1_000_000),
                item: Box::new(inner),
            },
        }]);
        let started = std::time::Instant::now();
        assert!(matches!(
            decode_schema(&definition, &[], DecodeContext::default()),
            Err(SchemaError::BudgetExceeded)
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}

#[cfg(test)]
mod validation_regression {
    use super::*;
    #[test]
    fn reversed_protocol_range_is_rejected() {
        let pack: SchemaPack = serde_json::from_value(serde_json::json!({
            "manifest":{"id":"test","name":"test","version":"1"},
            "schemas":[{"name":"test","match":{"state":"play","direction":"client_to_server","protocol_min":776,"protocol_max":765},"fields":[]}]
        })).unwrap();
        assert!(matches!(
            pack.validate(),
            Err(SchemaError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn impossible_layouts_are_rejected() {
        for fields in [
            serde_json::json!([{"name":"x","type":"array","item":{"type":"u8"}}]),
            serde_json::json!([{"name":"x","type":"bytes"}]),
            serde_json::json!([{"name":"x","type":"array","count_field":"later","item":{"type":"u8"}},{"name":"later","type":"u8"}]),
            serde_json::json!([{"name":"n","type":"bool"},{"name":"x","type":"array","count_field":"n","item":{"type":"u8"}}]),
        ] {
            let fields: Vec<FieldDefinition> = serde_json::from_value(fields).unwrap();
            assert!(validate_fields(&fields, 0).is_err());
        }
    }
}
