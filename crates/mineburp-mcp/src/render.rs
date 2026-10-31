//! Compact text rendering.
//!
//! Every byte here is read by a model with a finite context, so the rules are:
//! say nothing that is the default, abbreviate what repeats on every line, cap
//! anything unbounded and say how to get the rest.

use std::fmt::Write as _;

use mineburp_core::{
    ConnectionSnapshot, Direction, Disposition, PacketSummary, ProtocolState, TrafficSource,
};
use mineburp_protocol::{FieldSpan, PacketInsight};
use serde_json::Value;
use uuid::Uuid;

/// The connection id as every tool prints it and accepts it back.
pub fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_owned()
}

pub const fn dir(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToServer => "C>S",
        Direction::ServerToClient => "S>C",
    }
}

pub fn enum_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub fn state(state: ProtocolState) -> String {
    enum_name(&state)
}

/// `HH:MM:SS.mmm` in UTC.
pub fn time(micros: i64) -> String {
    let millis = micros.div_euclid(1_000);
    let day_millis = millis.rem_euclid(86_400_000);
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        day_millis / 3_600_000,
        day_millis / 60_000 % 60,
        day_millis / 1_000 % 60,
        day_millis % 1_000
    )
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, for headers.
pub fn datetime(micros: i64) -> String {
    let days = micros.div_euclid(86_400_000_000);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {}", &time(micros)[..8])
}

/// Howard Hinnant's days-to-civil conversion.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[allow(clippy::cast_precision_loss)]
pub fn bytes(count: u64) -> String {
    match count {
        0..1_024 => format!("{count}B"),
        1_024..1_048_576 => format!("{:.1}KB", count as f64 / 1_024.0),
        1_048_576..1_073_741_824 => format!("{:.1}MB", count as f64 / 1_048_576.0),
        _ => format!("{:.2}GB", count as f64 / 1_073_741_824.0),
    }
}

pub fn truncate(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max).collect();
    let rest = chars.count();
    if rest == 0 {
        head
    } else {
        format!("{head}…(+{rest})")
    }
}

/// One history row: `#id time dir state 0xid name size [disp] [conn] [ch=..]`.
pub fn packet_line(packet: &PacketSummary, show_connection: bool) -> String {
    let mut line = format!(
        "#{} {} {} {} {} {} {}",
        packet.id,
        time(packet.timestamp_micros),
        dir(packet.direction),
        state(packet.state),
        packet
            .packet_id
            .map_or_else(|| "--".to_owned(), |id| format!("0x{id:02x}")),
        packet.name.as_deref().unwrap_or("?"),
        bytes(packet.size as u64),
    );
    if !matches!(
        packet.disposition,
        Disposition::Forwarded | Disposition::Observed
    ) {
        let _ = write!(line, " [{}]", enum_name(&packet.disposition));
    }
    if packet.source == TrafficSource::SideChannel && packet.state == ProtocolState::Opaque {
        line.push_str(" raw");
    }
    if show_connection {
        let _ = write!(line, " c={}", short_id(packet.connection_id));
    }
    if let Some(channel) = &packet.channel {
        let _ = write!(line, " ch={channel}");
    }
    line
}

pub fn connection_line(connection: &ConnectionSnapshot, live: bool) -> String {
    let mut text = format!(
        "{} {} {} {}",
        short_id(connection.id),
        connection.target.authority(),
        enum_name(&connection.status),
        state(connection.state),
    );
    match (&connection.minecraft_version, connection.protocol_version) {
        (Some(version), Some(protocol)) => {
            let _ = write!(text, " {version}(p{protocol})");
        }
        (None, Some(protocol)) => {
            let _ = write!(text, " p{protocol}");
        }
        (Some(version), None) => {
            let _ = write!(text, " {version}");
        }
        (None, None) => {}
    }
    if let Some(loader) = &connection.loader {
        let _ = write!(text, " {loader}");
    }
    if connection.encrypted_client || connection.encrypted_server {
        text.push_str(" encrypted");
    }
    if let Some(threshold) = connection.compression_threshold {
        let _ = write!(text, " zlib>{threshold}");
    }
    let _ = write!(
        text,
        " {}pk {}",
        connection.packet_count,
        bytes(connection.byte_count)
    );
    if live {
        text.push_str(" LIVE");
    }
    if let Some(error) = &connection.last_error {
        let _ = write!(text, " err={}", truncate(error, 120));
    }
    text
}

/// Limits for [`tree`].
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names, reason = "each is a maximum")]
pub struct TreeLimits {
    pub max_lines: usize,
    pub max_items: usize,
    pub max_string: usize,
}

impl Default for TreeLimits {
    fn default() -> Self {
        Self {
            max_lines: 120,
            max_items: 16,
            max_string: 240,
        }
    }
}

/// Renders a decoded field tree as indented `key: value` lines.
pub fn tree(value: &Value, limits: TreeLimits) -> String {
    let mut out = Vec::new();
    let mut truncated = false;
    walk(value, None, 0, limits, &mut out, &mut truncated);
    let mut text = out.join("\n");
    if truncated {
        let _ = write!(
            text,
            "\n… more fields; narrow with `path` or raise `max_lines`"
        );
    }
    text
}

fn scalar(value: &Value, limits: TreeLimits) -> Option<String> {
    Some(match value {
        Value::Null => "null".into(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => {
            let text = truncate(text, limits.max_string);
            if text.contains('\n') || text.is_empty() || text.trim() != text {
                serde_json::to_string(&text).unwrap_or(text)
            } else {
                text
            }
        }
        _ => return None,
    })
}

fn walk(
    value: &Value,
    key: Option<&str>,
    depth: usize,
    limits: TreeLimits,
    out: &mut Vec<String>,
    truncated: &mut bool,
) {
    if out.len() >= limits.max_lines {
        *truncated = true;
        return;
    }
    let indent = "  ".repeat(depth);
    let label = key.map_or_else(String::new, |key| format!("{key}: "));
    if let Some(text) = scalar(value, limits) {
        out.push(format!("{indent}{label}{text}"));
        return;
    }
    match value {
        Value::Array(items) if items.iter().all(|item| scalar(item, limits).is_some()) => {
            let shown: Vec<String> = items
                .iter()
                .take(limits.max_items)
                .filter_map(|item| scalar(item, limits))
                .collect();
            let more = items.len().saturating_sub(limits.max_items);
            let tail = if more > 0 {
                format!(", …+{more}")
            } else {
                String::new()
            };
            out.push(format!("{indent}{label}[{}{tail}]", shown.join(", ")));
        }
        Value::Array(items) => {
            out.push(format!("{indent}{label}({} items)", items.len()));
            for (index, item) in items.iter().take(limits.max_items).enumerate() {
                walk(
                    item,
                    Some(&format!("[{index}]")),
                    depth + 1,
                    limits,
                    out,
                    truncated,
                );
            }
            if items.len() > limits.max_items {
                out.push(format!(
                    "{indent}  …+{} items",
                    items.len() - limits.max_items
                ));
            }
        }
        Value::Object(map) => {
            if key.is_some() {
                out.push(format!("{indent}{}", label.trim_end()));
            }
            let depth = if key.is_some() { depth + 1 } else { depth };
            for (child_key, child) in map {
                walk(child, Some(child_key), depth, limits, out, truncated);
            }
        }
        _ => {}
    }
}

/// Selects a subtree by a dotted path: `entries.3.name`.
pub fn select<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .filter(|segment| !segment.is_empty())
        .try_fold(value, |current, segment| {
            let segment = segment.trim_start_matches('[').trim_end_matches(']');
            match current {
                Value::Object(map) => map.get(segment),
                Value::Array(items) => items.get(segment.parse::<usize>().ok()?),
                _ => None,
            }
        })
}

/// The decode header plus fields.
pub fn insight(insight: &PacketInsight, limits: TreeLimits, path: Option<&str>) -> String {
    let mut out = String::new();
    let identified = enum_name(&insight.identification);
    let _ = write!(
        out,
        "decode: {} ({identified}",
        insight.name.as_deref().unwrap_or("unidentified")
    );
    if let Some(by) = &insight.decoded_by {
        let _ = write!(out, ", by {by}");
    }
    out.push(')');
    if let Some(channel) = &insight.channel {
        let _ = write!(out, " channel={channel}");
    }
    if let Some(loader) = &insight.loader {
        let _ = write!(out, " loader={loader}");
    }
    if let Some(summary) = &insight.summary {
        let _ = write!(out, "\nsummary: {}", truncate(summary, 400));
    }
    for warning in &insight.warnings {
        let _ = write!(out, "\nwarning: {warning}");
    }
    if let Some(error) = &insight.error {
        let _ = write!(out, "\nerror: {error}");
    }
    if let Some(fields) = &insight.fields {
        match path {
            Some(path) => match select(fields, path) {
                Some(selected) => {
                    let _ = write!(out, "\nfields.{path}:\n{}", tree(selected, limits));
                }
                None => {
                    let _ = write!(out, "\nno field at path `{path}`");
                }
            },
            None => {
                let _ = write!(out, "\nfields:\n{}", tree(fields, limits));
            }
        }
    }
    if !insight.stream.is_empty() {
        let _ = write!(
            out,
            "\nstream: {} packet(s) in payload",
            insight.stream.len()
        );
        for packet in insight.stream.iter().take(limits.max_items) {
            let _ = write!(
                out,
                "\n  @{} +{} {} {}",
                packet.offset,
                packet.length,
                packet
                    .packet_id
                    .map_or_else(|| "--".to_owned(), |id| format!("0x{id:02x}")),
                packet.name.as_deref().unwrap_or("?"),
            );
            if let Some(summary) = &packet.summary {
                let _ = write!(out, " — {}", truncate(summary, 120));
            }
        }
    }
    out
}

/// Editable spans: `@offset +len kind name = value`.
pub fn layout(fields: &[FieldSpan], complete: bool, limits: TreeLimits) -> String {
    let mut out = String::from("layout (offset +len kind name = value):");
    for span in fields.iter().take(limits.max_lines) {
        let value = scalar(&span.value, limits).unwrap_or_else(|| span.value.to_string());
        let _ = write!(
            out,
            "\n  @{} +{} {} {} = {}",
            span.offset,
            span.length,
            enum_name(&span.kind),
            span.name,
            value
        );
    }
    if fields.len() > limits.max_lines {
        let _ = write!(out, "\n  …+{} spans", fields.len() - limits.max_lines);
    }
    if !complete {
        out.push_str("\n  (partial: the tail is raw bytes)");
    }
    out
}

/// Hex, either one run or an offset/ASCII dump.
pub fn hex(data: &[u8], base_offset: usize, dump: bool) -> String {
    if !dump {
        return ::hex::encode(data);
    }
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        if row > 0 {
            out.push('\n');
        }
        let _ = write!(out, "{:06x} ", base_offset + row * 16);
        for index in 0..16 {
            match chunk.get(index) {
                Some(byte) => {
                    let _ = write!(out, " {byte:02x}");
                }
                None => out.push_str("   "),
            }
        }
        out.push_str("  ");
        out.extend(chunk.iter().map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn times_are_utc() {
        assert_eq!(time(1_700_000_000_123_456), "22:13:20.123");
        assert_eq!(datetime(1_700_000_000_000_000), "2023-11-14 22:13:20");
    }

    #[test]
    fn trees_cap_lists_and_strings() {
        let value = json!({
            "a": 1,
            "list": (0..40).collect::<Vec<_>>(),
            "nested": { "text": "x".repeat(300) },
        });
        let text = tree(&value, TreeLimits::default());
        assert!(text.contains("a: 1"));
        assert!(text.contains("…+24]"));
        assert!(text.contains("…(+60)"));
        assert_eq!(select(&value, "nested.text").map(|_| ()), Some(()));
        assert_eq!(select(&value, "list.[3]"), Some(&json!(3)));
    }

    #[test]
    fn hex_dump_has_offsets_and_ascii() {
        let text = hex(b"hello", 32, true);
        assert!(text.starts_with("000020  68 65"));
        assert!(text.ends_with("hello"));
        assert_eq!(hex(b"\x01\xff", 0, false), "01ff");
    }
}
