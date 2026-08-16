use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub type PacketId = i64;
pub type ConnectionId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    #[must_use]
    pub const fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolState {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
    Opaque,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficSource {
    Minecraft,
    SideChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Forwarded,
    Dropped,
    Edited,
    Delayed,
    Replayed,
    Observed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowMetadata {
    pub transport: String,
    pub local_address: String,
    pub remote_address: String,
    pub process_id: Option<u32>,
    pub stream_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WireMetadata {
    pub frame_length: usize,
    pub logical_length: usize,
    pub compressed: bool,
    pub encrypted: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketSummary {
    pub id: PacketId,
    pub sequence: u64,
    pub connection_id: ConnectionId,
    pub timestamp_micros: i64,
    pub source: TrafficSource,
    pub direction: Direction,
    pub state: ProtocolState,
    pub protocol_version: Option<i32>,
    pub packet_id: Option<i32>,
    pub name: Option<String>,
    pub channel: Option<String>,
    pub loader: Option<String>,
    pub size: usize,
    pub disposition: Disposition,
    pub flow: Option<FlowMetadata>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketDetail {
    pub summary: PacketSummary,
    #[serde(with = "bytes_serde")]
    pub logical_bytes: Bytes,
    pub decoded: Option<Value>,
    pub decode_error: Option<String>,
    pub wire: WireMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Listening,
    Connecting,
    Active,
    Transferred,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: ConnectionId,
    pub target: Target,
    pub listener_address: String,
    pub status: ConnectionStatus,
    pub state: ProtocolState,
    pub protocol_version: Option<i32>,
    pub minecraft_version: Option<String>,
    pub loader: Option<String>,
    pub compression_threshold: Option<i32>,
    pub encrypted_client: bool,
    pub encrypted_server: bool,
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterceptRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub expression: String,
    pub action: InterceptDecision,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum InterceptDecision {
    Forward,
    Drop,
    Hold,
    DelayMillis(u64),
}

/// A rule that rewrites packets automatically as they pass through.
///
/// Selection reuses the same filter expression language as the history and
/// intercept rules, so anything an operator can search for is also something
/// they can rewrite. An empty expression matches every packet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplacementRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub expression: String,
    /// Applied in order; each edit sees the output of the one before it.
    pub edits: Vec<PacketEdit>,
}

/// One rewrite applied to a logical frame.
///
/// The frame is the packet-id `VarInt` followed by the body, which is what both
/// the inspector and the Repeater work on, so offsets and field names mean the
/// same thing everywhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PacketEdit {
    /// Replaces the whole frame with the given hex.
    Frame { bytes: String },
    /// Replaces a byte range. A length of zero inserts.
    Range {
        offset: usize,
        length: usize,
        bytes: String,
    },
    /// Finds and replaces a byte sequence, given as hex.
    Bytes {
        find: String,
        replace: String,
        #[serde(default)]
        all: bool,
    },
    /// Finds and replaces literal text anywhere in the frame's bytes.
    Text {
        find: String,
        replace: String,
        #[serde(default)]
        all: bool,
        #[serde(default)]
        case_insensitive: bool,
    },
    /// Replaces regular-expression matches over the frame's bytes.
    Regex {
        pattern: String,
        replace: String,
        #[serde(default)]
        all: bool,
    },
    /// Sets a decoded field by name, re-encoding it — including any length
    /// prefix — so the frame stays well formed.
    Field { name: String, value: String },
    /// Rewrites inside a decoded field's value, keeping the frame well formed.
    FieldReplace {
        name: String,
        find: String,
        replace: String,
        #[serde(default)]
        regex: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepeaterTab {
    pub id: Uuid,
    pub name: String,
    pub connection_id: ConnectionId,
    pub direction: Direction,
    pub state: ProtocolState,
    #[serde(with = "bytes_serde")]
    pub logical_bytes: Bytes,
    pub decoded: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepeaterAttempt {
    pub id: Uuid,
    pub tab_id: Uuid,
    pub sent_at_micros: i64,
    pub disposition: Disposition,
    pub error: Option<String>,
}

mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(Bytes::from)
    }
}
