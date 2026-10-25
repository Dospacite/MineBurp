export type View =
  | "traffic"
  | "intercept"
  | "repeater"
  | "replace"
  | "schemas"
  | "instances"
  | "compare"
  | "stats";
export type Direction = "client_to_server" | "server_to_client";
export type TrafficSource = "minecraft" | "side_channel";
export type Disposition = "forwarded" | "dropped" | "edited" | "delayed" | "replayed" | "observed" | "failed";
export type ProtocolState = "handshake" | "status" | "login" | "configuration" | "play" | "opaque" | "closed";

export interface ProjectInfo {
  path: string;
  name: string;
  encrypted: boolean;
  schema_version: number;
  /**
   * True for the scratch project MineBurp opens for itself at startup. Capture
   * is on disk from the first packet either way, but a temporary project is
   * deleted when the session ends, so it must never read as saved work.
   */
  temporary: boolean;
}

export interface Target {
  host: string;
  port: number;
}

/** Mirrors `ConnectionStatus` in `mineburp-core`. */
export type ConnectionStatus =
  | "listening"
  | "connecting"
  | "active"
  | "transferred"
  | "closing"
  | "closed"
  | "failed";

/** Mirrors `LoaderKind` in `mineburp-launcher`. */
export type LoaderKind = "vanilla" | "fabric" | "quilt" | "forge" | "neo_forge" | "unknown";

export interface ConnectionSnapshot {
  id: string;
  target: Target;
  listener_address: string;
  status: ConnectionStatus;
  state: ProtocolState;
  protocol_version: number | null;
  minecraft_version: string | null;
  loader: string | null;
  compression_threshold: number | null;
  encrypted_client: boolean;
  encrypted_server: boolean;
  packet_count: number;
  byte_count: number;
  last_error: string | null;
}

export interface PacketSummary {
  id: number;
  sequence: number;
  connection_id: string;
  timestamp_micros: number;
  source: TrafficSource;
  direction: Direction;
  state: ProtocolState;
  protocol_version: number | null;
  packet_id: number | null;
  name: string | null;
  channel: string | null;
  loader: string | null;
  size: number;
  disposition: Disposition;
  /** Present for passively captured rows; proxied packets carry no flow. */
  flow: FlowMetadata | null;
}

export interface WireMetadata {
  frame_length: number;
  logical_length: number;
  compressed: boolean;
  encrypted: boolean;
  truncated: boolean;
}

/** How the decoder arrived at the name it reports. */
export type Identification = "registry" | "structure" | "unidentified";

/** One packet recovered from inside a raw transport payload. */
export interface StreamPacket {
  offset: number;
  length: number;
  packet_id: number | null;
  name: string | null;
  summary: string | null;
}

/**
 * The result of decoding a packet. Produced on demand when a packet is opened,
 * never during capture.
 */
export interface PacketInsight {
  name: string | null;
  label: string | null;
  summary: string | null;
  fields: Record<string, unknown> | null;
  channel: string | null;
  loader: string | null;
  identification: Identification;
  error: string | null;
  stream: StreamPacket[];
}

/** How a decoded field is written back to the wire. */
export type FieldKind =
  | "var_int"
  | "var_long"
  | "string"
  | "bool"
  | "u8"
  | "i8"
  | "i16"
  | "u16"
  | "i32"
  | "i64"
  | "f32"
  | "f64"
  | "bytes"
  | "prefixed_bytes";

/** One decoded value together with the bytes it occupies in the frame. */
export interface FieldSpan {
  name: string;
  kind: FieldKind;
  offset: number;
  length: number;
  value: string | number | boolean | null;
}

export interface PacketLayout {
  name: string | null;
  fields: FieldSpan[];
  /** False when the walk stopped early and the tail is raw bytes. */
  complete: boolean;
}

/**
 * A packet prepared for display. `bytes_base64` is only the leading window of
 * the payload — the rest is paged in through `packetBytes` — so opening a
 * multi-megabyte packet never has to move it all at once.
 */
export interface PacketView {
  summary: PacketSummary;
  wire: WireMetadata;
  insight: PacketInsight;
  stored_decoded: unknown | null;
  stored_decode_error: string | null;
  total_bytes: number;
  bytes_offset: number;
  bytes_base64: string;
}

export interface ByteWindow {
  offset: number;
  total: number;
  base64: string;
}

export interface RepeaterTab {
  id: string;
  name: string;
  connection_id: string;
  direction: Direction;
  state: ProtocolState;
  logical_bytes: number[];
  decoded: unknown | null;
}

/** One rewrite applied to a logical frame by a replacement rule. */
export type PacketEdit =
  | { kind: "frame"; bytes: string }
  | { kind: "range"; offset: number; length: number; bytes: string }
  | { kind: "bytes"; find: string; replace: string; all: boolean }
  | { kind: "text"; find: string; replace: string; all: boolean; case_insensitive: boolean }
  | { kind: "regex"; pattern: string; replace: string; all: boolean }
  | { kind: "field"; name: string; value: string }
  | { kind: "field_replace"; name: string; find: string; replace: string; regex: boolean };

export type PacketEditKind = PacketEdit["kind"];

/**
 * A rule that rewrites matching packets automatically as they pass through.
 * An empty expression matches every packet.
 */
export interface ReplacementRule {
  id: string;
  name: string;
  enabled: boolean;
  expression: string;
  edits: PacketEdit[];
}

export interface InstanceDescriptor {
  id: string;
  launcher: "official" | "prism" | "multi_mc" | "modrinth" | "curse_forge";
  name: string;
  path: string;
  minecraft_version: string | null;
  loader: LoaderKind;
  icon_path: string | null;
  supports_agent_configuration: boolean;
  client_assist_configured: boolean;
}

export interface ClientAssistStatus {
  endpoint: string;
  connected_agents: number;
  ready_sessions: number;
  agent_path: string;
  config_path: string;
  jvm_argument: string;
  direct_oauth_available: boolean;
}

export interface AgentSetupOutcome {
  kind: "managed" | "manual";
  configured: boolean;
  jvm_argument: string;
  message: string;
}

export interface CaptureCapabilities {
  available: boolean;
  requires_elevation: boolean;
  process_attribution: boolean;
  backend: string;
  reason: string | null;
}

export interface FlowMetadata {
  transport: string;
  local_address: string;
  remote_address: string;
  process_id: number | null;
  stream_id: string | null;
}

export interface AppCapabilities {
  side_capture: CaptureCapabilities;
  project_encryption: boolean;
  protocol_min: number;
  protocol_max: number;
}

export interface DecryptModeStatus {
  enabled: boolean;
  route_adapter: string;
  active_sessions: number;
}

/**
 * The history filter an operator has configured.
 *
 * Every list is a disjunction that means "any" when empty, so a freshly cleared
 * filter is the same thing as no filter at all.
 */
export interface PacketFilter {
  search: string;
  searchRegex: boolean;
  searchCaseSensitive: boolean;
  searchNegate: boolean;
  directions: Direction[];
  states: ProtocolState[];
  sources: TrafficSource[];
  dispositions: Disposition[];
  /** Packet-name substrings to keep. */
  includeNames: string[];
  /** Packet-name substrings to drop, applied after `includeNames`. */
  excludeNames: string[];
  minSize: number | null;
  maxSize: number | null;
  /** Free-form expression in the same language replacement rules use. */
  expression: string;
  /**
   * A search through the stored payload bytes.
   *
   * Unlike the other filters this one cannot be answered from an index — each
   * candidate payload is decompressed and scanned — so it is a separate control
   * the operator opts into rather than part of the quick search.
   */
  content: string;
  contentMode: ContentSearchMode;
  contentScope: ContentSearchScope;
  contentCaseSensitive: boolean;
  contentNegate: boolean;
  /** Only bookmarked packets; false means bookmarks do not narrow the history. */
  bookmarked: boolean;
}

/** How a payload search reads the term it was given. */
export type ContentSearchMode = "text" | "hex" | "regex";

/**
 * How much of the payload the term has to account for.
 *
 * `contains` answers "is this in there"; the rest answer "is this what the
 * packet is", which is what makes it possible to select — or, negated, drop —
 * every packet whose payload is exactly one sequence.
 */
export type ContentSearchScope = "contains" | "equals" | "prefix" | "suffix";

export const EMPTY_FILTER: PacketFilter = {
  search: "",
  searchRegex: false,
  searchCaseSensitive: false,
  searchNegate: false,
  directions: [],
  states: [],
  sources: [],
  dispositions: [],
  includeNames: [],
  excludeNames: [],
  minSize: null,
  maxSize: null,
  expression: "",
  content: "",
  contentMode: "text",
  contentScope: "contains",
  contentCaseSensitive: false,
  contentNegate: false,
  bookmarked: false,
};

export interface PacketHistoryQuery extends Partial<PacketFilter> {
  connectionId?: string | null;
  offset?: number;
  limit?: number;
  /** Keyset cursor: rows older than this id. */
  beforeId?: number | null;
  /** Keyset cursor: rows newer than this id. */
  afterId?: number | null;
}

export interface FilterVocabulary {
  fields: string[];
  operators: string[];
  states: string[];
  directions: string[];
  sources: string[];
  dispositions: string[];
}

export type ProxyEvent =
  | { type: "connection"; payload: ConnectionSnapshot }
  | { type: "packet"; payload: PacketSummary }
  | { type: "error"; payload: { connection_id: string; message: string } }
  | { type: "intercept_queue"; payload: { pending: number } };

/** What Intercept holds. Handshake and login frames are never held. */
export interface InterceptSettings {
  enabled: boolean;
  client_to_server: boolean;
  server_to_client: boolean;
  /** Filter expression selecting packets to hold; empty holds every packet. */
  expression: string;
  forward_keep_alive: boolean;
  /** Forward a held frame unchanged after this many milliseconds; null holds until decided. */
  auto_forward_after_ms: number | null;
}

/** A frame held by Intercept, waiting for Forward or Drop. */
export interface InterceptedPacket {
  id: number;
  summary: PacketSummary;
  target: string;
  held_at_micros: number;
  /** When the frame is forwarded automatically; null when it waits for a decision. */
  deadline_micros: number | null;
  bytes_base64: string;
}

/** Shaping for one direction. Mirrors `LinkConditions` in `mineburp-proxy`. */
export interface LinkConditions {
  delay_ms: number;
  jitter_ms: number;
  /** Null is unlimited. */
  bandwidth_bytes_per_second: number | null;
}

/** Shaping applied to every proxied connection. Mirrors `NetworkConditions`. */
export interface NetworkConditions {
  client_to_server: LinkConditions;
  server_to_client: LinkConditions;
}

/** Counters from the passive capture backend. Mirrors `CaptureStats` in `mineburp-capture`. */
export interface CaptureStats {
  /** False when no capture is running, including one whose dumpcap died. */
  running: boolean;
  frames_seen: number;
  bytes_seen: number;
  frames_emitted: number;
  bytes_emitted: number;
  frames_dropped: number;
  /** Frames waiting for their flow to be attributed to a process. */
  frames_held: number;
  retransmissions: number;
  reordered: number;
  /** Sequence holes that never filled and were skipped. */
  gaps: number;
  errors: number;
  last_error: string | null;
}

/** A failure the backend reported outside any command, e.g. a capture write. */
export interface BackendError {
  source: string;
  message: string;
  /** How many identical reports this one stands for. */
  repeated: number;
}

/** A packet's bookmark, colour, and note. Mirrors `PacketAnnotation` in `mineburp-project`. */
export interface PacketAnnotation {
  packetId: number;
  bookmarked: boolean;
  /** `#rrggbb` or a lowercase colour name. */
  color: string | null;
  note: string | null;
  updatedAtMicros: number;
}

/** A named history filter stored in the project. */
export interface SavedFilter {
  id: string;
  name: string;
  /** The filter as the history query command takes it. */
  filter: Record<string, unknown>;
  createdAtMicros: number;
  updatedAtMicros: number;
}

export interface TrafficBucket {
  startMicros: number;
  clientToServerPackets: number;
  clientToServerBytes: number;
  serverToClientPackets: number;
  serverToClientBytes: number;
}

export interface NameStat {
  name: string | null;
  packets: number;
  bytes: number;
}

export interface ConnectionStat {
  connectionId: string;
  packets: number;
  bytes: number;
}

export interface SizeBucket {
  min: number;
  /** Inclusive upper bound; null for the open-ended last bucket. */
  max: number | null;
  packets: number;
}

/** Counts, a timeline, rankings, and a size histogram for one filter. */
export interface TrafficStats {
  totalPackets: number;
  totalBytes: number;
  clientToServerPackets: number;
  clientToServerBytes: number;
  serverToClientPackets: number;
  serverToClientBytes: number;
  firstTimestampMicros: number | null;
  lastTimestampMicros: number | null;
  bucketMicros: number;
  buckets: TrafficBucket[];
  topByCount: NameStat[];
  topByBytes: NameStat[];
  topConnections: ConnectionStat[];
  sizeHistogram: SizeBucket[];
}

export interface StatsOptions {
  bucketMicros?: number | null;
  maxBuckets?: number;
  top?: number;
}

export interface PcapExportSummary {
  packets: number;
  connections: number;
}

export interface ImportOptions {
  serverPorts?: number[];
  /** The most rows one import writes. */
  maxFrames?: number;
  /** Split TCP streams into Minecraft packets (default); off keeps raw chunks. */
  splitPackets?: boolean;
  /** Protocol assumed for connections whose handshake is not in the capture. */
  protocolVersion?: number | null;
}

export interface ImportSummary {
  recordsRead: number;
  /** Rows written: packets plus raw rows. */
  framesImported: number;
  bytesImported: number;
  duplicatesRemoved: number;
  segmentsReordered: number;
  gaps: number;
  packetsDecoded: number;
  rawRows: number;
  connections: number;
  encryptedConnections: number;
  midstreamConnections: number;
  unsynchronisedStreams: number;
  desyncs: number;
  resyncs: number;
  frameErrors: number;
  exportedPackets: number;
  truncated: boolean;
  error: string | null;
}

export interface DeleteSummary {
  packets: number;
  connections: number;
}

export interface CompactSummary {
  bytesBefore: number;
  bytesAfter: number;
}

/** How the history's time column reads a timestamp. */
export type TimeMode = "absolute" | "relative" | "delta";
