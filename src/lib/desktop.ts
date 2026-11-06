import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AgentSetupOutcome,
  AppCapabilities,
  AttackMode,
  BackendError,
  ByteWindow,
  CaptureStats,
  ClientAssistStatus,
  CompactSummary,
  ConnectionSnapshot,
  DecryptModeStatus,
  DeleteSummary,
  Direction,
  FieldSpan,
  FilterVocabulary,
  ImportOptions,
  ImportSummary,
  InstanceDescriptor,
  InterceptedPacket,
  InterceptSettings,
  NetworkConditions,
  PacketAnnotation,
  PacketEdit,
  PacketHistoryQuery,
  PacketInsight,
  PacketLayout,
  PacketSummary,
  PacketView,
  PcapExportSummary,
  ProjectInfo,
  ProtocolState,
  ProxyEvent,
  RepeaterTab,
  ReplacementRule,
  SavedFilter,
  SequenceAnalysis,
  StatsOptions,
  TrafficStats,
} from "../domain/types";
import { t } from "../i18n";
import { flushProjectEditors } from "./projectWrites";

const inTauri = () => "__TAURI_INTERNALS__" in window;

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri()) {
    throw new Error("This operation is available in the MineBurp desktop runtime.");
  }
  return invoke<T>(command, args);
}

/** The most ids `packet_annotations_get` accepts in one call. */
export const ANNOTATION_BATCH = 2_000;

/** The history filter as the `packets_query` and `packets_export` commands take it. */
export function filterArgs(query: PacketHistoryQuery) {
  return {
    connectionId: query.connectionId || null,
    offset: query.offset ?? 0,
    limit: query.limit ?? 251,
    search: query.search || null,
    searchRegex: query.searchRegex ?? false,
    searchCaseSensitive: query.searchCaseSensitive ?? false,
    searchNegate: query.searchNegate ?? false,
    directions: query.directions ?? [],
    states: query.states ?? [],
    sources: query.sources ?? [],
    dispositions: query.dispositions ?? [],
    includeNames: query.includeNames ?? [],
    excludeNames: query.excludeNames ?? [],
    minSize: query.minSize ?? null,
    maxSize: query.maxSize ?? null,
    expression: query.expression || null,
    content: query.content || null,
    contentMode: query.contentMode ?? "text",
    contentScope: query.contentScope ?? "contains",
    contentCaseSensitive: query.contentCaseSensitive ?? false,
    contentNegate: query.contentNegate ?? false,
    beforeId: query.beforeId ?? null,
    afterId: query.afterId ?? null,
    oldestFirst: query.oldestFirst ?? false,
    // `false` would mean "only rows without a bookmark"; the UI only ever narrows to bookmarked ones.
    bookmarked: query.bookmarked ? true : null,
  };
}

export const desktop = {
  isAvailable: inTauri,
  intruderPlan: (mode: AttackMode, lengths: number[]) =>
    call<Array<Array<number | null>>>("intruder_plan", { mode, lengths }),
  sequencerAnalyze: (samples: string[]) => call<SequenceAnalysis>("sequencer_analyze", { samples }),
  workbenchDocumentGet: (expectedPath: string, key: string) =>
    call<unknown | null>("workbench_document_get", { expectedPath, key }),
  workbenchDocumentSave: (expectedPath: string, key: string, value: unknown) =>
    call<void>("workbench_document_save", { expectedPath, key, value }),
  payloadGenerate: (generator: import("../domain/types").PayloadGenerator) =>
    call<string[]>("payload_generate", { generator }),
  decoderTransform: (operation: string, input: string) =>
    call<{ output: string; consumed: number | null; trailing_hex: string }>("decoder_transform", {
      operation,
      input,
    }),
  channelStats: (query: PacketHistoryQuery = {}) =>
    call<import("../domain/types").ChannelStat[]>("channel_stats", { filter: filterArgs(query) }),
  packetFieldValues: (expectedPath: string, ids: number[], paths: string[]) =>
    call<Record<string, Array<unknown | null>>>("packet_field_values", { expectedPath, ids, paths }),
  capabilities: () => call<AppCapabilities>("app_capabilities"),
  captureStart: () => call<void>("capture_start"),
  captureStop: () => call<void>("capture_stop"),
  captureStats: () => call<CaptureStats>("capture_stats"),
  decryptMode: () => call<DecryptModeStatus>("decrypt_mode_status"),
  setDecryptMode: (enabled: boolean) => call<DecryptModeStatus>("decrypt_mode_set", { enabled }),
  projectCurrent: () => call<ProjectInfo | null>("project_current"),
  projectCreate: async (path: string, name: string, passphrase?: string) => {
    await flushProjectEditors();
    return call<ProjectInfo>("project_create", { path, name, passphrase: passphrase || null });
  },
  projectOpen: async (path: string, passphrase?: string) => {
    try {
      await flushProjectEditors();
    } catch (error) {
      if (
        !window.confirm(
          `Could not save project edits: ${String(error)}. Open another project and discard them?`,
        )
      )
        throw error;
    }
    return call<ProjectInfo>("project_open", { path, passphrase: passphrase || null, readOnly: false });
  },
  /** Copies the open project (usually the temporary session) to a new file and switches to it. */
  projectSaveAs: async (path: string, name: string, passphrase?: string) => {
    await flushProjectEditors();
    return call<ProjectInfo>("project_save_as", { path, name, passphrase: passphrase || null });
  },
  interceptSettings: () => call<InterceptSettings>("intercept_settings_get"),
  setInterceptSettings: (settings: InterceptSettings) =>
    call<InterceptSettings>("intercept_settings_set", { settings }),
  interceptPending: () => call<InterceptedPacket[]>("intercept_pending"),
  /** Forwards (optionally with replacement bytes) or drops one held frame. */
  interceptResolve: (id: number, action: "forward" | "drop", replacement?: Uint8Array) =>
    call<void>("intercept_resolve", {
      id,
      action,
      logicalBase64: replacement ? bytesToBase64(replacement) : null,
    }),
  interceptForwardAll: () => call<number>("intercept_forward_all"),
  networkConditions: () => call<NetworkConditions>("network_conditions_get"),
  /** Applies to every proxied connection, open ones included; returns what the backend kept. */
  setNetworkConditions: (conditions: NetworkConditions) =>
    call<NetworkConditions>("network_conditions_set", { conditions }),
  /** Proxy sessions and passively observed flows, as recorded in the project. */
  compareConnections: (a: string, b: string, query: PacketHistoryQuery = {}) =>
    call<import("../domain/types").ConnectionComparison>("connections_compare", {
      a,
      b,
      filter: filterArgs(query),
    }),
  connections: (recent = false) => call<ConnectionSnapshot[]>("connections_query", { recent }),
  packets: (query: PacketHistoryQuery = {}) =>
    call<PacketSummary[]>("packets_query", { filter: filterArgs(query) }),
  /** Writes every packet matching the filter to a JSON file; resolves to the count written. */
  packetsExport: (path: string, query: PacketHistoryQuery) =>
    call<number>("packets_export", { path, filter: filterArgs(query) }),
  /** Writes every packet matching the filter to a pcapng file, one synthetic TCP stream per connection. */
  packetsExportPcapng: (path: string, query: PacketHistoryQuery) =>
    call<PcapExportSummary>("packets_export_pcapng", { path, filter: filterArgs(query) }),
  /** Reads a pcap or pcapng file into the open project. */
  captureImport: (path: string, options?: ImportOptions) =>
    call<ImportSummary>("capture_import", { path, options: options ?? null }),
  /** Deletes every packet matching the filter, regardless of its limit. */
  packetsDelete: (query: PacketHistoryQuery, pruneConnections = true) =>
    call<DeleteSummary>("packets_delete", { filter: filterArgs(query), pruneConnections }),
  /** Returns the space freed by deleted history to the filesystem. */
  projectCompact: () => call<CompactSummary>("project_compact"),
  /** Stops every history query that is still running. */
  packetsQueryCancel: () => call<void>("packets_query_cancel"),
  trafficStats: (query: PacketHistoryQuery, options?: StatsOptions) =>
    call<TrafficStats>("traffic_stats", { filter: filterArgs(query), options: options ?? null }),
  /** The annotations of the given packets; at most `ANNOTATION_BATCH` ids per call. */
  packetAnnotationsGet: (ids: number[]) => call<PacketAnnotation[]>("packet_annotations_get", { ids }),
  /** Every annotation in the project, newest packet first. */
  packetAnnotationsList: (limit?: number) =>
    call<PacketAnnotation[]>("packet_annotations_list", { limit: limit ?? null }),
  /** Resolves to null when the update cleared the bookmark, colour, and note. */
  packetAnnotationSet: (packetId: number, bookmarked: boolean, color: string | null, note: string | null) =>
    call<PacketAnnotation | null>("packet_annotation_set", { packetId, bookmarked, color, note }),
  savedFilters: () => call<SavedFilter[]>("saved_filters_list"),
  /** Creates (no id) or updates a saved filter. */
  savedFilterSave: (filter: { id?: string | null; name: string; filter: Record<string, unknown> }) =>
    call<SavedFilter>("saved_filter_save", { filter: { ...filter, id: filter.id ?? null } }),
  savedFilterDelete: (id: string) => call<boolean>("saved_filter_delete", { id }),
  /** The field and value names the filter expression accepts. */
  filterVocabulary: () => call<FilterVocabulary>("filter_vocabulary"),
  /** Parses an expression without running it, for live feedback while typing. */
  filterValidate: (expression: string) => call<void>("filter_validate", { expression }),
  /** Loads one packet and decodes it — the decode happens only for this call. */
  packet: (id: number) => call<PacketView | null>("packet_detail", { id }),
  /** Pages through a stored packet's payload for the hex view. */
  packetBytes: (id: number, offset: number, limit: number) =>
    call<ByteWindow | null>("packet_bytes", { id, offset, limit }),
  /** Decodes arbitrary bytes — used by the Repeater for composed frames. */
  inspectBytes: (
    bytes: Uint8Array,
    protocolState: ProtocolState,
    direction: Direction,
    protocolVersion: number | null = null,
  ) =>
    call<PacketInsight>("inspect_bytes", {
      logicalBase64: bytesToBase64(bytes),
      protocolState,
      direction,
      protocolVersion,
    }),
  /** Walks a frame into editable field spans for the Repeater's decoded view. */
  packetLayout: (
    bytes: Uint8Array,
    protocolState: ProtocolState,
    direction: Direction,
    protocolVersion: number | null = null,
  ) =>
    call<PacketLayout>("packet_layout", {
      logicalBase64: bytesToBase64(bytes),
      protocolState,
      direction,
      protocolVersion,
    }),
  /** Walks a stored packet's whole payload, not just the window `packet` sends. */
  packetLayoutStored: (id: number) => call<PacketLayout | null>("packet_layout_stored", { id }),
  /**
   * Re-encodes one decoded field and splices it back into the frame.
   *
   * The splice is done in the backend so that a field whose length changes —
   * a string, a VarInt — rewrites its own prefix by the same code that read it.
   */
  fieldEdit: (bytes: Uint8Array, field: FieldSpan, value: string | number | boolean) =>
    call<string>("field_edit", {
      logicalBase64: bytesToBase64(bytes),
      offset: field.offset,
      length: field.length,
      kind: field.kind,
      value,
    }).then(base64ToBytes),
  proxySessions: () => call<ConnectionSnapshot[]>("proxy_sessions"),
  /** The automatic replacement rules, in the order they are applied. */
  replacementRules: () => call<ReplacementRule[]>("replacement_rules_get"),
  saveReplacementRules: (rules: ReplacementRule[], expectedPath?: string | null) =>
    call<void>("replacement_rules_set", { rules, expectedPath }),
  /** Runs a rule's edits against one frame without sending anything. */
  replacementRulePreview: (
    rule: ReplacementRule,
    bytes: Uint8Array,
    protocolState: ProtocolState,
    direction: Direction,
    protocolVersion: number | null,
    summary: PacketSummary | null,
  ) =>
    call<{ matched: boolean; action: "rewrite" | "drop"; protected: boolean; logical_base64: string }>(
      "replacement_rule_preview",
      { rule, logicalBase64: bytesToBase64(bytes), protocolState, direction, protocolVersion, summary },
    ),
  replacementPreview: (
    bytes: Uint8Array,
    protocolState: ProtocolState,
    direction: Direction,
    edits: PacketEdit[],
    protocolVersion: number | null = null,
  ) =>
    call<string>("replacement_preview", {
      logicalBase64: bytesToBase64(bytes),
      protocolState,
      direction,
      protocolVersion,
      edits,
    }).then(base64ToBytes),
  repeaterSend: (connectionId: string, direction: Direction, bytes: Uint8Array) =>
    call<void>("repeater_send", {
      connectionId,
      direction,
      logicalBase64: bytesToBase64(bytes),
    }),
  repeaterTabs: () => call<RepeaterTab[]>("repeater_tabs"),
  repeaterTabSave: (tab: RepeaterTab) => call<void>("repeater_tab_save", { tab }),
  repeaterTabDelete: (id: string) => call<void>("repeater_tab_delete", { id }),
  schemaValidate: (schemaJson: string) => call<unknown>("schema_validate", { schemaJson }),
  instances: () => call<InstanceDescriptor[]>("launcher_instances"),
  clientAssistStatus: () => call<ClientAssistStatus>("client_assist_status"),
  configureClientAssist: (instance: InstanceDescriptor, enabled: boolean) =>
    call<AgentSetupOutcome>("launcher_client_assist_configure", { instance, enabled }),
  launch: (instance: InstanceDescriptor) =>
    call<{ process_id: number }>("launcher_launch", {
      request: { instance, profile_name: null },
    }),
  authBegin: () => call<{ url: string }>("auth_begin"),
  authComplete: (callbackUrl: string) =>
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number }>("auth_complete", {
      callbackUrl,
    }),
  authSession: () =>
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number } | null>("auth_session"),
  authRefresh: () =>
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number }>("auth_refresh"),
  authSignOut: () => call<void>("auth_sign_out"),
  onProxyEvent: async (listener: (event: ProxyEvent) => void): Promise<UnlistenFn> => {
    if (!inTauri()) return () => undefined;
    return listen<ProxyEvent>("proxy-event", ({ payload }) => listener(payload));
  },
  /** Failures the backend reports outside any command, already coalesced. */
  onBackendError: async (listener: (error: BackendError) => void): Promise<UnlistenFn> => {
    if (!inTauri()) return () => undefined;
    return listen<BackendError>("backend-error", ({ payload }) => listener(payload));
  },
  /**
   * Something an MCP client changed behind the UI's back: `project`, `rules`,
   * `intercept`, `network`, `packets`, `schemas`, `repeater`, `filters`,
   * `annotations`, `capture`, or `decrypt`.
   */
  onMcpChange: async (listener: (topic: string) => void): Promise<UnlistenFn> => {
    if (!inTauri()) return () => undefined;
    return listen<string>("mcp-change", ({ payload }) => listener(payload));
  },
  /**
   * Coalesced signal that new rows landed in the project.
   *
   * The proxy and passive capture write through different paths and each raise
   * their own event; both mean the same thing to the history — pull the tail.
   */
  onPacketsAppended: async (listener: (count: number) => void): Promise<UnlistenFn> => {
    if (!inTauri()) return () => undefined;
    const unlisten = await Promise.all([
      listen<number>("proxy-packets-appended", ({ payload }) => listener(payload)),
      listen<number>("capture-packets-appended", ({ payload }) => listener(payload)),
    ]);
    return () => {
      for (const stop of unlisten) stop();
    };
  },
};

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  // Chunk-free but still O(n): charCodeAt loop is unavoidable in JS without TextEncoder tricks,
  // but avoid per-iteration method lookup by caching length.
  const output = new Uint8Array(binary.length);
  for (let i = 0, len = binary.length; i < len; i++) output[i] = binary.charCodeAt(i);
  return output;
}

/** A hex string that could not be read as bytes. */
export class HexParseError extends Error {
  override name = "HexParseError";
}

/**
 * Reads hex bytes the way an operator types or pastes them.
 *
 * Whitespace, commas, semicolons, and colons separate bytes; a token may carry
 * a `0x` prefix and C-style `\x` escapes are accepted. Anything else is an
 * error rather than noise: silently dropping a stray character turned `41 gg 42`
 * into two bytes and sent a frame nobody had written.
 */
export function parseHex(input: string): Uint8Array {
  let compact = "";
  for (const raw of input.split(/[\s,;:]+/)) {
    if (!raw) continue;
    const token = raw.replace(/^0x/i, "").replace(/\\x/gi, "");
    const bad = /[^0-9a-f]/i.exec(token);
    if (bad) throw new HexParseError(t("hex.parse.invalid", { character: bad[0], token: raw }));
    compact += token;
  }
  if (compact.length % 2 !== 0) throw new HexParseError(t("hex.parse.odd"));
  const output = new Uint8Array(compact.length / 2);
  for (let index = 0; index < compact.length; index += 2) {
    output[index / 2] = Number.parseInt(compact.slice(index, index + 2), 16);
  }
  return output;
}

/** `parseHex` for live editors: the bytes, or the reason there are none. */
export function tryParseHex(
  input: string,
): { bytes: Uint8Array; error: null } | { bytes: null; error: string } {
  try {
    return { bytes: parseHex(input), error: null };
  } catch (reason) {
    return { bytes: null, error: reason instanceof Error ? reason.message : String(reason) };
  }
}

/**
 * Renders a hex dump. `startOffset` keeps addresses truthful when only a window
 * of a large payload was loaded.
 */
export function formatHex(bytes: number[] | Uint8Array, columns = 16, startOffset = 0): string {
  const rows: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += columns) {
    const row = Array.from(bytes.slice(offset, offset + columns));
    const address = (startOffset + offset).toString(16).padStart(6, "0");
    const hex = row
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(columns * 3 - 1);
    const ascii = row.map((byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".")).join("");
    rows.push(`${address}  ${hex}  ${ascii}`);
  }
  return rows.join("\n");
}

/** The bytes and nothing else: no addresses, no ASCII column, no line breaks. */
export function formatRawHex(bytes: number[] | Uint8Array): string {
  const len = bytes.length;
  const parts = new Array<string>(len);
  for (let i = 0; i < len; i++) parts[i] = (bytes[i] as number).toString(16).padStart(2, "0");
  return parts.join(" ");
}

export function formatHexInput(bytes: number[] | Uint8Array, columns = 16): string {
  const len = bytes.length;
  const pairs = new Array<string>(len);
  for (let i = 0; i < len; i++) pairs[i] = (bytes[i] as number).toString(16).padStart(2, "0");
  const rows: string[] = [];
  for (let offset = 0; offset < len; offset += columns) {
    rows.push(pairs.slice(offset, offset + columns).join(" "));
  }
  return rows.join("\n");
}

export function bytesToBase64(bytes: Uint8Array): string {
  // Chunked to avoid "Maximum call stack size exceeded" on large packets (>100 KiB)
  // and to avoid O(n^2) string concatenation. 8 KiB chunks keep apply() safe.
  const chunk = 8192;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, Math.min(i + chunk, bytes.length));
    // Spread via apply avoids per-byte string concatenation
    binary += String.fromCharCode.apply(null, slice as unknown as number[]);
  }
  return btoa(binary);
}

/** The most `packet_bytes` returns in one call; the backend clamps larger requests. */
export const MAX_WINDOW_BYTES = 256 * 1024;

/**
 * Reads a stored payload in backend-sized windows.
 *
 * `packet_bytes` returns at most 256 KiB per call, so asking for a whole large
 * packet in one request quietly returned its first window. `complete` says
 * whether the result is the entire payload or was cut at `limit`.
 */
export async function readPayload(
  id: number,
  limit = Number.POSITIVE_INFINITY,
): Promise<{ bytes: Uint8Array; total: number; complete: boolean }> {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  let total = Number.POSITIVE_INFINITY;
  while (offset < Math.min(total, limit)) {
    const want = Math.min(MAX_WINDOW_BYTES, Math.min(total, limit) - offset);
    const window = await desktop.packetBytes(id, offset, want);
    if (!window) throw new Error(t("payload.gone"));
    total = window.total;
    const chunk = base64ToBytes(window.base64).subarray(0, Math.max(0, Math.min(total, limit) - offset));
    if (chunk.length === 0) break;
    chunks.push(chunk);
    offset += chunk.length;
  }
  const bytes = new Uint8Array(offset);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  if (!Number.isFinite(total)) total = offset;
  return { bytes, total, complete: offset >= total };
}

/**
 * Ties an asynchronous `listen` to a synchronous cleanup.
 *
 * `listen` resolves after the effect that called it may already have been
 * cleaned up — React's StrictMode does exactly that on mount — and pushing the
 * unlisten function into a list after the cleanup ran left the first listener
 * registered forever, so every event was handled twice.
 */
export function subscription(pending: Promise<UnlistenFn>): () => void {
  let disposed = false;
  let stop: UnlistenFn | null = null;
  void pending
    .then((unlisten) => {
      if (disposed) unlisten();
      else stop = unlisten;
    })
    .catch(() => undefined);
  return () => {
    disposed = true;
    stop?.();
    stop = null;
  };
}

/** Standard base64, for pasting into tools that take it. */
export function formatBase64(bytes: Uint8Array): string {
  return bytesToBase64(bytes);
}

/** A C byte array literal, twelve bytes per line. */
export function formatCArray(bytes: Uint8Array, name = "packet"): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 12) {
    const row = Array.from(
      bytes.subarray(offset, offset + 12),
      (byte) => `0x${byte.toString(16).padStart(2, "0")}`,
    );
    lines.push(`  ${row.join(", ")}${offset + 12 < bytes.length ? "," : ""}`);
  }
  return `const unsigned char ${name}[${bytes.length}] = {\n${lines.join("\n")}\n};`;
}

/** Copies text to the clipboard, falling back to a hidden textarea where the API is missing. */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error(t("copy.failed"));
}

/** Saves bytes through the webview's download path. */
export function downloadBytes(bytes: Uint8Array, filename: string): void {
  const blob = new Blob([bytes as unknown as BlobPart], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
