import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type {
  AgentSetupOutcome,
  AppCapabilities,
  ByteWindow,
  ClientAssistStatus,
  ConnectionSnapshot,
  DecryptModeStatus,
  Direction,
  FieldSpan,
  FilterVocabulary,
  HeldPacket,
  InstanceDescriptor,
  PacketEdit,
  PacketHistoryQuery,
  PacketInsight,
  PacketLayout,
  PacketSummary,
  PacketView,
  ProjectInfo,
  ProtocolState,
  ProxyEvent,
  RepeaterTab,
  ReplacementRule,
} from "../domain/types";

const inTauri = () => "__TAURI_INTERNALS__" in window;

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri()) {
    throw new Error("This operation is available in the MineBurp desktop runtime.");
  }
  return invoke<T>(command, args);
}

export const desktop = {
  isAvailable: inTauri,
  capabilities: () => call<AppCapabilities>("app_capabilities"),
  captureStart: () => call<void>("capture_start"),
  captureStop: () => call<void>("capture_stop"),
  captureStats: () =>
    call<{
      frames_seen: number;
      bytes_seen: number;
      frames_emitted: number;
      frames_dropped: number;
    }>("capture_stats"),
  decryptMode: () => call<DecryptModeStatus>("decrypt_mode_status"),
  setDecryptMode: (enabled: boolean) =>
    call<DecryptModeStatus>("decrypt_mode_set", { enabled }),
  projectCurrent: () => call<ProjectInfo | null>("project_current"),
  projectCreate: (path: string, name: string, passphrase?: string) =>
    call<ProjectInfo>("project_create", { path, name, passphrase: passphrase || null }),
  projectOpen: (path: string, passphrase?: string) =>
    call<ProjectInfo>("project_open", { path, passphrase: passphrase || null, readOnly: false }),
  /** Proxy sessions and passively observed flows, as recorded in the project. */
  connections: () => call<ConnectionSnapshot[]>("connections_query"),
  packets: (query: PacketHistoryQuery = {}) =>
    call<PacketSummary[]>("packets_query", {
      filter: {
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
      },
    }),
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
  setIntercept: (enabled: boolean) =>
    call<void>("intercept_rules_set", {
      rules: enabled
        ? [
            {
              id: crypto.randomUUID(),
              name: "Interactive intercept",
              enabled: true,
              expression: "source == minecraft",
              action: { type: "hold" },
            },
          ]
        : [],
    }),
  interceptRules: () =>
    call<Array<{ id: string; enabled: boolean; expression: string; action: { type: string } }>>(
      "intercept_rules_get",
    ),
  resolveHeld: (held: HeldPacket, resolution: "forward" | "drop" | Uint8Array) =>
    call<void>("held_resolve", {
      id: held.id,
      resolution:
        resolution instanceof Uint8Array
          ? { type: "replace_base64", payload: bytesToBase64(resolution) }
          : { type: resolution },
    }),
  /** The automatic replacement rules, in the order they are applied. */
  replacementRules: () => call<ReplacementRule[]>("replacement_rules_get"),
  saveReplacementRules: (rules: ReplacementRule[]) =>
    call<void>("replacement_rules_set", { rules }),
  /** Runs a rule's edits against one frame without sending anything. */
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
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number }>(
      "auth_complete",
      { callbackUrl },
    ),
  authSession: () =>
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number } | null>(
      "auth_session",
    ),
  authRefresh: () =>
    call<{ profile: { id: string; name: string }; expires_at_epoch_seconds: number }>(
      "auth_refresh",
    ),
  authSignOut: () => call<void>("auth_sign_out"),
  onProxyEvent: async (listener: (event: ProxyEvent) => void): Promise<UnlistenFn> => {
    if (!inTauri()) return () => undefined;
    return listen<ProxyEvent>("proxy-event", ({ payload }) => listener(payload));
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
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
  return output;
}

export function parseHex(input: string): Uint8Array {
  const compact = input.replace(/(?:0x|[^0-9a-f])/gi, "");
  if (compact.length % 2 !== 0) throw new Error("Hex input must contain complete byte pairs.");
  const output = new Uint8Array(compact.length / 2);
  for (let index = 0; index < compact.length; index += 2) {
    output[index / 2] = Number.parseInt(compact.slice(index, index + 2), 16);
  }
  return output;
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
    const hex = row.map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(columns * 3 - 1);
    const ascii = row.map((byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".")).join("");
    rows.push(`${address}  ${hex}  ${ascii}`);
  }
  return rows.join("\n");
}

/** The bytes and nothing else: no addresses, no ASCII column, no line breaks. */
export function formatRawHex(bytes: number[] | Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

export function formatHexInput(bytes: number[] | Uint8Array, columns = 16): string {
  const pairs = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  const rows: string[] = [];
  for (let offset = 0; offset < pairs.length; offset += columns) {
    rows.push(pairs.slice(offset, offset + columns).join(" "));
  }
  return rows.join("\n");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
