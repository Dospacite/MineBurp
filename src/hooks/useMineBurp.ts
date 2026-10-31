import { useCallback, useEffect, useRef, useState } from "react";

import type {
  AppCapabilities,
  BackendError,
  ConnectionSnapshot,
  DecryptModeStatus,
  InterceptSettings,
  PacketFilter,
  PacketView,
  ProjectInfo,
} from "../domain/types";
import { EMPTY_FILTER } from "../domain/types";
import { desktop, subscription } from "../lib/desktop";

/** Cadence for session/project polling — unrelated to traffic volume. */
const STATUS_POLL_MS = 2_000;
const STATUS_POLL_MS_HIDDEN = 10_000;

const INTERCEPT_PREFERENCES_KEY = "mineburp.intercept";
/** Messages kept in the log; older ones fall off the end. */
const LOG_LIMIT = 200;

export type CaptureStatus = "starting" | "running" | "unavailable" | "failed";

/** One message in the activity log. Repeats of the latest message are counted, not duplicated. */
export interface LogEntry {
  id: number;
  at: number;
  tone: "error" | "info";
  text: string;
  count: number;
}

/**
 * The Intercept filter the operator last used. Only the selection is kept:
 * Intercept itself always starts off, so launching MineBurp never silently
 * holds a game that nobody is watching.
 */
function storedInterceptPreferences(): Partial<InterceptSettings> {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(INTERCEPT_PREFERENCES_KEY) ?? "{}");
    if (!parsed || typeof parsed !== "object") return {};
    const { client_to_server, server_to_client, expression, forward_keep_alive } = parsed as Record<
      string,
      unknown
    >;
    return {
      ...(typeof client_to_server === "boolean" && { client_to_server }),
      ...(typeof server_to_client === "boolean" && { server_to_client }),
      ...(typeof expression === "string" && { expression }),
      ...(typeof forward_keep_alive === "boolean" && { forward_keep_alive }),
    };
  } catch {
    return {};
  }
}

function storeInterceptPreferences({ enabled: _enabled, ...preferences }: InterceptSettings): void {
  try {
    localStorage.setItem(INTERCEPT_PREFERENCES_KEY, JSON.stringify(preferences));
  } catch {
    // A convenience only.
  }
}

export function useMineBurp() {
  const [project, setProject] = useState<ProjectInfo | null>(null);
  const [capabilities, setCapabilities] = useState<AppCapabilities | null>(null);
  /**
   * Every connection the project knows about — live proxy sessions and the
   * flows passive capture observed. The proxy's own list covers only the
   * former, which left passively captured traffic impossible to filter to.
   */
  const [connections, setConnections] = useState<ConnectionSnapshot[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketView | null>(null);
  /**
   * The id of the row that was clicked.
   *
   * Kept separately from the fetched packet so the table can highlight exactly
   * one row the instant it is clicked, rather than waiting for a round trip and
   * inheriting whichever response happens to resolve last.
   */
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  /**
   * The history filter.
   *
   * Held here rather than in the history itself because that component unmounts
   * whenever another view is on screen, which threw away a filter the operator
   * had just built the moment they looked at the repeater.
   */
  const [packetFilter, setPacketFilter] = useState<PacketFilter>({ ...EMPTY_FILTER });
  /** Which connection the traffic view is narrowed to, for the same reason. */
  const [connectionId, setConnectionId] = useState<string | null>(null);
  const [decryptMode, setDecryptModeState] = useState<DecryptModeStatus | null>(null);
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus>("starting");
  const [appendSignal, setAppendSignal] = useState(0);
  const [interceptSettings, setInterceptSettingsState] = useState<InterceptSettings | null>(null);
  /** How many frames Intercept is holding; the view refetches the queue when it changes. */
  const [interceptPending, setInterceptPending] = useState(0);
  /** Bumped on every queue event, so a resolve that leaves the count unchanged still refetches. */
  const [interceptSignal, setInterceptSignal] = useState(0);
  const [error, setErrorState] = useState<string | null>(null);
  /** A confirmation, shown in the same corner as errors but never over one. */
  const [notice, setNoticeState] = useState<string | null>(null);
  /**
   * Every message the toast has shown. The toast holds one at a time, so a
   * burst of failures used to leave only the last one readable.
   */
  const [log, setLog] = useState<LogEntry[]>([]);
  const [unreadErrors, setUnreadErrors] = useState(0);
  const packetRequest = useRef(0);
  const logId = useRef(0);
  /** The settings the backend last confirmed, read by queued patches. */
  const interceptRef = useRef<InterceptSettings | null>(null);
  /** Intercept updates run one at a time, each on top of the one before. */
  const interceptQueue = useRef<Promise<unknown>>(Promise.resolve());

  const record = useCallback((tone: LogEntry["tone"], text: string) => {
    setLog((entries) => {
      const latest = entries[0];
      if (latest && latest.tone === tone && latest.text === text) {
        return [{ ...latest, at: Date.now(), count: latest.count + 1 }, ...entries.slice(1)];
      }
      return [{ id: ++logId.current, at: Date.now(), tone, text, count: 1 }, ...entries].slice(0, LOG_LIMIT);
    });
    if (tone === "error") setUnreadErrors((count) => count + 1);
  }, []);

  const setError = useCallback(
    (text: string | null) => {
      setErrorState(text);
      if (text) record("error", text);
    },
    [record],
  );

  const setNotice = useCallback(
    (text: string | null) => {
      setNoticeState(text);
      if (text) record("info", text);
    },
    [record],
  );

  const clearLog = useCallback(() => {
    setLog([]);
    setUnreadErrors(0);
  }, []);
  const markLogRead = useCallback(() => setUnreadErrors(0), []);

  const refresh = useCallback(async () => {
    if (!desktop.isAvailable()) return;
    try {
      const [current, stored, live, currentDecryptMode] = await Promise.all([
        desktop.projectCurrent(),
        desktop.connections().catch(() => [] as ConnectionSnapshot[]),
        desktop.proxySessions(),
        desktop.decryptMode(),
      ]);
      // The project has every flow but persists a proxy session's counters only
      // when its state changes, so the live snapshot wins where both have a row.
      const currentConnections = merge(stored, live);
      // These arrive as fresh objects on every poll. Replacing state
      // unconditionally gave the whole tree a new `project` and `connections`
      // identity twice a second, re-running downstream effects — including the
      // history reload that made the packet table appear to reset.
      setProject((previous) => (same(previous, current) ? previous : current));
      setConnections((previous) => (same(previous, currentConnections) ? previous : currentConnections));
      setDecryptModeState((previous) => (same(previous, currentDecryptMode) ? previous : currentDecryptMode));
    } catch (reason) {
      setError(message(reason));
    }
  }, [setError]);

  // Opening another project invalidates every row id the old one handed out.
  const projectPath = project?.path ?? null;
  useEffect(() => {
    void projectPath;
    packetRequest.current++;
    setSelectedPacket(null);
    setSelectedPacketId(null);
  }, [projectPath]);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .capabilities()
      .then(async (next) => {
        setCapabilities(next);
        if (!next.side_capture.available) {
          setCaptureStatus("unavailable");
          return;
        }
        try {
          await desktop.captureStart();
          setCaptureStatus("running");
        } catch (reason) {
          setCaptureStatus("failed");
          setError(message(reason));
        }
      })
      .catch((reason) => {
        setCaptureStatus("failed");
        setError(message(reason));
      });
    void desktop
      .interceptSettings()
      .then((current) =>
        desktop.setInterceptSettings({ ...current, ...storedInterceptPreferences(), enabled: false }),
      )
      .then((next) => {
        interceptRef.current = next;
        setInterceptSettingsState(next);
      })
      .catch((reason) => setError(message(reason)));
    void refresh();
    let timer: number | undefined;
    const schedule = () => {
      window.clearInterval(timer);
      const interval = document.hidden ? STATUS_POLL_MS_HIDDEN : STATUS_POLL_MS;
      timer = window.setInterval(() => void refresh(), interval);
    };
    schedule();
    const onVisibility = () => {
      schedule();
      if (!document.hidden) void refresh();
    };
    document.addEventListener("visibilitychange", onVisibility);
    const stopProxyEvents = subscription(
      desktop.onProxyEvent((event) => {
        if (event.type === "connection") void refresh();
        if (event.type === "error") setError(event.payload.message);
        if (event.type === "intercept_queue") {
          setInterceptPending(event.payload.pending);
          setInterceptSignal((value) => value + 1);
        }
      }),
    );
    // Both writers coalesce their own appends in the backend, so this fires a
    // handful of times a second rather than once per packet.
    const stopAppends = subscription(desktop.onPacketsAppended(() => setAppendSignal((value) => value + 1)));
    // An MCP client acted on the app: pull what it may have changed. Intercept
    // settings must be refetched before the next UI patch builds on them, or
    // that patch would quietly revert the agent's change.
    const stopMcpChanges = subscription(
      desktop.onMcpChange((topic) => {
        if (topic === "intercept") {
          void desktop
            .interceptSettings()
            .then((next) => {
              interceptRef.current = next;
              setInterceptSettingsState(next);
            })
            .catch((reason) => setError(message(reason)));
        }
        if (topic === "packets" || topic === "annotations") setAppendSignal((value) => value + 1);
        void refresh();
      }),
    );
    // Already coalesced by the backend; logged rather than toasted so a
    // failing writer cannot keep covering the window.
    const stopBackendErrors = subscription(
      desktop.onBackendError((failure) => record("error", backendErrorText(failure))),
    );
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      stopProxyEvents();
      stopMcpChanges();
      stopAppends();
      stopBackendErrors();
    };
  }, [record, refresh, setError]);

  const selectPacket = useCallback(
    async (id: number) => {
      setSelectedPacketId(id);
      const requestId = ++packetRequest.current;
      try {
        const packet = await desktop.packet(id);
        // A slower request for a row the operator has already moved off must not
        // replace the inspector contents.
        if (requestId !== packetRequest.current) return;
        setSelectedPacket(packet);
      } catch (reason) {
        if (requestId === packetRequest.current) setError(message(reason));
      }
    },
    [setError],
  );

  const setDecryptMode = useCallback(
    async (enabled: boolean) => {
      try {
        const next = await desktop.setDecryptMode(enabled);
        setDecryptModeState(next);
        return next;
      } catch (reason) {
        setError(message(reason));
        throw reason;
      }
    },
    [setError],
  );

  /**
   * Changes some Intercept settings, leaving the rest as the backend last had them.
   *
   * Patches are applied in order on top of each other. Committing the
   * expression on blur and then toggling a direction used to send two full
   * settings objects built from the same stale copy, so whichever landed last
   * silently reverted the other.
   */
  const patchInterceptSettings = useCallback(
    (patch: Partial<InterceptSettings>): Promise<InterceptSettings> => {
      const run = interceptQueue.current.then(async () => {
        const base = interceptRef.current;
        if (!base) throw new Error("Intercept settings are not loaded yet.");
        const next = await desktop.setInterceptSettings({ ...base, ...patch });
        interceptRef.current = next;
        setInterceptSettingsState(next);
        storeInterceptPreferences(next);
        return next;
      });
      interceptQueue.current = run.catch(() => undefined);
      return run.catch((reason) => {
        setError(message(reason));
        throw reason;
      });
    },
    [setError],
  );

  return {
    project,
    setProject,
    capabilities,
    connections,
    selectedPacket,
    selectedPacketId,
    selectPacket,
    packetFilter,
    setPacketFilter,
    connectionId,
    setConnectionId,
    decryptMode,
    setDecryptMode,
    captureStatus,
    appendSignal,
    interceptSettings,
    patchInterceptSettings,
    interceptPending,
    interceptSignal,
    error,
    setError,
    notice,
    setNotice,
    log,
    unreadErrors,
    clearLog,
    markLogRead,
    refresh,
  };
}

/** How a backend failure reads in the activity log. */
export function backendErrorText(failure: BackendError): string {
  const repeated = failure.repeated > 1 ? ` (×${failure.repeated})` : "";
  return `${failure.source}: ${failure.message}${repeated}`;
}

export function message(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

/**
 * Value equality for the small status payloads returned by polling.
 *
 * Structured comparison rather than `JSON.stringify`: the poll runs twice a
 * second against every connection, and serializing each snapshot allocates
 * enough to matter — key order also made equal payloads look different.
 */
export function same(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (typeof left !== "object" || typeof right !== "object" || !left || !right) {
    return Number.isNaN(left) && Number.isNaN(right);
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((item, index) => same(item, right[index]));
  }
  const a = left as Record<string, unknown>;
  const b = right as Record<string, unknown>;
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((key) => same(a[key], b[key]));
}

/** Overlays live proxy sessions onto the project's connection rows, busiest first. */
export function merge(stored: ConnectionSnapshot[], live: ConnectionSnapshot[]): ConnectionSnapshot[] {
  const byId = new Map(stored.map((connection) => [connection.id, connection]));
  for (const session of live) byId.set(session.id, session);
  return [...byId.values()].sort((left, right) => right.packet_count - left.packet_count);
}
