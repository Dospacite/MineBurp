import { useCallback, useEffect, useRef, useState } from "react";

import type {
  AppCapabilities,
  ConnectionSnapshot,
  DecryptModeStatus,
  HeldPacket,
  PacketView,
  ProjectInfo,
} from "../domain/types";
import { desktop } from "../lib/desktop";

/** Cadence for session/project polling — unrelated to traffic volume. */
const STATUS_POLL_MS = 2_000;

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
  const [heldPackets, setHeldPackets] = useState<HeldPacket[]>([]);
  const [decryptMode, setDecryptModeState] = useState<DecryptModeStatus | null>(null);
  const [captureStatus, setCaptureStatus] = useState<"starting" | "running" | "unavailable" | "failed">("starting");
  const [appendSignal, setAppendSignal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const packetRequest = useRef(0);

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
      setConnections((previous) =>
        same(previous, currentConnections) ? previous : currentConnections,
      );
      setDecryptModeState((previous) =>
        same(previous, currentDecryptMode) ? previous : currentDecryptMode,
      );
    } catch (reason) {
      setError(message(reason));
    }
  }, []);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop.capabilities().then(async (next) => {
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
    }).catch((reason) => {
      setCaptureStatus("failed");
      setError(message(reason));
    });
    void refresh();
    const timer = window.setInterval(() => void refresh(), STATUS_POLL_MS);
    const cleanups: Array<() => void> = [];
    void desktop
      .onProxyEvent((event) => {
        if (event.type === "held") {
          setHeldPackets((current) => [event.payload, ...current.filter((item) => item.id !== event.payload.id)]);
        }
        if (event.type === "connection") void refresh();
        if (event.type === "error") setError(event.payload.message);
      })
      .then((cleanup) => cleanups.push(cleanup));
    // Both writers coalesce their own appends in the backend, so this fires a
    // handful of times a second rather than once per packet.
    void desktop
      .onPacketsAppended(() => setAppendSignal((value) => value + 1))
      .then((cleanup) => cleanups.push(cleanup));
    return () => {
      window.clearInterval(timer);
      for (const cleanup of cleanups) cleanup();
    };
  }, [refresh]);

  const selectPacket = useCallback(async (id: number) => {
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
  }, []);

  const setDecryptMode = useCallback(async (enabled: boolean) => {
    try {
      const next = await desktop.setDecryptMode(enabled);
      setDecryptModeState(next);
      return next;
    } catch (reason) {
      setError(message(reason));
      throw reason;
    }
  }, []);

  return {
    project,
    setProject,
    capabilities,
    connections,
    selectedPacket,
    selectedPacketId,
    selectPacket,
    heldPackets,
    decryptMode,
    setDecryptMode,
    captureStatus,
    appendSignal,
    dismissHeld: (id: string) => setHeldPackets((current) => current.filter((item) => item.id !== id)),
    error,
    setError,
    refresh,
  };
}

export function message(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

/** Value equality for the small status payloads returned by polling. */
function same(left: unknown, right: unknown): boolean {
  return left === right || JSON.stringify(left) === JSON.stringify(right);
}

/** Overlays live proxy sessions onto the project's connection rows, busiest first. */
function merge(
  stored: ConnectionSnapshot[],
  live: ConnectionSnapshot[],
): ConnectionSnapshot[] {
  const byId = new Map(stored.map((connection) => [connection.id, connection]));
  for (const session of live) byId.set(session.id, session);
  return [...byId.values()].sort((left, right) => right.packet_count - left.packet_count);
}
