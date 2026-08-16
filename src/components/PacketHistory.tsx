import { Pause, Play } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  PacketFilter,
  PacketHistoryQuery,
  PacketSummary,
  ProjectInfo,
} from "../domain/types";
import { desktop } from "../lib/desktop";
import { EmptyState } from "./EmptyState";
import { PacketFilterBar } from "./PacketFilterBar";
import { PacketTable } from "./PacketTable";
import type { VirtualRowsHandle } from "./VirtualRows";

const PAGE_SIZE = 250;
/** How many rows the history keeps before dropping the oldest loaded page. */
const RETAINED_ROWS = 5_000;
/** Minimum gap between tail polls, even under a flood of append signals. */
const TAIL_INTERVAL_MS = 700;

export function PacketHistory({
  project,
  connectionId,
  filter,
  onFilterChange,
  selectedId,
  appendSignal,
  onSelect,
  onError,
}: {
  project: ProjectInfo | null;
  /** Connection selected in the capture sidebar, or null for all traffic. */
  connectionId: string | null;
  /**
   * The filter, owned by the workbench. This view unmounts whenever another
   * one is on screen, so keeping it here would discard it on every tab switch.
   */
  filter: PacketFilter;
  onFilterChange: (filter: PacketFilter) => void;
  selectedId: number | null;
  /** Increments when the backend reports new packets were written. */
  appendSignal: number;
  onSelect: (id: number) => void;
  onError: (error: string) => void;
}) {
  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [following, setFollowing] = useState(true);
  const [pendingNew, setPendingNew] = useState(0);
  const request = useRef(0);
  const table = useRef<VirtualRowsHandle | null>(null);
  const lastTail = useRef(0);
  const bindTable = useCallback((handle: VirtualRowsHandle | null) => {
    table.current = handle;
  }, []);

  const query = useMemo<PacketHistoryQuery>(
    () => ({ ...filter, search: filter.search.trim(), connectionId }),
    [connectionId, filter],
  );
  const queryKey = JSON.stringify(query);

  const reload = useCallback(async () => {
    if (!project || !desktop.isAvailable()) return;
    const requestId = ++request.current;
    setLoading(true);
    try {
      const result = await desktop.packets({ ...query, limit: PAGE_SIZE + 1 });
      if (requestId !== request.current) return;
      setPackets(result.slice(0, PAGE_SIZE));
      setHasMore(result.length > PAGE_SIZE);
      setPendingNew(0);
    } catch (reason) {
      if (requestId === request.current) onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (requestId === request.current) setLoading(false);
    }
  }, [onError, project, query]);

  /**
   * Appends rows newer than what is loaded.
   *
   * The previous version re-read page zero on a timer and replaced the visible
   * rows with the newest 250, which is what made the table appear to reset
   * while capture was running. Reading forward from the newest known id leaves
   * everything already loaded — and the operator's scroll position — alone.
   */
  const pullTail = useCallback(async () => {
    if (!project || !desktop.isAvailable()) return;
    const newest = packets[0]?.id;
    if (newest === undefined) {
      await reload();
      return;
    }
    try {
      const result = await desktop.packets({ ...query, afterId: newest, limit: PAGE_SIZE });
      if (result.length === 0) return;
      setPackets((current) => {
        const known = new Set(current.map((packet) => packet.id));
        const fresh = result.filter((packet) => !known.has(packet.id));
        if (fresh.length === 0) return current;
        const next = [...fresh, ...current];
        return next.length > RETAINED_ROWS ? next.slice(0, RETAINED_ROWS) : next;
      });
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    }
  }, [onError, packets, project, query, reload]);

  const loadOlder = useCallback(async () => {
    if (!project || loading || !hasMore) return;
    const oldest = packets.at(-1)?.id;
    if (oldest === undefined) return;
    const requestId = ++request.current;
    setLoading(true);
    try {
      const result = await desktop.packets({ ...query, beforeId: oldest, limit: PAGE_SIZE + 1 });
      if (requestId !== request.current) return;
      const page = result.slice(0, PAGE_SIZE);
      setPackets((current) => {
        const known = new Set(current.map((packet) => packet.id));
        return [...current, ...page.filter((packet) => !known.has(packet.id))];
      });
      setHasMore(result.length > PAGE_SIZE);
    } catch (reason) {
      if (requestId === request.current) onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (requestId === request.current) setLoading(false);
    }
  }, [hasMore, loading, onError, packets, project, query]);

  // Changing filters is the only thing that legitimately replaces the rows.
  // Deliberately keyed on the query's *value* and the project path rather than
  // on `reload`'s identity: a wholesale reload here is what discards loaded
  // pages and the operator's scroll position.
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  useEffect(() => {
    const timer = window.setTimeout(() => void reloadRef.current(), 200);
    return () => window.clearTimeout(timer);
  }, [queryKey, project?.path]);

  useEffect(() => {
    if (!project || appendSignal === 0) return undefined;
    if (!following) {
      setPendingNew((count) => count + 1);
      return undefined;
    }
    // Rate limit with a trailing timer rather than by dropping the signal, so
    // the last packets of a burst still arrive once traffic goes quiet.
    const wait = Math.max(0, TAIL_INTERVAL_MS - (Date.now() - lastTail.current));
    const timer = window.setTimeout(() => {
      lastTail.current = Date.now();
      void pullTail();
    }, wait);
    return () => window.clearTimeout(timer);
  }, [appendSignal, following, project, pullTail]);

  if (!project) {
    return <EmptyState title="No project is open" detail="Open or create a project to record packet history." />;
  }

  return (
    <section className="packet-history" aria-label="Persisted packet history">
      <PacketFilterBar
        filter={filter}
        onChange={onFilterChange}
        loaded={packets.length}
        onError={onError}
      />
      <div className="history-result-bar" aria-live="polite">
        <span>{hasMore ? "more available" : "all loaded"}</span>
        <div className="history-follow">
          {!following && pendingNew > 0 && (
            <button
              className="link-button"
              onClick={() => {
                setFollowing(true);
                setPendingNew(0);
                table.current?.scrollToTop();
                void pullTail();
              }}
            >
jump to newest
            </button>
          )}
          <button
            className={`follow-toggle ${following ? "on" : ""}`}
            aria-pressed={following}
            onClick={() => setFollowing(!following)}
            title={following ? "Pause live updates" : "Resume live updates"}
          >
            {following ? <Play size={11} /> : <Pause size={11} />}
            {following ? "Following" : "Paused"}
          </button>
          <span>{loading ? "Updating…" : "Newest first"}</span>
        </div>
      </div>
      {packets.length ? (
        <PacketTable
          packets={packets}
          selectedId={selectedId}
          onSelect={onSelect}
          handleRef={bindTable}
          // Scrolling away from the newest row pauses following, so reading
          // older traffic is never interrupted by arriving packets.
          onScrollStateChange={(atTop) => {
            if (!atTop && following) setFollowing(false);
          }}
          footer={
            <div className="history-footer">
              <button className="button" disabled={!hasMore || loading} onClick={() => void loadOlder()}>
                {hasMore ? "Load older packets" : "Start of matching history"}
              </button>
            </div>
          }
        />
      ) : (
        <EmptyState title={loading ? "Loading…" : "No packets match these filters"} detail={loading ? "" : "Adjust the filters or capture more traffic."} />
      )}
    </section>
  );
}
