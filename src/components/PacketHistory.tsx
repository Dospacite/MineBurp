import {
  Bookmark,
  BookmarkCheck,
  ClipboardCopy,
  Columns3,
  EyeOff,
  Filter,
  GitCompare,
  MessagesSquare,
  Network,
  Pause,
  Play,
  Replace,
  Send,
  StickyNote,
  Timer,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  ConnectionSnapshot,
  PacketFilter,
  PacketHistoryQuery,
  PacketSummary,
  ProjectInfo,
} from "../domain/types";
import { t } from "../i18n";
import { annotationStore, useAnnotations } from "../lib/annotations";
import { loadTableSettings, storeTableSettings, type TableSettings } from "../lib/columns";
import { copyText, desktop, readPayload } from "../lib/desktop";
import { andExpression, expressionForPacket, quoteValue } from "../lib/expressions";
import { AnnotationEditor } from "./AnnotationEditor";
import { BookmarksDialog } from "./BookmarksDialog";
import { ColumnSettings } from "./ColumnSettings";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { ConversationList } from "./ConversationList";
import { EmptyState } from "./EmptyState";
import { PacketFilterBar } from "./PacketFilterBar";
import { COPY_LIMIT, type CopyFormat, renderCopy } from "./PacketInspector";
import { PacketTable, type RowCommand } from "./PacketTable";
import type { VirtualRowsHandle } from "./VirtualRows";

export const PAGE_SIZE = 250;
/** How many rows the history keeps before dropping the oldest loaded page. */
export const RETAINED_ROWS = 5_000;
/** Minimum gap between tail polls, even under a flood of append signals. */
const TAIL_INTERVAL_MS = 700;
/** Pause after the last filter edit before the history is re-queried. */
const RELOAD_DEBOUNCE_MS = 300;

/** What the history can ask the rest of the workbench to do with a packet. */
export interface PacketActions {
  sendToRepeater: (id: number) => void;
  /** Puts a packet on one side of the comparison; `b` also opens the Compare view. */
  compare: (id: number, slot: "a" | "b") => void;
  /** Whether a first packet is waiting to be compared against. */
  hasCompareA: boolean;
  /** Opens Replace with a new rule selecting packets like this one. */
  createRule: (expression: string) => void;
}

/**
 * Reads every row newer than `afterId` without leaving a hole.
 *
 * With only `afterId` set, the backend returns the *oldest* rows past the
 * cursor (newest first within the page), so the tail walks forward one page at
 * a time. It stops once there is more than the history keeps; the caller then
 * reloads the newest page instead of showing a stretch with a gap above it.
 */
export async function fetchNewer(
  query: PacketHistoryQuery,
  afterId: number,
  isCurrent: () => boolean = () => true,
): Promise<{ rows: PacketSummary[]; complete: boolean } | null> {
  let rows: PacketSummary[] = [];
  let cursor = afterId;
  for (;;) {
    const page = await desktop.packets({ ...query, afterId: cursor, beforeId: null, limit: PAGE_SIZE + 1 });
    if (!isCurrent()) return null;
    // The extra row is the newest one; it is read again as part of the next page.
    const full = page.length > PAGE_SIZE;
    const taken = full ? page.slice(page.length - PAGE_SIZE) : page;
    rows = [...taken, ...rows];
    if (!full) return { rows, complete: true };
    if (rows.length >= RETAINED_ROWS) return { rows, complete: false };
    const newest = taken[0]?.id;
    if (newest === undefined) return { rows, complete: true };
    cursor = newest;
  }
}

export function PacketHistory({
  project,
  connectionId,
  connections = [],
  onConnectionChange,
  filter,
  onFilterChange,
  selectedId,
  appendSignal,
  onSelect,
  actions,
  onError,
  onNotice,
  reloadSignal = 0,
}: {
  project: ProjectInfo | null;
  /** Connection selected in the capture sidebar, or null for all traffic. */
  connectionId: string | null;
  connections?: ConnectionSnapshot[];
  onConnectionChange?: (connectionId: string | null) => void;
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
  actions?: PacketActions;
  onError: (error: string) => void;
  onNotice?: (notice: string) => void;
  /** Bumped when rows changed underneath the history, e.g. after a delete or an import. */
  reloadSignal?: number;
}) {
  const [packets, setPacketsState] = useState<PacketSummary[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [following, setFollowing] = useState(true);
  /** New traffic arrived while following was paused. */
  const [hasNew, setHasNew] = useState(false);
  const [layout, setLayout] = useState<"table" | "conversation">("table");
  const [settings, setSettings] = useState<TableSettings>(loadTableSettings);
  const [columnsOpen, setColumnsOpen] = useState(false);
  const [timeReference, setTimeReference] = useState<number | null>(null);
  const [menu, setMenu] = useState<{ packet: PacketSummary; x: number; y: number } | null>(null);
  const [editing, setEditing] = useState<number | null>(null);
  const [bookmarksOpen, setBookmarksOpen] = useState(false);
  const annotations = useAnnotations();
  const request = useRef(0);
  /** A reload is waiting on the backend; a newer one cancels it there too. */
  const reloading = useRef(false);
  /** Changes whenever the rows are replaced; a tail read from an older epoch is discarded. */
  const epoch = useRef(0);
  const tailBusy = useRef(false);
  const tailAgain = useRef(false);
  const table = useRef<VirtualRowsHandle | null>(null);
  const lastTail = useRef(0);
  const packetsRef = useRef<PacketSummary[]>([]);
  packetsRef.current = packets;
  const followingRef = useRef(following);
  followingRef.current = following;
  const bindTable = useCallback((handle: VirtualRowsHandle | null) => {
    table.current = handle;
  }, []);

  /** Rows are mirrored into a ref so the tail can read the newest id without re-subscribing. */
  const setPackets = useCallback((update: (current: PacketSummary[]) => PacketSummary[]) => {
    setPacketsState((current) => {
      const next = update(current);
      packetsRef.current = next;
      return next;
    });
  }, []);

  const query = useMemo<PacketHistoryQuery>(
    () => ({ ...filter, search: filter.search.trim(), connectionId }),
    [connectionId, filter],
  );
  const queryKey = JSON.stringify(query);
  const queryRef = useRef(query);
  queryRef.current = query;

  const fail = useCallback(
    (reason: unknown) => onError(reason instanceof Error ? reason.message : String(reason)),
    [onError],
  );

  const reload = useCallback(async () => {
    if (!project || !desktop.isAvailable()) return;
    const requestId = ++request.current;
    epoch.current++;
    // A superseded query — typically a payload search — would otherwise keep
    // a reader busy until its time budget ran out.
    if (reloading.current) await desktop.packetsQueryCancel().catch(() => undefined);
    if (requestId !== request.current) return;
    reloading.current = true;
    setLoading(true);
    try {
      const result = await desktop.packets({ ...queryRef.current, limit: PAGE_SIZE + 1 });
      if (requestId !== request.current) return;
      setPackets(() => result.slice(0, PAGE_SIZE));
      setHasMore(result.length > PAGE_SIZE);
      setHasNew(false);
    } catch (reason) {
      if (requestId === request.current) fail(reason);
    } finally {
      if (requestId === request.current) {
        reloading.current = false;
        setLoading(false);
      }
    }
  }, [fail, project, setPackets]);

  /**
   * Prepends rows newer than what is loaded, leaving everything already
   * loaded — and the operator's scroll position — alone.
   *
   * One tail read runs at a time; a signal that arrives during one schedules a
   * single follow-up instead of a second concurrent read.
   */
  const pullTail = useCallback(async () => {
    if (!project || !desktop.isAvailable()) return;
    if (tailBusy.current) {
      tailAgain.current = true;
      return;
    }
    tailBusy.current = true;
    try {
      do {
        tailAgain.current = false;
        const newest = packetsRef.current[0]?.id;
        if (newest === undefined) {
          await reload();
          continue;
        }
        const started = epoch.current;
        let result: Awaited<ReturnType<typeof fetchNewer>>;
        try {
          result = await fetchNewer(queryRef.current, newest, () => started === epoch.current);
        } catch (reason) {
          // A read cancelled because the filter changed is not a failure.
          if (started === epoch.current) throw reason;
          continue;
        }
        if (!result || result.rows.length === 0) continue;
        if (!result.complete) {
          // More arrived than the history keeps: start again from the newest
          // page and leave the rest to "Load older" rather than a hole.
          await reload();
          continue;
        }
        // Updaters may run lazily, so whether rows were dropped is judged
        // here; an overestimate only means "Load older" finds nothing.
        if (packetsRef.current.length + result.rows.length > RETAINED_ROWS) setHasMore(true);
        setPackets((current) => {
          const known = new Set(current.map((packet) => packet.id));
          const fresh = result.rows.filter((packet) => !known.has(packet.id));
          if (fresh.length === 0) return current;
          const next = [...fresh, ...current];
          return next.length <= RETAINED_ROWS ? next : next.slice(0, RETAINED_ROWS);
        });
      } while (tailAgain.current);
    } catch (reason) {
      fail(reason);
    } finally {
      tailBusy.current = false;
    }
  }, [fail, project, reload, setPackets]);
  const pullTailRef = useRef(pullTail);
  pullTailRef.current = pullTail;

  const loadOlder = useCallback(async () => {
    if (!project || loading || !hasMore) return;
    const oldest = packetsRef.current.at(-1)?.id;
    if (oldest === undefined) return;
    const requestId = ++request.current;
    const started = epoch.current;
    setLoading(true);
    try {
      const result = await desktop.packets({ ...queryRef.current, beforeId: oldest, limit: PAGE_SIZE + 1 });
      if (requestId !== request.current || started !== epoch.current) return;
      const page = result.slice(0, PAGE_SIZE);
      setPackets((current) => {
        const known = new Set(current.map((packet) => packet.id));
        return [...current, ...page.filter((packet) => !known.has(packet.id))];
      });
      setHasMore(result.length > PAGE_SIZE);
    } catch (reason) {
      if (requestId === request.current) fail(reason);
    } finally {
      if (requestId === request.current) setLoading(false);
    }
  }, [fail, hasMore, loading, project, setPackets]);

  // Changing filters is the only thing that legitimately replaces the rows.
  // Keyed on the query's *value* and the project path rather than on
  // `reload`'s identity: a wholesale reload here is what discards loaded
  // pages and the operator's scroll position.
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  useEffect(() => {
    void queryKey;
    const timer = window.setTimeout(() => void reloadRef.current(), RELOAD_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [queryKey, project?.path]);

  useEffect(() => {
    if (reloadSignal > 0) void reloadRef.current();
  }, [reloadSignal]);

  // Annotations are fetched for loaded rows only, in batches, and cached.
  useEffect(() => {
    if (packets.length === 0 || !desktop.isAvailable()) return;
    annotationStore.ensure(packets.map((packet) => packet.id)).catch(fail);
  }, [fail, packets]);

  // A different project's timestamps are a different clock.
  useEffect(() => {
    void project?.path;
    setTimeReference(null);
  }, [project?.path]);

  // Only the signal drives this effect. Following and the loaded rows are read
  // through refs: depending on them re-ran the effect after every append, which
  // queried again and, while paused, counted the operator's own "load older"
  // as new traffic.
  useEffect(() => {
    if (!project || appendSignal === 0) return undefined;
    if (!followingRef.current) {
      setHasNew(true);
      return undefined;
    }
    // Rate limit with a trailing timer rather than by dropping the signal, so
    // the last packets of a burst still arrive once traffic goes quiet.
    const wait = Math.max(0, TAIL_INTERVAL_MS - (Date.now() - lastTail.current));
    const timer = window.setTimeout(() => {
      lastTail.current = Date.now();
      void pullTailRef.current();
    }, wait);
    return () => window.clearTimeout(timer);
  }, [appendSignal, project]);

  const updateSettings = useCallback((next: TableSettings) => {
    setSettings(next);
    storeTableSettings(next);
  }, []);

  const connectionLabels = useMemo(
    () =>
      new Map(
        connections.map((connection) => [
          connection.id,
          `${connection.target.host}:${connection.target.port}`,
        ]),
      ),
    [connections],
  );

  const effectiveReference = timeReference ?? packets.at(-1)?.timestamp_micros ?? null;

  const copyRow = useCallback(
    async (packet: PacketSummary, format: CopyFormat) => {
      try {
        const view = format === "json" ? await desktop.packet(packet.id) : null;
        const { bytes, complete, total } = await readPayload(packet.id, COPY_LIMIT);
        await copyText(renderCopy(format, bytes, view));
        onNotice?.(
          complete
            ? t("copy.done", { count: bytes.length.toLocaleString() })
            : t("inspector.copy.partial", {
                copied: bytes.length.toLocaleString(),
                total: total.toLocaleString(),
              }),
        );
      } catch (reason) {
        fail(reason);
      }
    },
    [fail, onNotice],
  );

  const onRowMenu = useCallback(
    (packet: PacketSummary, x: number, y: number) => setMenu({ packet, x, y }),
    [],
  );

  const onRowCommand = useCallback(
    (command: RowCommand, packet: PacketSummary) => {
      if (command === "repeater") actions?.sendToRepeater(packet.id);
      else if (command === "copy-hex") void copyRow(packet, "hex");
      else if (command === "compare") actions?.compare(packet.id, actions.hasCompareA ? "b" : "a");
      else if (command === "bookmark") void annotationStore.toggleBookmark(packet.id).catch(fail);
    },
    [actions, copyRow, fail],
  );

  function menuItems(packet: PacketSummary): MenuItem[] {
    const label = packet.name ?? (packet.packet_id === null ? null : `0x${packet.packet_id.toString(16)}`);
    const predicate = packet.name
      ? `name == ${quoteValue(packet.name)}`
      : packet.packet_id === null
        ? null
        : `id == ${packet.packet_id}`;
    const items: MenuItem[] = [];
    const bookmarked = annotations.get(packet.id)?.bookmarked ?? false;
    items.push(
      {
        label: bookmarked ? t("menu.bookmark.remove") : t("menu.bookmark"),
        shortcut: "Ctrl+B",
        icon: bookmarked ? <BookmarkCheck size={13} /> : <Bookmark size={13} />,
        onSelect: () => void annotationStore.toggleBookmark(packet.id).catch(fail),
      },
      {
        label: t("menu.annotate"),
        icon: <StickyNote size={13} />,
        onSelect: () => setEditing(packet.id),
      },
      { kind: "separator" },
    );
    if (actions) {
      items.push(
        {
          label: t("menu.repeater"),
          shortcut: "Ctrl+R",
          icon: <Send size={13} />,
          onSelect: () => actions.sendToRepeater(packet.id),
        },
        { kind: "separator" },
        {
          label: t("menu.compare-a"),
          icon: <GitCompare size={13} />,
          onSelect: () => actions.compare(packet.id, "a"),
        },
        {
          label: t("menu.compare-b"),
          shortcut: "Ctrl+D",
          icon: <GitCompare size={13} />,
          disabled: !actions.hasCompareA,
          onSelect: () => actions.compare(packet.id, "b"),
        },
        { kind: "separator" },
      );
    }
    if (predicate && label) {
      items.push({
        label: t("menu.only-name", { name: label }),
        icon: <Filter size={13} />,
        onSelect: () =>
          onFilterChange({ ...filter, expression: andExpression(filter.expression, predicate) }),
      });
    }
    if (packet.name) {
      const name = packet.name;
      items.push({
        label: t("menu.hide-name", { name }),
        icon: <EyeOff size={13} />,
        onSelect: () =>
          onFilterChange({
            ...filter,
            excludeNames: filter.excludeNames.includes(name)
              ? filter.excludeNames
              : [...filter.excludeNames, name],
          }),
      });
    }
    if (onConnectionChange) {
      items.push(
        {
          label: t("menu.only-connection"),
          icon: <Network size={13} />,
          disabled: connectionId === packet.connection_id,
          onSelect: () => onConnectionChange(packet.connection_id),
        },
        {
          label: t("menu.conversation"),
          icon: <MessagesSquare size={13} />,
          onSelect: () => {
            onConnectionChange(packet.connection_id);
            setLayout("conversation");
          },
        },
      );
    }
    items.push(
      timeReference === packet.timestamp_micros
        ? {
            label: t("menu.time-reference.clear"),
            icon: <Timer size={13} />,
            onSelect: () => setTimeReference(null),
          }
        : {
            label: t("menu.time-reference"),
            icon: <Timer size={13} />,
            onSelect: () => {
              setTimeReference(packet.timestamp_micros);
              if (settings.timeMode !== "relative") updateSettings({ ...settings, timeMode: "relative" });
            },
          },
    );
    if (actions) {
      items.push(
        { kind: "separator" },
        {
          label: t("menu.rule"),
          icon: <Replace size={13} />,
          onSelect: () => actions.createRule(expressionForPacket(packet)),
        },
      );
    }
    items.push(
      { kind: "separator" },
      { kind: "heading", label: t("menu.copy-as") },
      {
        label: t("copy.as.hex"),
        shortcut: "Ctrl+Shift+C",
        icon: <ClipboardCopy size={13} />,
        onSelect: () => void copyRow(packet, "hex"),
      },
      { label: t("copy.as.base64"), onSelect: () => void copyRow(packet, "base64") },
      { label: t("copy.as.c"), onSelect: () => void copyRow(packet, "c") },
      { label: t("copy.as.json"), onSelect: () => void copyRow(packet, "json") },
      { label: t("copy.as.dump"), onSelect: () => void copyRow(packet, "dump") },
    );
    return items;
  }

  if (!project) {
    return <EmptyState title={t("traffic.no-project.title")} detail={t("history.no-project.detail")} />;
  }

  const footer = (
    <div className="history-footer">
      <button
        type="button"
        className="button"
        disabled={!hasMore || loading}
        onClick={() => void loadOlder()}
      >
        {hasMore ? t("history.load-older") : t("history.start-of-history")}
      </button>
    </div>
  );
  // Scrolling away from the newest row pauses following, so reading older
  // traffic is never interrupted by arriving packets.
  const onScrollStateChange = (atTop: boolean) => {
    if (!atTop && followingRef.current) setFollowing(false);
  };

  return (
    <section className="packet-history" aria-label={t("history.title")}>
      <PacketFilterBar
        filter={filter}
        onChange={onFilterChange}
        loaded={packets.length}
        onError={onError}
        onNotice={onNotice}
      />
      <div className="history-result-bar" aria-live="polite">
        <div className="history-layout">
          <div className="segmented" aria-label={t("history.layout")}>
            <button
              type="button"
              className={layout === "table" ? "active" : ""}
              aria-pressed={layout === "table"}
              onClick={() => setLayout("table")}
            >
              {t("history.layout.table")}
            </button>
            <button
              type="button"
              className={layout === "conversation" ? "active" : ""}
              aria-pressed={layout === "conversation"}
              onClick={() => setLayout("conversation")}
              title={t("conversation.hint")}
            >
              {t("history.layout.conversation")}
            </button>
          </div>
          <button
            type="button"
            className="icon-button"
            aria-label={t("columns.title")}
            title={t("columns.title")}
            onClick={() => setColumnsOpen(true)}
          >
            <Columns3 size={13} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={t("bookmarks.open")}
            title={t("bookmarks.open")}
            onClick={() => setBookmarksOpen(true)}
          >
            <Bookmark size={13} aria-hidden="true" />
          </button>
          <span>{hasMore ? t("history.more-available") : t("history.all-loaded")}</span>
          {layout === "conversation" && !connectionId && (
            <span className="history-hint">{t("conversation.all-connections")}</span>
          )}
        </div>
        <div className="history-follow">
          {!following && hasNew && (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setFollowing(true);
                setHasNew(false);
                table.current?.scrollToTop();
                void pullTail();
              }}
            >
              {t("history.jump-newest")}
            </button>
          )}
          <button
            type="button"
            className={`follow-toggle ${following ? "on" : ""}`}
            aria-pressed={following}
            onClick={() => {
              const next = !following;
              setFollowing(next);
              if (next && hasNew) {
                setHasNew(false);
                void pullTail();
              }
            }}
            title={following ? t("history.pause") : t("history.resume")}
          >
            {following ? <Play size={11} /> : <Pause size={11} />}
            {following ? t("history.following") : t("history.paused")}
          </button>
          <span>{loading ? t("history.updating") : t("history.newest-first")}</span>
        </div>
      </div>
      {packets.length ? (
        layout === "table" ? (
          <PacketTable
            packets={packets}
            selectedId={selectedId}
            onSelect={onSelect}
            handleRef={bindTable}
            columns={settings.columns}
            timeMode={settings.timeMode}
            timeReference={effectiveReference}
            connectionLabels={connectionLabels}
            onRowMenu={onRowMenu}
            onRowCommand={onRowCommand}
            annotations={annotations}
            onScrollStateChange={onScrollStateChange}
            footer={footer}
          />
        ) : (
          <ConversationList
            packets={packets}
            selectedId={selectedId}
            onSelect={onSelect}
            handleRef={bindTable}
            onRowMenu={onRowMenu}
            onScrollStateChange={onScrollStateChange}
            footer={footer}
          />
        )
      ) : (
        <EmptyState
          title={loading ? t("history.loading") : t("history.empty.title")}
          detail={loading ? "" : t("history.empty.detail")}
        />
      )}
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          label={t("menu.label")}
          items={menuItems(menu.packet)}
          onClose={() => setMenu(null)}
        />
      )}
      {editing !== null && (
        <AnnotationEditor packetId={editing} onClose={() => setEditing(null)} onError={onError} />
      )}
      {bookmarksOpen && (
        <BookmarksDialog onSelect={onSelect} onClose={() => setBookmarksOpen(false)} onError={onError} />
      )}
      {columnsOpen && (
        <ColumnSettings settings={settings} onChange={updateSettings} onClose={() => setColumnsOpen(false)} />
      )}
    </section>
  );
}
