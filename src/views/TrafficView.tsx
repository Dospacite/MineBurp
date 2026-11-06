import {
  Archive,
  Database,
  FileJson,
  FileUp,
  Loader2,
  Network,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Trash2,
  WifiOff,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ContextMenu, type MenuItem } from "../components/ContextMenu";
import { DeleteHistoryDialog } from "../components/DeleteHistoryDialog";
import { EmptyState } from "../components/EmptyState";
import { ImportCaptureDialog } from "../components/ImportCaptureDialog";
import { describe } from "../components/PacketFilterBar";
import { type PacketActions, PacketHistory } from "../components/PacketHistory";
import { PacketInspector } from "../components/PacketInspector";
import { Split } from "../components/Split";
import type {
  AppCapabilities,
  CaptureStats,
  ConnectionSnapshot,
  DecryptModeStatus,
  PacketFilter,
  PacketView,
  ProjectInfo,
} from "../domain/types";
import { t } from "../i18n";
import { annotationStore } from "../lib/annotations";
import { desktop } from "../lib/desktop";
import { chooseExportDestination, choosePcapngDestination } from "../lib/files";
import { formatBytes } from "../lib/format";
import { useTrafficAppend, useTrafficConnections } from "../lib/trafficStore";

type CaptureStatus = "starting" | "running" | "unavailable" | "failed";

const STATS_POLL_MS = 2_000;

export function TrafficView({
  capabilities,
  project,
  connections: providedConnections,
  selectedPacket,
  selectedPacketId,
  filter,
  onFilterChange,
  connectionId,
  onConnectionChange,
  decryptMode,
  captureStatus,
  appendSignal: providedAppendSignal,
  onSelectPacket,
  onDecryptModeChange,
  onOpenRepeater,
  actions,
  onError,
  onNotice,
  onDataChanged,
}: {
  capabilities: AppCapabilities | null;
  project: ProjectInfo | null;
  connections?: ConnectionSnapshot[];
  selectedPacket: PacketView | null;
  selectedPacketId: number | null;
  /** Held by the workbench so it survives a trip to another view. */
  filter: PacketFilter;
  onFilterChange: (filter: PacketFilter) => void;
  connectionId: string | null;
  onConnectionChange: (connectionId: string | null) => void;
  decryptMode: DecryptModeStatus | null;
  captureStatus: CaptureStatus;
  appendSignal?: number;
  onSelectPacket: (id: number) => void;
  onDecryptModeChange: (enabled: boolean) => Promise<DecryptModeStatus>;
  /** Sends the inspected packet to a new Repeater tab. */
  onOpenRepeater: (packet: PacketView) => void;
  actions?: PacketActions;
  onError: (error: string) => void;
  onNotice: (notice: string) => void;
  /** Rows were added or removed outside the live capture; connections need a refresh. */
  onDataChanged?: () => void;
}) {
  const storedConnections = useTrafficConnections();
  const connections = providedConnections ?? storedConnections;
  const storeSignal = useTrafficAppend();
  const appendSignal = providedAppendSignal ?? storeSignal;
  const [dataMenu, setDataMenu] = useState<{ x: number; y: number } | null>(null);
  const [dialog, setDialog] = useState<"delete" | "import" | null>(null);
  const [reloadSignal, setReloadSignal] = useState(0);
  const [changingDecryptMode, setChangingDecryptMode] = useState(false);
  const [connectionSearch, setConnectionSearch] = useState("");
  const [exporting, setExporting] = useState(false);
  const capture = capabilities?.side_capture;
  // Stable so the memoised inspector does not re-render on every append.
  const compareInspected = useMemo(
    () => (actions ? (id: number) => actions.compare(id, actions.hasCompareA ? "b" : "a") : undefined),
    [actions],
  );

  useEffect(() => {
    if (connectionId && !connections.some((connection) => connection.id === connectionId)) {
      onConnectionChange(null);
    }
  }, [connectionId, connections, onConnectionChange]);

  async function toggleDecryptMode() {
    if (changingDecryptMode) return;
    setChangingDecryptMode(true);
    try {
      await onDecryptModeChange(!decryptMode?.enabled);
    } catch {
      // The hook publishes the actionable error toast.
    } finally {
      setChangingDecryptMode(false);
    }
  }

  const decryptEnabled = decryptMode?.enabled ?? false;
  const totalPackets = connections.reduce((sum, connection) => sum + connection.packet_count, 0);
  const filteredConnections = connections.filter((c) => {
    if (!connectionSearch.trim()) return true;
    const q = connectionSearch.toLowerCase();
    return (
      c.target.host.toLowerCase().includes(q) ||
      String(c.target.port).includes(q) ||
      c.state.toLowerCase().includes(q) ||
      (c.minecraft_version ?? "").toLowerCase().includes(q)
    );
  });

  const historyQuery = { ...filter, search: filter.search.trim(), connectionId };
  const fail = (reason: unknown) => onError(reason instanceof Error ? reason.message : String(reason));

  async function exportFiltered(format: "json" | "pcapng") {
    if (exporting) return;
    try {
      const path = format === "json" ? await chooseExportDestination() : await choosePcapngDestination();
      if (!path) return;
      setExporting(true);
      if (format === "json") {
        const count = await desktop.packetsExport(path, historyQuery);
        onNotice(t("traffic.export.done", { count: count.toLocaleString(), path }));
      } else {
        const summary = await desktop.packetsExportPcapng(path, historyQuery);
        onNotice(
          t("traffic.export.pcapng.done", {
            count: summary.packets.toLocaleString(),
            connections: summary.connections.toLocaleString(),
            path,
          }),
        );
      }
    } catch (reason) {
      fail(reason);
    } finally {
      setExporting(false);
    }
  }

  async function compact() {
    if (exporting) return;
    setExporting(true);
    try {
      const summary = await desktop.projectCompact();
      onNotice(
        t("traffic.compact.done", {
          before: formatBytes(summary.bytesBefore),
          after: formatBytes(summary.bytesAfter),
        }),
      );
    } catch (reason) {
      fail(reason);
    } finally {
      setExporting(false);
    }
  }

  const changed = () => {
    setReloadSignal((value) => value + 1);
    onDataChanged?.();
  };

  const connectionLabel = connectionId
    ? (() => {
        const connection = connections.find((c) => c.id === connectionId);
        return connection ? `${connection.target.host}:${connection.target.port}` : connectionId.slice(0, 8);
      })()
    : null;
  const filterSummary = describe(filter);
  const scope = [filterSummary ?? t("filter.all-packets"), connectionLabel].filter(Boolean).join(" · ");
  const noProject = !project;

  const dataItems: MenuItem[] = [
    { kind: "heading", label: t("traffic.data.export") },
    {
      label: t("traffic.export"),
      icon: <FileJson size={13} />,
      onSelect: () => void exportFiltered("json"),
    },
    {
      label: t("traffic.export.pcapng"),
      icon: <Network size={13} />,
      onSelect: () => void exportFiltered("pcapng"),
    },
    { kind: "separator" },
    { label: t("traffic.import"), icon: <FileUp size={13} />, onSelect: () => setDialog("import") },
    { kind: "separator" },
    {
      label: t("traffic.delete"),
      icon: <Trash2 size={13} />,
      onSelect: () => setDialog("delete"),
    },
    { label: t("traffic.compact"), icon: <Archive size={13} />, onSelect: () => void compact() },
  ];

  const statusDetail =
    captureStatus === "running" || captureStatus === "starting" ? null : (capture?.reason ?? null);

  return (
    <Split
      orientation="columns"
      storageKey="traffic"
      initial={[0.19, 0.51, 0.3]}
      minimum={200}
      className="capture-layout"
    >
      <aside className="flow-pane" aria-label={t("traffic.capture.sidebar")}>
        <div className={`decrypt-control ${decryptEnabled ? "enabled" : ""}`}>
          <span className="decrypt-icon" aria-hidden="true">
            {decryptEnabled ? <ShieldCheck size={16} /> : <ShieldOff size={16} />}
          </span>
          <strong>{t("traffic.decrypt.title")}</strong>
          <button
            type="button"
            className={`decrypt-switch ${decryptEnabled ? "on" : ""}`}
            role="switch"
            aria-checked={decryptEnabled}
            disabled={changingDecryptMode}
            onClick={() => void toggleDecryptMode()}
          >
            {decryptEnabled ? t("traffic.decrypt.on") : t("traffic.decrypt.off")}
          </button>
        </div>
        <div className={`capture-status ${captureStatus}`} role="status" aria-live="polite">
          {captureStatus === "running" ? (
            <Radio size={15} />
          ) : captureStatus === "starting" ? (
            <Loader2 className="spin" size={15} />
          ) : captureStatus === "unavailable" ? (
            <WifiOff size={15} />
          ) : (
            <ShieldAlert size={15} />
          )}
          <span>
            <strong>{t(`app.capture.${captureStatus}`)}</strong>
            {statusDetail && <small>{statusDetail}</small>}
          </span>
        </div>
        {(captureStatus === "running" || captureStatus === "failed") && capture?.available && (
          <CaptureCounters />
        )}
        <div className="flow-toolbar">
          <label className="flow-search">
            <Search size={12} aria-hidden="true" />
            <input
              value={connectionSearch}
              onChange={(e) => setConnectionSearch(e.target.value)}
              placeholder={t("traffic.connections.filter.placeholder")}
              aria-label={t("traffic.connections.filter")}
            />
          </label>
          <button
            type="button"
            className="icon-button"
            title={t("traffic.data")}
            aria-label={t("traffic.data")}
            aria-haspopup="menu"
            aria-expanded={dataMenu !== null}
            disabled={noProject || exporting}
            onClick={(event) => {
              const rect = event.currentTarget.getBoundingClientRect();
              setDataMenu({ x: rect.left, y: rect.bottom + 4 });
            }}
          >
            {exporting ? (
              <Loader2 className="spin" size={14} aria-hidden="true" />
            ) : (
              <Database size={14} aria-hidden="true" />
            )}
          </button>
        </div>
        <div className="flow-list" role="group" aria-label={t("traffic.connections")}>
          <button
            type="button"
            className={`flow-card ${connectionId === null ? "selected" : ""}`}
            onClick={() => onConnectionChange(null)}
            aria-pressed={connectionId === null}
          >
            <span>
              <strong>{t("traffic.all")}</strong>
              <small>{t("traffic.packets.count", { count: totalPackets.toLocaleString() })}</small>
            </span>
          </button>
          {filteredConnections.map((connection) => (
            <button
              type="button"
              className={`flow-card ${connectionId === connection.id ? "selected" : ""}`}
              key={connection.id}
              onClick={() => onConnectionChange(connection.id)}
              aria-pressed={connectionId === connection.id}
            >
              <span className="transport-badge">{connection.state}</span>
              <span>
                <strong>
                  {connection.target.host}:{connection.target.port}
                </strong>
                <small>
                  {connection.packet_count.toLocaleString()} · {formatBytes(connection.byte_count)}
                </small>
              </span>
            </button>
          ))}
          {filteredConnections.length === 0 && connections.length > 0 && (
            <p className="flow-empty">{t("traffic.connections.none", { query: connectionSearch })}</p>
          )}
        </div>
      </aside>
      <main className="traffic-pane">
        {project ? (
          <PacketHistory
            key={project?.path}
            project={project}
            connectionId={connectionId}
            filter={filter}
            onFilterChange={onFilterChange}
            selectedId={selectedPacketId}
            appendSignal={appendSignal}
            onSelect={onSelectPacket}
            connections={connections}
            onConnectionChange={onConnectionChange}
            actions={actions}
            onError={onError}
            onNotice={onNotice}
            reloadSignal={reloadSignal}
          />
        ) : (
          <EmptyState title={t("traffic.no-project.title")} detail={t("traffic.no-project.detail")} />
        )}
      </main>
      {dataMenu && (
        <ContextMenu
          x={dataMenu.x}
          y={dataMenu.y}
          label={t("traffic.data")}
          items={dataItems}
          onClose={() => setDataMenu(null)}
        />
      )}
      {dialog === "delete" && (
        <DeleteHistoryDialog
          query={historyQuery}
          scope={scope}
          narrowed={filterSummary !== null || connectionId !== null}
          onDeleted={(summary) => {
            annotationStore.reset();
            onNotice(
              t("traffic.delete.done", {
                packets: summary.packets.toLocaleString(),
                connections: summary.connections.toLocaleString(),
              }),
            );
            changed();
          }}
          onClose={() => setDialog(null)}
          onError={onError}
        />
      )}
      {dialog === "import" && (
        <ImportCaptureDialog onImported={changed} onClose={() => setDialog(null)} onError={onError} />
      )}
      <aside className="capture-inspector" aria-label={t("traffic.inspector")}>
        <PacketInspector
          packet={selectedPacket}
          onRepeater={onOpenRepeater}
          onCompare={compareInspected}
          onError={onError}
          onNotice={onNotice}
        />
      </aside>
    </Split>
  );
}

/**
 * What passive capture has seen. Dropped frames are the ones the backend
 * could not keep up with, so a non-zero count is called out rather than buried.
 */
function CaptureCounters() {
  const [stats, setStats] = useState<CaptureStats | null>(null);

  useEffect(() => {
    if (!desktop.isAvailable()) return undefined;
    let live = true;
    const poll = () => {
      if (document.hidden) return;
      void desktop
        .captureStats()
        .then((next) => live && setStats(next))
        .catch(() => undefined);
    };
    poll();
    const timer = window.setInterval(poll, STATS_POLL_MS);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, []);

  if (!stats) return null;
  const counters: Array<{ key: string; label: string; value: string; alert?: boolean }> = [
    {
      key: "seen",
      label: t("capture.stats.seen"),
      value: `${stats.frames_seen.toLocaleString()} · ${formatBytes(stats.bytes_seen)}`,
    },
    {
      key: "kept",
      label: t("capture.stats.kept"),
      value: `${stats.frames_emitted.toLocaleString()} · ${formatBytes(stats.bytes_emitted ?? 0)}`,
    },
    {
      key: "dropped",
      label: t("capture.stats.dropped"),
      value: stats.frames_dropped.toLocaleString(),
      alert: stats.frames_dropped > 0,
    },
    { key: "held", label: t("capture.stats.held"), value: (stats.frames_held ?? 0).toLocaleString() },
    {
      key: "retransmissions",
      label: t("capture.stats.retransmissions"),
      value: (stats.retransmissions ?? 0).toLocaleString(),
    },
    { key: "reordered", label: t("capture.stats.reordered"), value: (stats.reordered ?? 0).toLocaleString() },
    {
      key: "gaps",
      label: t("capture.stats.gaps"),
      value: (stats.gaps ?? 0).toLocaleString(),
      alert: (stats.gaps ?? 0) > 0,
    },
    {
      key: "errors",
      label: t("capture.stats.errors"),
      value: (stats.errors ?? 0).toLocaleString(),
      alert: (stats.errors ?? 0) > 0,
    },
  ];
  return (
    <div className="capture-counters-block">
      {stats.running === false && (
        <p className="capture-stopped" role="status">
          {t("capture.stats.stopped")}
        </p>
      )}
      <dl className="capture-counters" aria-label={t("capture.stats")}>
        {counters.map((counter) => (
          <div key={counter.key} className={counter.alert ? "dropped" : ""}>
            <dt>{counter.label}</dt>
            <dd>{counter.value}</dd>
          </div>
        ))}
      </dl>
      {stats.last_error && (
        <p className="capture-last-error" title={stats.last_error}>
          {t("capture.stats.last-error", { error: stats.last_error })}
        </p>
      )}
    </div>
  );
}
