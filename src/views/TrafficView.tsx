import { Loader2, Radio, ShieldAlert, ShieldCheck, ShieldOff, WifiOff } from "lucide-react";
import { useEffect, useState } from "react";

import { EmptyState } from "../components/EmptyState";
import { PacketHistory } from "../components/PacketHistory";
import { PacketInspector } from "../components/PacketInspector";
import { Split } from "../components/Split";
import type {
  AppCapabilities,
  ConnectionSnapshot,
  DecryptModeStatus,
  PacketFilter,
  PacketView,
  ProjectInfo,
} from "../domain/types";

type CaptureStatus = "starting" | "running" | "unavailable" | "failed";

export function TrafficView({
  capabilities,
  project,
  connections,
  selectedPacket,
  selectedPacketId,
  filter,
  onFilterChange,
  connectionId,
  onConnectionChange,
  decryptMode,
  captureStatus,
  appendSignal,
  onSelectPacket,
  onDecryptModeChange,
  onOpenRepeater,
  onError,
}: {
  capabilities: AppCapabilities | null;
  project: ProjectInfo | null;
  connections: ConnectionSnapshot[];
  selectedPacket: PacketView | null;
  selectedPacketId: number | null;
  /** Held by the workbench so it survives a trip to another view. */
  filter: PacketFilter;
  onFilterChange: (filter: PacketFilter) => void;
  connectionId: string | null;
  onConnectionChange: (connectionId: string | null) => void;
  decryptMode: DecryptModeStatus | null;
  captureStatus: CaptureStatus;
  appendSignal: number;
  onSelectPacket: (id: number) => void;
  onDecryptModeChange: (enabled: boolean) => Promise<DecryptModeStatus>;
  onOpenRepeater: () => void;
  onError: (error: string) => void;
}) {
  const [changingDecryptMode, setChangingDecryptMode] = useState(false);
  const capture = capabilities?.side_capture;

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
  const statusDetail = captureStatus === "running" || captureStatus === "starting" ? null : capture?.reason ?? null;

  return (
    <Split orientation="columns" storageKey="traffic" initial={[0.19, 0.51, 0.3]} minimum={200} className="capture-layout">
      <aside className="flow-pane" aria-label="Capture and decrypt controls">
        <div className={`decrypt-control ${decryptEnabled ? "enabled" : ""}`}>
          <span className="decrypt-icon" aria-hidden="true">{decryptEnabled ? <ShieldCheck size={16} /> : <ShieldOff size={16} />}</span>
          <strong>Decrypt connections</strong>
          <button className={`decrypt-switch ${decryptEnabled ? "on" : ""}`} role="switch" aria-checked={decryptEnabled} disabled={changingDecryptMode} onClick={() => void toggleDecryptMode()}>
            {decryptEnabled ? "On" : "Off"}
          </button>
        </div>
        <div className={`capture-status ${captureStatus}`} role="status" aria-live="polite">
          {captureStatus === "running" ? <Radio size={15} /> : captureStatus === "starting" ? <Loader2 className="spin" size={15} /> : captureStatus === "unavailable" ? <WifiOff size={15} /> : <ShieldAlert size={15} />}
          <span><strong>{captureStatus}</strong>{statusDetail && <small>{statusDetail}</small>}</span>
        </div>
        <div className="flow-list" aria-label="Observed connections">
          <button className={`flow-card ${connectionId === null ? "selected" : ""}`} onClick={() => onConnectionChange(null)} aria-pressed={connectionId === null}>
            <span><strong>All traffic</strong><small>{totalPackets.toLocaleString()} packets</small></span>
          </button>
          {connections.map((connection) => (
            <button
              className={`flow-card ${connectionId === connection.id ? "selected" : ""}`}
              key={connection.id}
              onClick={() => onConnectionChange(connection.id)}
              aria-pressed={connectionId === connection.id}
            >
              <span className="transport-badge">{connection.state}</span>
              <span>
                <strong>{connection.target.host}:{connection.target.port}</strong>
                <small>{connection.packet_count.toLocaleString()} · {formatBytes(connection.byte_count)}</small>
              </span>
            </button>
          ))}
        </div>
      </aside>
      <main className="traffic-pane">
        {project ? (
          <PacketHistory
            project={project}
            connectionId={connectionId}
            filter={filter}
            onFilterChange={onFilterChange}
            selectedId={selectedPacketId}
            appendSignal={appendSignal}
            onSelect={onSelectPacket}
            onError={onError}
          />
        ) : (
          <EmptyState title="No project is open" detail="Open or create one to resume recording." />
        )}
      </main>
      <aside className="capture-inspector" aria-label="Selected packet details">
        <PacketInspector packet={selectedPacket} onRepeater={onOpenRepeater} onError={onError} />
      </aside>
    </Split>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KiB`;
  return `${(bytes / 1_048_576).toFixed(1)} MiB`;
}
