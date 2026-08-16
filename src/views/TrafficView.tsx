import { Loader2, Radio, ShieldAlert, ShieldCheck, ShieldOff, WifiOff } from "lucide-react";
import { useEffect, useState } from "react";

import { EmptyState } from "../components/EmptyState";
import { PacketHistory } from "../components/PacketHistory";
import { PacketInspector } from "../components/PacketInspector";
import type {
  AppCapabilities,
  ConnectionSnapshot,
  DecryptModeStatus,
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
  decryptMode: DecryptModeStatus | null;
  captureStatus: CaptureStatus;
  appendSignal: number;
  onSelectPacket: (id: number) => void;
  onDecryptModeChange: (enabled: boolean) => Promise<DecryptModeStatus>;
  onOpenRepeater: () => void;
  onError: (error: string) => void;
}) {
  const [connectionId, setConnectionId] = useState<string | null>(null);
  const [changingDecryptMode, setChangingDecryptMode] = useState(false);
  const capture = capabilities?.side_capture;

  useEffect(() => {
    if (connectionId && !connections.some((connection) => connection.id === connectionId)) {
      setConnectionId(null);
    }
  }, [connectionId, connections]);

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

  const statusCopy = captureStatus === "running"
    ? "Capturing TCP and UDP traffic owned by Minecraft clients"
    : captureStatus === "starting"
      ? "Starting system capture…"
      : capture?.reason ?? "System capture is unavailable";
  const decryptEnabled = decryptMode?.enabled ?? false;
  const totalPackets = connections.reduce((sum, connection) => sum + connection.packet_count, 0);

  return (
    <div className="capture-layout">
      <aside className="flow-pane" aria-label="Capture and decrypt controls">
        <div className="pane-header">
          <div><span className="eyebrow">Connection mode</span><h2>Capture</h2></div>
        </div>
        <section className={`decrypt-control ${decryptEnabled ? "enabled" : ""}`} aria-label="Decrypt connection mode">
          <div className="decrypt-control-heading">
            <span className="decrypt-icon" aria-hidden="true">{decryptEnabled ? <ShieldCheck size={16} /> : <ShieldOff size={16} />}</span>
            <span><strong>Decrypt connections</strong><small>{decryptEnabled ? "Active for configured Minecraft clients" : "Passive capture is the safe default"}</small></span>
          </div>
          <button className={`decrypt-switch ${decryptEnabled ? "on" : ""}`} role="switch" aria-checked={decryptEnabled} disabled={changingDecryptMode} onClick={() => void toggleDecryptMode()}>
            <span>{decryptEnabled ? "On" : "Off"}</span>
          </button>
          <p>MineBurp creates a one-use private route inside the configured Java client. No public listener or target setup is exposed.</p>
          {decryptEnabled && <p className="decrypt-auth-note">Online mode needs launcher assistance or a valid signed-in Microsoft/Minecraft session to authorize the upstream hash.</p>}
        </section>
        <div className={`capture-status ${captureStatus}`} role="status" aria-live="polite">
          {captureStatus === "running" ? <Radio size={15} /> : captureStatus === "starting" ? <Loader2 className="spin" size={15} /> : captureStatus === "unavailable" ? <WifiOff size={15} /> : <ShieldAlert size={15} />}
          <span><strong>{captureStatus}</strong><small>{statusCopy}</small></span>
        </div>
        <div className="flow-list" aria-label="Observed connections">
          <button className={`flow-card ${connectionId === null ? "selected" : ""}`} onClick={() => setConnectionId(null)} aria-pressed={connectionId === null}>
            <span><strong>All Minecraft traffic</strong><small>{totalPackets.toLocaleString()} packets recorded</small></span>
          </button>
          {connections.map((connection) => (
            <button
              className={`flow-card ${connectionId === connection.id ? "selected" : ""}`}
              key={connection.id}
              onClick={() => setConnectionId(connection.id)}
              aria-pressed={connectionId === connection.id}
            >
              <span className="transport-badge">{connection.state}</span>
              <span>
                <strong>{connection.target.host}:{connection.target.port}</strong>
                <small>{connection.packet_count.toLocaleString()} packets · {formatBytes(connection.byte_count)}</small>
              </span>
            </button>
          ))}
        </div>
      </aside>
      <main className="traffic-pane">
        <div className="pane-header traffic-header">
          <div>
            <span className="eyebrow">{project?.temporary ? "Temporary project" : "Project-backed"}</span>
            <h2>Packet history</h2>
          </div>
        </div>
        <div className="traffic-content">
          {project ? (
            <PacketHistory
              project={project}
              connectionId={connectionId}
              selectedId={selectedPacketId}
              appendSignal={appendSignal}
              onSelect={onSelectPacket}
              onError={onError}
            />
          ) : (
            <EmptyState
              title="No project is open"
              detail="MineBurp normally records into a temporary project on startup. Open or create one to resume recording."
            />
          )}
        </div>
      </main>
      <aside className="capture-inspector" aria-label="Selected packet details">
        <PacketInspector packet={selectedPacket} onRepeater={onOpenRepeater} onError={onError} />
      </aside>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KiB`;
  return `${(bytes / 1_048_576).toFixed(1)} MiB`;
}
