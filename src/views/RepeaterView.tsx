import { Save, Send } from "lucide-react";
import { useEffect, useState } from "react";

import type { ConnectionSnapshot, Direction, PacketView } from "../domain/types";
import { base64ToBytes, desktop, formatHexInput, parseHex } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";
import { EmptyState } from "../components/EmptyState";

export function RepeaterView({
  sessions,
  seed,
  onError,
}: {
  sessions: ConnectionSnapshot[];
  seed: PacketView | null;
  onError: (error: string) => void;
}) {
  const active = sessions.filter((session) => session.status === "active" && session.state !== "opaque");
  const [connectionId, setConnectionId] = useState("");
  const [direction, setDirection] = useState<Direction>("client_to_server");
  const [hex, setHex] = useState("");
  const [tabId, setTabId] = useState<string>(() => crypto.randomUUID());
  const [tabName, setTabName] = useState("Repeater 1");
  const [attempts, setAttempts] = useState<Array<{ at: Date; bytes: number; result: string }>>([]);
  const [seedTruncated, setSeedTruncated] = useState(false);

  useEffect(() => {
    if (!seed) return;
    setConnectionId(seed.summary.connection_id);
    setDirection(seed.summary.direction);
    setHex(formatHexInput(base64ToBytes(seed.bytes_base64)));
    // Only the loaded window is seeded, so an oversized packet cannot silently
    // be replayed as a truncated frame without the operator knowing.
    setSeedTruncated(seed.total_bytes > seed.bytes_offset + base64ToBytes(seed.bytes_base64).length);
  }, [seed]);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .repeaterTabs()
      .then((tabs) => {
        const tab = tabs[0];
        if (!tab) return;
        setTabId(tab.id);
        setTabName(tab.name);
        setConnectionId(tab.connection_id);
        setDirection(tab.direction);
        setHex(formatHexInput(tab.logical_bytes));
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!connectionId && active[0]) setConnectionId(active[0].id);
  }, [active, connectionId]);

  async function send() {
    try {
      const bytes = parseHex(hex);
      await desktop.repeaterSend(connectionId, direction, bytes);
      setAttempts((items) => [{ at: new Date(), bytes: bytes.length, result: "sent" }, ...items]);
    } catch (reason) {
      const error = message(reason);
      setAttempts((items) => [{ at: new Date(), bytes: 0, result: error }, ...items]);
      onError(error);
    }
  }

  async function save() {
    try {
      const bytes = parseHex(hex);
      const session = sessions.find((item) => item.id === connectionId);
      await desktop.repeaterTabSave({
        id: tabId,
        name: tabName,
        connection_id: connectionId,
        direction,
        state: session?.state ?? "play",
        logical_bytes: Array.from(bytes),
        decoded: null,
      });
    } catch (reason) {
      onError(message(reason));
    }
  }

  if (!active.length) {
    return <EmptyState title="Repeater needs an active interception session" detail="Automatic system capture is observation-only. Repeater becomes available when an internal routed session can safely inject framed traffic." />;
  }

  return (
    <div className="repeater-layout">
      <section className="repeater-editor">
        <div className="pane-header"><div><span className="eyebrow">Live injection</span><h2>Repeater</h2></div><div className="button-row"><input className="tab-name-input" aria-label="Repeater tab name" value={tabName} onChange={(event) => setTabName(event.target.value)} /><button className="button" onClick={save}><Save size={14} /> Save tab</button></div></div>
        <div className="repeater-toolbar">
          <label>Connection<select value={connectionId} onChange={(event) => setConnectionId(event.target.value)}>{active.map((session) => <option value={session.id} key={session.id}>{session.target.host}:{session.target.port} · {session.state}</option>)}</select></label>
          <label>Direction<select value={direction} onChange={(event) => setDirection(event.target.value as Direction)}><option value="client_to_server">Client → server</option><option value="server_to_client">Server → client</option></select></label>
          <button className="button accent" onClick={send} disabled={!connectionId}><Send size={14} /> Send</button>
        </div>
        <label className="editor-label" htmlFor="repeater-hex">Logical frame bytes</label>
        <textarea id="repeater-hex" className="hex-editor" spellCheck={false} value={hex} onChange={(event) => setHex(event.target.value)} placeholder="00 0f 6d 69 6e 65 63 72 61 66 74 3a 62 72 61 6e 64 …" />
        <p className="muted">Include the packet ID VarInt as the first byte(s). Length and compression framing are added automatically.</p>
        {seedTruncated && <p className="decode-note">Only the first loaded window of this packet was seeded — sending it as-is would replay a truncated frame.</p>}
      </section>
      <aside className="attempt-pane">
        <div className="pane-header"><div><span className="eyebrow">This tab</span><h2>Attempts</h2></div></div>
        {attempts.length ? attempts.map((attempt, index) => <div className="attempt" key={`${attempt.at.toISOString()}-${index}`}><span>{attempt.at.toLocaleTimeString()}</span><strong>{attempt.result}</strong><small>{attempt.bytes} bytes</small></div>) : <EmptyState title="No attempts" detail="Sent frames will appear here." />}
      </aside>
    </div>
  );
}
