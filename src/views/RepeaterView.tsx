import { Save, Send } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import type {
  ConnectionSnapshot,
  Direction,
  FieldSpan,
  PacketLayout,
  PacketView,
  ProtocolState,
} from "../domain/types";
import { base64ToBytes, desktop, formatHexInput, parseHex } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";
import { EmptyState } from "../components/EmptyState";
import { FieldEditor } from "../components/FieldEditor";
import { Split } from "../components/Split";

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play"];

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
  const [state, setState] = useState<ProtocolState>("play");
  const [hex, setHex] = useState("");
  const [layout, setLayout] = useState<PacketLayout | null>(null);
  const [decoding, setDecoding] = useState(false);
  const [tabId, setTabId] = useState<string>(() => crypto.randomUUID());
  const [tabName, setTabName] = useState("Repeater 1");
  const [attempts, setAttempts] = useState<Array<{ at: Date; bytes: number; result: string }>>([]);
  /** A seed larger than its loaded window would otherwise be replayed short. */
  const [seedTruncated, setSeedTruncated] = useState(false);
  const decode = useRef(0);

  const session = sessions.find((item) => item.id === connectionId);
  const protocolVersion = session?.protocol_version ?? null;

  useEffect(() => {
    if (!seed) return;
    setConnectionId(seed.summary.connection_id);
    setDirection(seed.summary.direction);
    setState(seed.summary.state === "opaque" || seed.summary.state === "closed" ? "play" : seed.summary.state);
    const loaded = base64ToBytes(seed.bytes_base64);
    setHex(formatHexInput(loaded));
    setSeedTruncated(seed.total_bytes > seed.bytes_offset + loaded.length);
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
        setState(tab.state);
        setHex(formatHexInput(tab.logical_bytes));
        setSeedTruncated(false);
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!connectionId && active[0]) setConnectionId(active[0].id);
  }, [active, connectionId]);

  // The decode follows the bytes: typing hex, editing a field, or switching
  // state all end up here, so the two editors can never disagree.
  useEffect(() => {
    if (!desktop.isAvailable()) return undefined;
    const requestId = ++decode.current;
    const timer = window.setTimeout(() => {
      void (async () => {
        let bytes: Uint8Array;
        try {
          bytes = parseHex(hex);
        } catch {
          if (requestId === decode.current) setLayout(null);
          return;
        }
        if (bytes.length === 0) {
          if (requestId === decode.current) setLayout(null);
          return;
        }
        setDecoding(true);
        try {
          const next = await desktop.packetLayout(bytes, state, direction, protocolVersion);
          if (requestId === decode.current) setLayout(next);
        } catch {
          if (requestId === decode.current) setLayout(null);
        } finally {
          if (requestId === decode.current) setDecoding(false);
        }
      })();
    }, 180);
    return () => window.clearTimeout(timer);
  }, [direction, hex, protocolVersion, state]);

  const commitField = useCallback(
    async (field: FieldSpan, value: string | boolean) => {
      try {
        const edited = await desktop.fieldEdit(parseHex(hex), field, value);
        setHex(formatHexInput(edited));
      } catch (reason) {
        onError(message(reason));
      }
    },
    [hex, onError],
  );

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
      await desktop.repeaterTabSave({
        id: tabId,
        name: tabName,
        connection_id: connectionId,
        direction,
        state,
        logical_bytes: Array.from(bytes),
        decoded: null,
      });
    } catch (reason) {
      onError(message(reason));
    }
  }

  if (!active.length) {
    return <EmptyState title="No active interception session" detail="Repeater becomes available when a routed session can inject framed traffic." />;
  }

  return (
    <Split orientation="columns" storageKey="repeater" initial={[0.74, 0.26]} minimum={220} className="repeater-layout">
      <section className="repeater-editor">
        <div className="repeater-toolbar">
          <label>Connection<select value={connectionId} onChange={(event) => setConnectionId(event.target.value)}>{active.map((item) => <option value={item.id} key={item.id}>{item.target.host}:{item.target.port} · {item.state}</option>)}</select></label>
          <label>Direction<select value={direction} onChange={(event) => setDirection(event.target.value as Direction)}><option value="client_to_server">Client → server</option><option value="server_to_client">Server → client</option></select></label>
          <label>State<select value={state} onChange={(event) => setState(event.target.value as ProtocolState)}>{STATES.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <input className="tab-name-input" aria-label="Repeater tab name" value={tabName} onChange={(event) => setTabName(event.target.value)} />
          <button className="button" onClick={save}><Save size={14} /> Save</button>
          <button className="button accent" onClick={send} disabled={!connectionId}><Send size={14} /> Send</button>
        </div>
        <Split orientation="rows" storageKey="repeater-editors" initial={[0.55, 0.45]} minimum={120} className="repeater-panes">
          <section className="editor-section">
            <h3>{layout?.name ?? "Decoded"}{layout && !layout.complete ? " · partial" : ""}</h3>
            <div className="editor-scroll">
              <FieldEditor layout={layout} onCommit={(field, value) => void commitField(field, value)} busy={decoding} />
            </div>
          </section>
          <section className="editor-section">
            <h3>Bytes{seedTruncated ? " · truncated seed" : ""}</h3>
            <textarea
              id="repeater-hex"
              className="hex-editor"
              spellCheck={false}
              value={hex}
              onChange={(event) => { setHex(event.target.value); setSeedTruncated(false); }}
              placeholder="00 0f 6d 69 6e 65 63 72 61 66 74 3a 62 72 61 6e 64"
            />
          </section>
        </Split>
      </section>
      <aside className="attempt-pane">
        {attempts.length ? attempts.map((attempt, index) => <div className="attempt" key={`${attempt.at.toISOString()}-${index}`}><span>{attempt.at.toLocaleTimeString()}</span><strong>{attempt.result}</strong><small>{attempt.bytes} B</small></div>) : <EmptyState title="No attempts" detail="Sent frames appear here." />}
      </aside>
    </Split>
  );
}
