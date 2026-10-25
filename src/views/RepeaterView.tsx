import { Loader2, Plus, Save, Send, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { EmptyState } from "../components/EmptyState";
import { FieldEditor } from "../components/FieldEditor";
import { Split } from "../components/Split";
import type {
  ConnectionSnapshot,
  Direction,
  FieldSpan,
  PacketLayout,
  PacketView,
  ProtocolState,
  RepeaterTab,
} from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { base64ToBytes, desktop, formatHexInput, parseHex, readPayload, tryParseHex } from "../lib/desktop";
import { newId } from "../lib/ids";

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play"];

interface Attempt {
  at: number;
  bytes: number;
  ok: boolean;
  result: string;
}

/** One Repeater tab as the editor holds it, including what has not been saved. */
export interface RepeaterTabState {
  id: string;
  name: string;
  connectionId: string;
  direction: Direction;
  state: ProtocolState;
  protocolVersion: number | null;
  hex: string;
  attempts: Attempt[];
  /** The hex holds only the leading window of a larger packet. */
  truncated: boolean;
  loadingFull: boolean;
  sourcePacketId: number | null;
  /** Persisted at least once, so closing it also deletes the saved copy. */
  saved: boolean;
  dirty: boolean;
}

/** A request from elsewhere in the workbench to open a packet in a new tab. */
export interface RepeaterRequest {
  packet: PacketView;
  nonce: number;
}

function replayableState(state: ProtocolState): ProtocolState {
  return state === "opaque" || state === "closed" ? "play" : state;
}

export function tabFromPacket(packet: PacketView, index: number): RepeaterTabState {
  const loaded = base64ToBytes(packet.bytes_base64);
  return {
    id: newId(),
    name: packet.summary.name ? `${packet.summary.name}` : t("repeater.tab.default", { index }),
    connectionId: packet.summary.connection_id,
    direction: packet.summary.direction,
    state: replayableState(packet.summary.state),
    protocolVersion: packet.summary.protocol_version,
    hex: formatHexInput(loaded),
    attempts: [],
    truncated: packet.bytes_offset > 0 || packet.total_bytes > packet.bytes_offset + loaded.length,
    loadingFull: false,
    sourcePacketId: packet.summary.id,
    saved: false,
    dirty: true,
  };
}

function tabFromSaved(tab: RepeaterTab): RepeaterTabState {
  return {
    id: tab.id,
    name: tab.name,
    connectionId: tab.connection_id,
    direction: tab.direction,
    state: replayableState(tab.state),
    protocolVersion: null,
    hex: formatHexInput(tab.logical_bytes),
    attempts: [],
    truncated: false,
    loadingFull: false,
    sourcePacketId: null,
    saved: true,
    dirty: false,
  };
}

function blankTab(index: number, connectionId: string): RepeaterTabState {
  return {
    id: newId(),
    name: t("repeater.tab.default", { index }),
    connectionId,
    direction: "client_to_server",
    state: "play",
    protocolVersion: null,
    hex: "",
    attempts: [],
    truncated: false,
    loadingFull: false,
    sourcePacketId: null,
    saved: false,
    dirty: false,
  };
}

/**
 * Hand-built and replayed frames, one per tab.
 *
 * The view stays mounted while other views are on screen, so unsaved edits
 * survive a look at the traffic. A packet arrives only through an explicit
 * "Send to Repeater", and always in a tab of its own: selecting a row no
 * longer rewrites whatever the operator was composing.
 */
export function RepeaterView({
  sessions,
  request,
  onRequestHandled,
  visible = true,
  onError,
}: {
  sessions: ConnectionSnapshot[];
  request: RepeaterRequest | null;
  onRequestHandled: (nonce: number) => void;
  /** Whether the view is on screen; keyboard shortcuts only apply then. */
  visible?: boolean;
  onError: (error: string) => void;
}) {
  const live = sessions.filter((session) => session.status === "active" && session.state !== "opaque");
  const [tabs, setTabs] = useState<RepeaterTabState[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [layout, setLayout] = useState<{ layout: PacketLayout; hex: string } | null>(null);
  const [decoding, setDecoding] = useState(false);
  const decode = useRef(0);
  const counter = useRef(1);
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;

  const active = tabs.find((tab) => tab.id === activeId) ?? tabs[0] ?? null;
  const session = sessions.find((item) => item.id === active?.connectionId);
  const protocolVersion = active?.protocolVersion ?? session?.protocol_version ?? null;
  const parsed = active ? tryParseHex(active.hex) : null;

  const patchTab = useCallback((id: string, patch: Partial<RepeaterTabState>) => {
    setTabs((current) => current.map((tab) => (tab.id === id ? { ...tab, ...patch } : tab)));
  }, []);

  const loadFull = useCallback(
    async (id: string, packetId: number) => {
      patchTab(id, { loadingFull: true });
      try {
        const { bytes, complete } = await readPayload(packetId);
        patchTab(id, { hex: formatHexInput(bytes), truncated: !complete, loadingFull: false });
      } catch (reason) {
        patchTab(id, { loadingFull: false });
        onError(message(reason));
      }
    },
    [onError, patchTab],
  );

  // Saved tabs join whatever is already open — including a tab a request
  // opened before they finished loading — instead of replacing it.
  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .repeaterTabs()
      .then((saved) => {
        setTabs((current) => {
          const open = new Set(current.map((tab) => tab.id));
          return [...current, ...saved.filter((tab) => !open.has(tab.id)).map(tabFromSaved)];
        });
        counter.current += saved.length;
      })
      .catch((reason) => onError(message(reason)));
  }, [onError]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: each request is handled once, by nonce.
  useEffect(() => {
    if (!request) return;
    const tab = tabFromPacket(request.packet, counter.current++);
    setTabs((current) => [...current, tab]);
    setActiveId(tab.id);
    onRequestHandled(request.nonce);
    if (tab.truncated) void loadFull(tab.id, request.packet.summary.id);
  }, [request?.nonce]);

  // A tab without a connection picks the first live one.
  useEffect(() => {
    if (active && !active.connectionId && live[0]) patchTab(active.id, { connectionId: live[0].id });
  }, [active, live, patchTab]);

  // The decode follows the bytes of the active tab: typing hex, editing a
  // field, or switching state all end up here, so the editors cannot disagree.
  const activeHex = active?.hex ?? "";
  const activeState = active?.state ?? "play";
  const activeDirection = active?.direction ?? "client_to_server";
  useEffect(() => {
    const requestId = ++decode.current;
    if (!desktop.isAvailable()) return undefined;
    const timer = window.setTimeout(() => {
      void (async () => {
        const result = tryParseHex(activeHex);
        if (!result.bytes || result.bytes.length === 0) {
          if (requestId === decode.current) setLayout(null);
          return;
        }
        setDecoding(true);
        try {
          const next = await desktop.packetLayout(
            result.bytes,
            activeState,
            activeDirection,
            protocolVersion,
          );
          if (requestId === decode.current) setLayout({ layout: next, hex: activeHex });
        } catch {
          if (requestId === decode.current) setLayout(null);
        } finally {
          if (requestId === decode.current) setDecoding(false);
        }
      })();
    }, 180);
    return () => window.clearTimeout(timer);
  }, [activeDirection, activeHex, activeState, protocolVersion]);

  // A layout decoded from older bytes would splice an edit at the wrong offset.
  const currentLayout = layout && layout.hex === activeHex ? layout.layout : null;

  const commitField = useCallback(
    async (field: FieldSpan, value: string | boolean) => {
      const tab = tabsRef.current.find((item) => item.id === active?.id);
      if (!tab) return;
      if (!layout || layout.hex !== tab.hex) {
        onError(t("repeater.decode-pending"));
        return;
      }
      try {
        const edited = await desktop.fieldEdit(parseHex(tab.hex), field, value);
        patchTab(tab.id, { hex: formatHexInput(edited), dirty: true });
      } catch (reason) {
        onError(message(reason));
      }
    },
    [active?.id, layout, onError, patchTab],
  );

  const send = useCallback(async () => {
    const tab = tabsRef.current.find((item) => item.id === active?.id);
    if (!tab) return;
    const record = (attempt: Attempt) =>
      setTabs((current) =>
        current.map((item) =>
          item.id === tab.id ? { ...item, attempts: [attempt, ...item.attempts].slice(0, 200) } : item,
        ),
      );
    try {
      const bytes = parseHex(tab.hex);
      await desktop.repeaterSend(tab.connectionId, tab.direction, bytes);
      record({ at: Date.now(), bytes: bytes.length, ok: true, result: t("repeater.sent") });
    } catch (reason) {
      const error = message(reason);
      record({ at: Date.now(), bytes: 0, ok: false, result: error });
      onError(error);
    }
  }, [active?.id, onError]);

  const save = useCallback(async () => {
    const tab = tabsRef.current.find((item) => item.id === active?.id);
    if (!tab) return;
    try {
      const bytes = parseHex(tab.hex);
      await desktop.repeaterTabSave({
        id: tab.id,
        name: tab.name,
        connection_id: tab.connectionId,
        direction: tab.direction,
        state: tab.state,
        logical_bytes: Array.from(bytes),
        decoded: null,
      });
      patchTab(tab.id, { saved: true, dirty: false });
    } catch (reason) {
      onError(message(reason));
    }
  }, [active?.id, onError, patchTab]);

  async function closeTab(tab: RepeaterTabState) {
    setTabs((current) => current.filter((item) => item.id !== tab.id));
    if (active?.id === tab.id) {
      const index = tabs.findIndex((item) => item.id === tab.id);
      setActiveId(tabs[index + 1]?.id ?? tabs[index - 1]?.id ?? null);
    }
    if (!tab.saved) return;
    try {
      await desktop.repeaterTabDelete(tab.id);
    } catch (reason) {
      onError(message(reason));
    }
  }

  function addTab() {
    const tab = blankTab(counter.current++, active?.connectionId || live[0]?.id || "");
    setTabs((current) => [...current, tab]);
    setActiveId(tab.id);
  }

  // Ctrl/Cmd+Enter sends and Ctrl/Cmd+S saves while the Repeater is on screen.
  useEffect(() => {
    if (!visible) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key === "Enter") {
        event.preventDefault();
        void send();
      } else if (event.key.toLowerCase() === "s") {
        event.preventDefault();
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save, send, visible]);

  const sendable = active !== null && live.some((item) => item.id === active.connectionId) && parsed?.bytes;

  return (
    <section className="repeater-view">
      <div className="repeater-tabs" role="tablist" aria-label={t("repeater.tabs")}>
        {tabs.map((tab) => (
          <div key={tab.id} className={`repeater-tab ${tab.id === active?.id ? "active" : ""}`}>
            <button
              type="button"
              role="tab"
              aria-selected={tab.id === active?.id}
              onClick={() => setActiveId(tab.id)}
              title={tab.name}
            >
              {tab.name}
              {tab.dirty && (
                <span className="repeater-tab-dirty" title={t("repeater.unsaved")}>
                  •<span className="visually-hidden"> {t("repeater.unsaved")}</span>
                </span>
              )}
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label={t("repeater.tab.close", { name: tab.name })}
              onClick={() => void closeTab(tab)}
            >
              <X size={12} aria-hidden="true" />
            </button>
          </div>
        ))}
        <button type="button" className="icon-button" aria-label={t("repeater.tab.new")} onClick={addTab}>
          <Plus size={14} aria-hidden="true" />
        </button>
      </div>
      {!live.length && <p className="intercept-notice">{t("repeater.no-session.detail")}</p>}
      {active ? (
        <Split
          orientation="columns"
          storageKey="repeater"
          initial={[0.74, 0.26]}
          minimum={220}
          className="repeater-layout"
        >
          <section className="repeater-editor">
            <div className="repeater-toolbar">
              <label>
                {t("repeater.connection")}
                <select
                  value={active.connectionId}
                  onChange={(event) =>
                    patchTab(active.id, { connectionId: event.target.value, protocolVersion: null })
                  }
                >
                  {!live.some((item) => item.id === active.connectionId) && (
                    <option value={active.connectionId}>{t("repeater.connection.inactive")}</option>
                  )}
                  {live.map((item) => (
                    <option value={item.id} key={item.id}>
                      {item.target.host}:{item.target.port} · {item.state}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {t("repeater.direction")}
                <select
                  value={active.direction}
                  onChange={(event) =>
                    patchTab(active.id, { direction: event.target.value as Direction, dirty: true })
                  }
                >
                  <option value="client_to_server">{t("repeater.direction.c2s")}</option>
                  <option value="server_to_client">{t("repeater.direction.s2c")}</option>
                </select>
              </label>
              <label>
                {t("repeater.state")}
                <select
                  value={active.state}
                  onChange={(event) =>
                    patchTab(active.id, { state: event.target.value as ProtocolState, dirty: true })
                  }
                >
                  {STATES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <input
                className="tab-name-input"
                aria-label={t("repeater.tab-name")}
                value={active.name}
                onChange={(event) => patchTab(active.id, { name: event.target.value, dirty: true })}
              />
              <button
                type="button"
                className="button"
                onClick={() => void save()}
                title={t("repeater.save.shortcut")}
              >
                <Save size={14} /> {t("repeater.save")}
              </button>
              <button
                type="button"
                className="button accent"
                onClick={() => void send()}
                disabled={!sendable}
                title={t("repeater.send.shortcut")}
              >
                <Send size={14} /> {t("repeater.send")}
              </button>
            </div>
            <Split
              orientation="rows"
              storageKey="repeater-editors"
              initial={[0.55, 0.45]}
              minimum={120}
              className="repeater-panes"
            >
              <section className="editor-section">
                <h3>
                  {currentLayout?.name ?? t("repeater.decoded")}
                  {currentLayout && !currentLayout.complete ? t("repeater.partial") : ""}
                </h3>
                <div className="editor-scroll">
                  <FieldEditor
                    layout={currentLayout}
                    onCommit={(field, value) => void commitField(field, value)}
                    busy={decoding || currentLayout === null}
                  />
                </div>
              </section>
              <section className="editor-section">
                <div className="section-header">
                  <h3>
                    {t("repeater.bytes")}
                    {active.truncated ? t("repeater.truncated-seed") : ""}
                  </h3>
                  {active.truncated && active.sourcePacketId !== null && (
                    <button
                      type="button"
                      className="link-button"
                      disabled={active.loadingFull}
                      onClick={() =>
                        active.sourcePacketId !== null && void loadFull(active.id, active.sourcePacketId)
                      }
                    >
                      {active.loadingFull ? (
                        <>
                          <Loader2 className="spin" size={12} aria-hidden="true" />{" "}
                          {t("repeater.loading-full")}
                        </>
                      ) : (
                        t("repeater.load-full")
                      )}
                    </button>
                  )}
                </div>
                <textarea
                  id="repeater-hex"
                  className="hex-editor"
                  aria-label={t("repeater.bytes")}
                  aria-invalid={parsed?.error ? true : undefined}
                  spellCheck={false}
                  value={active.hex}
                  onChange={(event) =>
                    patchTab(active.id, { hex: event.target.value, truncated: false, dirty: true })
                  }
                  placeholder="00 0f 6d 69 6e 65 63 72 61 66 74 3a 62 72 61 6e 64"
                />
                {parsed?.error && (
                  <p className="filter-error" role="alert">
                    {parsed.error}
                  </p>
                )}
              </section>
            </Split>
          </section>
          <aside className="attempt-pane" aria-label={t("repeater.attempts")}>
            {active.attempts.length ? (
              active.attempts.map((attempt, index) => (
                <div className={`attempt ${attempt.ok ? "" : "failed"}`} key={`${attempt.at}-${index}`}>
                  <span>{new Date(attempt.at).toLocaleTimeString()}</span>
                  <strong>{attempt.result}</strong>
                  <small>{attempt.bytes} B</small>
                </div>
              ))
            ) : (
              <EmptyState title={t("repeater.attempts.none")} detail={t("repeater.attempts.hint")} />
            )}
          </aside>
        </Split>
      ) : (
        <EmptyState title={t("repeater.empty.title")} detail={t("repeater.empty.detail")} />
      )}
    </section>
  );
}
