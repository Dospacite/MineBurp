import { Loader2, Plus, Redo2, Save, Send, Undo2, X } from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { FieldEditor } from "../components/FieldEditor";
import { Split } from "../components/Split";
import type {
  ConnectionSnapshot,
  Direction,
  PacketView,
  ProtocolState,
  RepeaterEditHistory,
  RepeaterTab,
} from "../domain/types";
import { useFrameEditor } from "../hooks/useFrameEditor";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { base64ToBytes, desktop, formatHexInput, parseHex, readPayload, tryParseHex } from "../lib/desktop";
import { initialHistory, namedRevision, recordEdit, redoEdit, undoEdit } from "../lib/editHistory";
import { newId } from "../lib/ids";
import { registerProjectEditor } from "../lib/projectWrites";
import { useTrafficConnections } from "../lib/trafficStore";

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play"];

interface Attempt {
  at: number;
  bytes: number;
  ok: boolean;
  result: string;
}

/** One Repeater tab as the editor holds it, including what has not been saved. */
export interface RepeaterTabState {
  history: RepeaterEditHistory;
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
    history: initialHistory(formatHexInput(loaded)),
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
    history: tab.edit_history ?? initialHistory(formatHexInput(tab.logical_bytes)),
    id: tab.id,
    name: tab.name,
    connectionId: tab.connection_id,
    direction: tab.direction,
    state: replayableState(tab.state),
    protocolVersion: tab.protocol_version ?? null,
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
    history: initialHistory(""),
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
export const RepeaterView = memo(function RepeaterView({
  sessions: providedConnections,
  request,
  onRequestHandled,
  visible = true,
  onError,
  projectKey,
}: {
  projectKey?: string | null;
  sessions?: ConnectionSnapshot[];
  request: RepeaterRequest | null;
  onRequestHandled: (nonce: number) => void;
  /** Whether the view is on screen; keyboard shortcuts only apply then. */
  visible?: boolean;
  onError: (error: string) => void;
}) {
  const storedConnections = useTrafficConnections();
  const sessions = providedConnections ?? storedConnections;
  const live = sessions.filter((session) => session.status === "active" && session.state !== "opaque");
  const [tabs, renderTabs] = useState<RepeaterTabState[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);

  const [revisionName, setRevisionName] = useState("");
  const [showOriginal, setShowOriginal] = useState(false);
  const counter = useRef(1);
  const tabsRef = useRef(tabs);
  const setTabs = useCallback(
    (update: RepeaterTabState[] | ((tabs: RepeaterTabState[]) => RepeaterTabState[])) => {
      const next = typeof update === "function" ? update(tabsRef.current) : update;
      tabsRef.current = next;
      renderTabs(next);
    },
    [],
  );
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;

  const active = tabs.find((tab) => tab.id === activeId) ?? tabs[0] ?? null;
  const activeIdentity = useRef(active?.id);
  activeIdentity.current = active?.id;
  const session = sessions.find((item) => item.id === active?.connectionId);
  const protocolVersion = active?.protocolVersion ?? session?.protocol_version ?? null;
  const parseInput = active?.hex;
  const parsed = useMemo(() => (parseInput === undefined ? null : tryParseHex(parseInput)), [parseInput]);

  const patchTab = useCallback(
    (id: string, patch: Partial<RepeaterTabState>, typing = false) => {
      const next = tabsRef.current.map((tab) =>
        tab.id === id
          ? {
              ...tab,
              ...patch,
              history:
                patch.history ??
                (patch.hex === undefined ? tab.history : recordEdit(tab.history, tab.hex, patch.hex, typing)),
            }
          : tab,
      );
      tabsRef.current = next;
      setTabs(next);
    },
    [setTabs],
  );

  const loadFull = useCallback(
    async (id: string, packetId: number, expectedHex?: string) => {
      const before = expectedHex ?? tabsRef.current.find((tab) => tab.id === id)?.hex;
      patchTab(id, { loadingFull: true });
      try {
        const { bytes, complete } = await readPayload(packetId);
        const hex = formatHexInput(bytes);
        setTabs((current) =>
          current.map((tab) =>
            tab.id !== id
              ? tab
              : before !== undefined && tab.hex !== before
                ? { ...tab, loadingFull: false }
                : { ...tab, hex, history: initialHistory(hex), truncated: !complete, loadingFull: false },
          ),
        );
      } catch (reason) {
        patchTab(id, { loadingFull: false });
        onError(message(reason));
      }
    },
    [onError, patchTab, setTabs],
  );

  // Saved tabs join whatever is already open — including a tab a request
  // opened before they finished loading — instead of replacing it.
  useEffect(() => {
    void projectKey;
    if (!desktop.isAvailable()) return;
    let live = true;
    setTabs([]);
    setActiveId(null);
    void desktop
      .repeaterTabs()
      .then((saved) => {
        if (!live) return;
        setTabs((current) => {
          const open = new Set(current.map((tab) => tab.id));
          return [...current, ...saved.filter((tab) => !open.has(tab.id)).map(tabFromSaved)];
        });
        counter.current += saved.length;
      })
      .catch((reason) => {
        if (live) onError(message(reason));
      });
    return () => {
      live = false;
    };
  }, [onError, projectKey, setTabs]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: each request is handled once, by nonce.
  useEffect(() => {
    if (!request) return;
    const tab = tabFromPacket(request.packet, counter.current++);
    setTabs((current) => [...current, tab]);
    setActiveId(tab.id);
    onRequestHandled(request.nonce);
    if (tab.truncated) void loadFull(tab.id, request.packet.summary.id, tab.hex);
  }, [request?.nonce]);

  // A tab without a connection picks the first live one.
  useEffect(() => {
    if (active && !active.connectionId && live[0]) patchTab(active.id, { connectionId: live[0].id });
  }, [active, live, patchTab]);

  const frame = useFrameEditor(
    active?.hex ?? "",
    active?.state ?? "play",
    active?.direction ?? "client_to_server",
    protocolVersion,
    active?.id ?? null,
    (hex) => {
      if (active) {
        patchTab(active.id, { hex, dirty: true });
      }
    },
    onError,
  );
  const { layout: currentLayout, decoding, commitField } = frame;

  useEffect(
    () =>
      registerProjectEditor(async () => {
        await frame.flush();
        for (const tab of tabsRef.current.filter((tab) => tab.dirty)) {
          if (tab.truncated || tab.loadingFull)
            throw new Error("Load the full Repeater frame before saving.");
          await desktop.repeaterTabSave({
            id: tab.id,
            name: tab.name,
            connection_id: tab.connectionId,
            direction: tab.direction,
            state: tab.state,
            protocol_version: tab.protocolVersion,
            logical_bytes: Array.from(parseHex(tab.hex)),
            decoded: null,
            edit_history: tab.history,
          });
        }
      }),
    [frame.flush],
  );

  const send = useCallback(async () => {
    const identity = activeIdentity.current;
    try {
      await frame.flush();
    } catch {
      return;
    }
    if (activeIdentity.current !== identity) return;
    const tab = tabsRef.current.find((item) => item.id === identity);
    if (!tab) return;
    const record = (attempt: Attempt) =>
      setTabs((current) =>
        current.map((item) =>
          item.id === tab.id ? { ...item, attempts: [attempt, ...item.attempts].slice(0, 200) } : item,
        ),
      );
    try {
      const bytes = parseHex(frame.latestHex());
      await desktop.repeaterSend(tab.connectionId, tab.direction, bytes);
      record({ at: Date.now(), bytes: bytes.length, ok: true, result: t("repeater.sent") });
    } catch (reason) {
      const error = message(reason);
      record({ at: Date.now(), bytes: 0, ok: false, result: error });
      onError(error);
    }
  }, [onError, frame.latestHex, frame.flush, setTabs]);

  const save = useCallback(async () => {
    const identity = activeIdentity.current;
    try {
      await frame.flush();
    } catch {
      return;
    }
    if (activeIdentity.current !== identity) return;
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
        protocol_version:
          tab.protocolVersion ??
          sessionsRef.current.find((item) => item.id === tab.connectionId)?.protocol_version ??
          null,
        logical_bytes: Array.from(bytes),
        decoded: null,
        edit_history: tab.history,
      });
      setTabs((current) =>
        current.map((item) =>
          item.id === tab.id
            ? {
                ...item,
                saved: true,
                dirty:
                  item.hex !== tab.hex ||
                  item.history !== tab.history ||
                  item.name !== tab.name ||
                  item.direction !== tab.direction ||
                  item.state !== tab.state ||
                  item.connectionId !== tab.connectionId,
              }
            : item,
        ),
      );
    } catch (reason) {
      onError(message(reason));
    }
  }, [active?.id, onError, setTabs, frame.flush]);

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

  const travel = useCallback(
    (direction: "undo" | "redo") => {
      const tab = tabsRef.current.find((t) => t.id === active?.id);
      if (!tab) return;
      const result = direction === "undo" ? undoEdit(tab.history, tab.hex) : redoEdit(tab.history, tab.hex);
      if (result)
        patchTab(tab.id, { hex: result.hex, history: result.history, dirty: true, truncated: false });
    },
    [active?.id, patchTab],
  );

  // Ctrl/Cmd+Enter sends and Ctrl/Cmd+S saves while the Repeater is on screen.
  useEffect(() => {
    if (!visible) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.target instanceof Element && !event.target.closest(".repeater-view")) return;
      if (
        (event.key.toLowerCase() === "z" || event.key.toLowerCase() === "y") &&
        event.target instanceof Element &&
        event.target.matches("input, textarea:not(.hex-editor)")
      )
        return;
      if (document.querySelector('[role="dialog"]')) return;
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key === "Enter") {
        event.preventDefault();
        void send();
      } else if (event.key.toLowerCase() === "z") {
        event.preventDefault();
        travel(event.shiftKey ? "redo" : "undo");
      } else if (event.key.toLowerCase() === "y") {
        event.preventDefault();
        travel("redo");
      } else if (event.key.toLowerCase() === "s") {
        event.preventDefault();
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save, send, visible, travel]);

  const sendable = active !== null && live.some((item) => item.id === active.connectionId) && parsed?.bytes;

  return (
    <section className="repeater-view">
      <div className="repeater-tabs" role="tablist" aria-label={t("repeater.tabs")}>
        {tabs.map((tab) => (
          <div key={tab.id} className={`repeater-tab ${tab.id === active?.id ? "active" : ""}`}>
            <button
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-controls="repeater-panel"
              tabIndex={tab.id === active?.id ? 0 : -1}
              onKeyDown={(event) => {
                const index = tabs.indexOf(tab);
                const next =
                  event.key === "ArrowRight"
                    ? tabs[(index + 1) % tabs.length]
                    : event.key === "ArrowLeft"
                      ? tabs[(index + tabs.length - 1) % tabs.length]
                      : null;
                if (next) {
                  event.preventDefault();
                  setActiveId(next.id);
                  document.getElementById(`tab-${next.id}`)?.focus();
                }
              }}
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
          <section
            className="repeater-editor"
            role="tabpanel"
            id="repeater-panel"
            aria-labelledby={`tab-${active.id}`}
          >
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
              <button
                type="button"
                className="button"
                disabled={!active.history.past.length}
                onClick={() => travel("undo")}
                title={t("history.undo-shortcut")}
              >
                <Undo2 size={13} />
                {t("history.undo")}
              </button>
              <button
                type="button"
                className="button"
                disabled={!active.history.future.length}
                onClick={() => travel("redo")}
                title={t("history.redo-shortcut")}
              >
                <Redo2 size={13} />
                {t("history.redo")}
              </button>
              {session && session.status === "active" && session.state !== active.state && (
                <p className="repeater-state-warning" role="note">
                  {t("repeater.state-mismatch", { tab: active.state, session: session.state })}
                </p>
              )}
            </div>
            <p className="history-revision-note">{t("history.revision-note")}</p>
            <div className="revision-toolbar">
              <label>
                {t("history.revision-name")}
                <input
                  maxLength={80}
                  value={revisionName}
                  onChange={(e) => setRevisionName(e.target.value)}
                />
              </label>
              <button
                type="button"
                className="button"
                disabled={!revisionName.trim()}
                onClick={() => {
                  try {
                    patchTab(active.id, {
                      history: namedRevision(active.history, revisionName, active.hex),
                      dirty: true,
                    });
                    setRevisionName("");
                  } catch (error) {
                    onError(message(error));
                  }
                }}
              >
                {t("history.snapshot")}
              </button>
              <select
                aria-label={t("history.restore")}
                value=""
                onChange={(e) => {
                  const revision = active.history.revisions.find((r) => r.name === e.target.value);
                  if (revision) patchTab(active.id, { hex: revision.hex, dirty: true });
                }}
              >
                <option value="" disabled>
                  {t("history.restore")}
                </option>
                {active.history.revisions.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.name}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="button"
                disabled={
                  active.history.original_available === false || active.hex === active.history.original
                }
                onClick={() => patchTab(active.id, { hex: active.history.original, dirty: true })}
              >
                {t("history.reset-original")}
              </button>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  disabled={active.history.original_available === false}
                  checked={showOriginal}
                  onChange={(e) => setShowOriginal(e.target.checked)}
                />
                {t("history.compare-original")}
              </label>
            </div>
            {showOriginal && active.history.original_available !== false && (
              <label className="original-frame">
                {t("history.original")}
                <textarea readOnly rows={3} value={active.history.original} />
              </label>
            )}
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
                        active.sourcePacketId !== null &&
                        void loadFull(active.id, active.sourcePacketId, active.hex)
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
                    patchTab(active.id, { hex: event.target.value, truncated: false, dirty: true }, true)
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
});
