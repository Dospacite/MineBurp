import { FastForward, Gauge, Hand, RotateCcw, Send, ShieldOff, Timer, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { EmptyState } from "../components/EmptyState";
import { ExpressionInput } from "../components/ExpressionInput";
import { FieldEditor } from "../components/FieldEditor";
import { isNeutral, NetworkConditionsDialog } from "../components/NetworkConditionsDialog";
import { Split } from "../components/Split";
import type {
  FieldSpan,
  InterceptedPacket,
  InterceptSettings,
  NetworkConditions,
  PacketLayout,
} from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { base64ToBytes, desktop, formatHexInput, parseHex, tryParseHex } from "../lib/desktop";

export function InterceptView({
  settings,
  onSettingsPatch,
  pendingSignal,
  decryptEnabled,
  onError,
}: {
  settings: InterceptSettings | null;
  /**
   * Changes some settings and leaves the rest as the backend has them. A
   * patch, not a whole object, so two quick changes cannot revert each other.
   */
  onSettingsPatch: (patch: Partial<InterceptSettings>) => Promise<InterceptSettings>;
  /** Changes whenever the backend reports the queue changed. */
  pendingSignal: number;
  decryptEnabled: boolean;
  onError: (error: string) => void;
}) {
  const [queue, setQueue] = useState<InterceptedPacket[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [hex, setHex] = useState("");
  const [layout, setLayout] = useState<PacketLayout | null>(null);
  const [decoding, setDecoding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [expression, setExpression] = useState(settings?.expression ?? "");
  const [expressionError, setExpressionError] = useState<string | null>(null);
  /** The expression has been typed but not applied; settings updates leave it alone. */
  const expressionDirty = useRef(false);
  const decode = useRef(0);
  const [networkOpen, setNetworkOpen] = useState(false);
  const [network, setNetwork] = useState<NetworkConditions | null>(null);
  const [autoForward, setAutoForward] = useState(secondsText(settings?.auto_forward_after_ms ?? null));

  const appliedAutoForward = settings?.auto_forward_after_ms;
  useEffect(() => {
    if (appliedAutoForward !== undefined) setAutoForward(secondsText(appliedAutoForward));
  }, [appliedAutoForward]);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .networkConditions()
      .then(setNetwork)
      .catch((reason) => onError(message(reason)));
  }, [onError]);

  const selected = queue.find((packet) => packet.id === selectedId) ?? null;
  const original = useMemo(
    () => (selected ? formatHexInput(base64ToBytes(selected.bytes_base64)) : ""),
    [selected],
  );
  const edited = selected !== null && normalise(hex) !== normalise(original);
  const hexError = selected ? tryParseHex(hex).error : null;

  const appliedExpression = settings?.expression;
  useEffect(() => {
    if (appliedExpression !== undefined && !expressionDirty.current) setExpression(appliedExpression);
  }, [appliedExpression]);

  // Refetch on every queue event rather than trusting a count: resolving one
  // frame while another arrives leaves the count unchanged.
  // biome-ignore lint/correctness/useExhaustiveDependencies: pendingSignal is the trigger.
  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .interceptPending()
      .then((next) => {
        setQueue(next);
        // Stay on the frame being edited; otherwise move to the oldest one.
        setSelectedId((current) =>
          current !== null && next.some((packet) => packet.id === current) ? current : (next[0]?.id ?? null),
        );
      })
      .catch((reason) => onError(message(reason)));
  }, [pendingSignal, onError]);

  // A newly selected frame starts from its captured bytes.
  useEffect(() => setHex(original), [original]);

  useEffect(() => {
    if (!selected || !desktop.isAvailable()) {
      setLayout(null);
      return undefined;
    }
    const requestId = ++decode.current;
    const timer = window.setTimeout(() => {
      void (async () => {
        const parsed = tryParseHex(hex);
        if (!parsed.bytes) {
          if (requestId === decode.current) setLayout(null);
          return;
        }
        const bytes = parsed.bytes;
        setDecoding(true);
        try {
          const next = await desktop.packetLayout(
            bytes,
            selected.summary.state,
            selected.summary.direction,
            selected.summary.protocol_version,
          );
          if (requestId === decode.current) setLayout(next);
        } catch {
          if (requestId === decode.current) setLayout(null);
        } finally {
          if (requestId === decode.current) setDecoding(false);
        }
      })();
    }, 150);
    return () => window.clearTimeout(timer);
  }, [hex, selected]);

  const commitField = useCallback(
    async (field: FieldSpan, value: string | boolean) => {
      try {
        setHex(formatHexInput(await desktop.fieldEdit(parseHex(hex), field, value)));
      } catch (reason) {
        onError(message(reason));
      }
    },
    [hex, onError],
  );

  const resolve = useCallback(
    async (action: "forward" | "drop") => {
      if (!selected || busy) return;
      setBusy(true);
      try {
        const replacement = action === "forward" && edited ? parseHex(hex) : undefined;
        await desktop.interceptResolve(selected.id, action, replacement);
      } catch (reason) {
        onError(message(reason));
      } finally {
        setBusy(false);
      }
    },
    [busy, edited, hex, onError, selected],
  );

  async function forwardAll() {
    try {
      await desktop.interceptForwardAll();
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function update(patch: Partial<InterceptSettings>) {
    if (!settings) return;
    try {
      await onSettingsPatch(patch);
    } catch {
      // The workbench shows the error.
    }
  }

  const autoForwardMs = parseSeconds(autoForward);

  async function applyAutoForward() {
    if (!settings || autoForwardMs === undefined || autoForwardMs === settings.auto_forward_after_ms) return;
    await update({ auto_forward_after_ms: autoForwardMs });
  }

  async function applyExpression() {
    if (!settings || expression === settings.expression) {
      expressionDirty.current = false;
      return;
    }
    try {
      if (expression.trim()) await desktop.filterValidate(expression);
      setExpressionError(null);
      await update({ expression });
      expressionDirty.current = false;
    } catch (reason) {
      setExpressionError(message(reason));
    }
  }

  // Ctrl/Cmd+Enter forwards from anywhere; Ctrl/Cmd+Backspace drops outside text fields.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key === "Enter") {
        event.preventDefault();
        void resolve("forward");
      } else if (event.key === "Backspace" && !isTextEntry(event.target)) {
        // Inside a text field Ctrl+Backspace deletes a word; leave it alone.
        event.preventDefault();
        void resolve("drop");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [resolve]);

  const enabled = settings?.enabled ?? false;

  return (
    <section className="intercept-view">
      <div className="intercept-toolbar">
        <div className={`decrypt-control ${enabled ? "enabled intercepting" : ""}`}>
          <span className="decrypt-icon" aria-hidden="true">
            <Hand size={16} />
          </span>
          <strong>{t("intercept.title")}</strong>
          <button
            type="button"
            className={`decrypt-switch ${enabled ? "on" : ""}`}
            role="switch"
            aria-checked={enabled}
            disabled={!settings}
            onClick={() => void update({ enabled: !enabled })}
          >
            {enabled ? t("traffic.decrypt.on") : t("traffic.decrypt.off")}
          </button>
        </div>
        <fieldset className="intercept-directions" aria-label={t("intercept.directions")}>
          <label className="check">
            <input
              type="checkbox"
              checked={settings?.client_to_server ?? false}
              onChange={(event) => void update({ client_to_server: event.target.checked })}
            />
            {t("repeater.direction.c2s")}
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={settings?.server_to_client ?? false}
              onChange={(event) => void update({ server_to_client: event.target.checked })}
            />
            {t("repeater.direction.s2c")}
          </label>
          <label className="check" title={t("intercept.keep-alive.hint")}>
            <input
              type="checkbox"
              checked={settings?.forward_keep_alive ?? true}
              onChange={(event) => void update({ forward_keep_alive: event.target.checked })}
            />
            {t("intercept.keep-alive")}
          </label>
          <label className="check intercept-auto-forward" title={t("intercept.auto-forward.hint")}>
            <Timer size={13} aria-hidden="true" />
            {t("intercept.auto-forward")}
            <input
              inputMode="decimal"
              size={4}
              value={autoForward}
              aria-invalid={autoForwardMs === undefined || undefined}
              placeholder="—"
              onChange={(event) => setAutoForward(event.target.value)}
              onBlur={() => void applyAutoForward()}
              onKeyDown={(event) => {
                if (event.key === "Enter") void applyAutoForward();
              }}
            />
            {t("intercept.auto-forward.unit")}
          </label>
        </fieldset>
        {/* biome-ignore lint/a11y/noLabelWithoutControl: the label wraps ExpressionInput's input. */}
        <label className="intercept-expression">
          {t("intercept.expression")}
          <ExpressionInput
            value={expression}
            onChange={(next) => {
              expressionDirty.current = true;
              setExpression(next);
            }}
            onBlur={() => void applyExpression()}
            onEnter={() => void applyExpression()}
            placeholder={t("intercept.expression.placeholder")}
            ariaLabel={t("intercept.expression")}
            invalid={expressionError !== null}
          />
          {expressionError && (
            <small className="filter-error" role="alert">
              {expressionError}
            </small>
          )}
        </label>
        <button
          type="button"
          className="button"
          disabled={queue.length === 0}
          onClick={() => void forwardAll()}
        >
          <FastForward size={14} aria-hidden="true" />
          {t("intercept.forward-all", { count: queue.length })}
        </button>
        <button
          type="button"
          className={`button ${isNeutral(network) ? "" : "accent"}`}
          onClick={() => setNetworkOpen(true)}
          title={t("network.title")}
        >
          <Gauge size={14} aria-hidden="true" />
          {isNeutral(network) ? t("network.button") : t("network.active")}
        </button>
      </div>
      {networkOpen && (
        <NetworkConditionsDialog
          onApplied={setNetwork}
          onClose={() => setNetworkOpen(false)}
          onError={onError}
        />
      )}
      {!decryptEnabled && (
        <p className="intercept-notice">
          <ShieldOff size={13} aria-hidden="true" />
          {t("intercept.needs-decrypt")}
        </p>
      )}
      <Split
        orientation="columns"
        storageKey="intercept"
        initial={[0.3, 0.7]}
        minimum={220}
        className="intercept-layout"
      >
        <aside className="intercept-queue" aria-label={t("intercept.queue")}>
          {queue.length === 0 ? (
            <EmptyState
              title={enabled ? t("intercept.empty.waiting") : t("intercept.empty.off")}
              detail={enabled ? t("intercept.empty.waiting.detail") : t("intercept.empty.off.detail")}
            />
          ) : (
            queue.map((packet) => (
              <button
                type="button"
                key={packet.id}
                className={`flow-card ${packet.id === selectedId ? "selected" : ""}`}
                aria-pressed={packet.id === selectedId}
                onClick={() => setSelectedId(packet.id)}
              >
                <span className={`direction ${packet.summary.direction}`}>
                  {packet.summary.direction === "client_to_server" ? "C → S" : "S → C"}
                </span>
                <span>
                  <strong>
                    {packet.summary.name ??
                      (packet.summary.packet_id === null
                        ? "?"
                        : `0x${packet.summary.packet_id.toString(16)}`)}
                  </strong>
                  <small>
                    {packet.target} · {packet.summary.state} · {packet.summary.size} B
                    {packet.deadline_micros !== null && (
                      <>
                        {" · "}
                        <Countdown deadlineMicros={packet.deadline_micros} />
                      </>
                    )}
                  </small>
                </span>
              </button>
            ))
          )}
        </aside>
        <section className="repeater-editor intercept-editor">
          {selected ? (
            <>
              <div className="repeater-toolbar">
                <span className="intercept-held">
                  {t("intercept.held", {
                    direction: selected.summary.direction === "client_to_server" ? "C → S" : "S → C",
                    target: selected.target,
                  })}
                  {edited && <span className="project-tag">{t("intercept.edited")}</span>}
                  {selected.deadline_micros !== null && (
                    <span className="project-tag">
                      <Countdown deadlineMicros={selected.deadline_micros} />
                    </span>
                  )}
                </span>
                <button type="button" className="button" disabled={!edited} onClick={() => setHex(original)}>
                  <RotateCcw size={14} aria-hidden="true" />
                  {t("intercept.reset")}
                </button>
                <button
                  type="button"
                  className="button danger"
                  disabled={busy}
                  onClick={() => void resolve("drop")}
                  title={t("intercept.drop.shortcut")}
                >
                  <Trash2 size={14} aria-hidden="true" />
                  {t("intercept.drop")}
                </button>
                <button
                  type="button"
                  className="button accent"
                  disabled={busy}
                  onClick={() => void resolve("forward")}
                  title={t("intercept.forward.shortcut")}
                >
                  <Send size={14} aria-hidden="true" />
                  {edited ? t("intercept.forward-edited") : t("intercept.forward")}
                </button>
              </div>
              <Split
                orientation="rows"
                storageKey="intercept-editors"
                initial={[0.55, 0.45]}
                minimum={120}
                className="repeater-panes"
              >
                <section className="editor-section">
                  <h3>
                    {layout?.name ?? t("repeater.decoded")}
                    {layout && !layout.complete ? ` · ${t("repeater.partial")}` : ""}
                  </h3>
                  <div className="editor-scroll">
                    <FieldEditor
                      layout={layout}
                      onCommit={(field, value) => void commitField(field, value)}
                      busy={decoding}
                    />
                  </div>
                </section>
                <section className="editor-section">
                  <h3>{t("repeater.bytes")}</h3>
                  <textarea
                    className="hex-editor"
                    aria-label={t("repeater.bytes")}
                    aria-invalid={hexError ? true : undefined}
                    spellCheck={false}
                    value={hex}
                    onChange={(event) => setHex(event.target.value)}
                  />
                  {hexError && (
                    <p className="filter-error" role="alert">
                      {hexError}
                    </p>
                  )}
                </section>
              </Split>
            </>
          ) : (
            <EmptyState title={t("intercept.none-selected")} detail={t("intercept.shortcuts")} />
          )}
        </section>
      </Split>
    </section>
  );
}

/** Seconds left before a held frame is forwarded on its own, refreshed while shown. */
export function Countdown({ deadlineMicros }: { deadlineMicros: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, []);
  const seconds = Math.max(0, Math.ceil((deadlineMicros / 1000 - now) / 1000));
  return (
    <span className="intercept-countdown" role="timer">
      {t("intercept.countdown", { seconds })}
    </span>
  );
}

function secondsText(milliseconds: number | null): string {
  return milliseconds === null ? "" : String(milliseconds / 1000);
}

/**
 * Reads the auto-forward field: null when empty (wait for the operator),
 * milliseconds when it is a positive number, undefined when it is not valid.
 */
export function parseSeconds(text: string): number | null | undefined {
  if (text.trim() === "") return null;
  const seconds = Number(text);
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 3600) return undefined;
  return Math.round(seconds * 1000);
}

/** Hex compared by bytes, not by the spacing the operator typed. */
function normalise(hex: string): string {
  return hex.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

function isTextEntry(target: EventTarget | null): boolean {
  return target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement;
}
