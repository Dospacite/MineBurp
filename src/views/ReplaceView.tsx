import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { ExpressionInput } from "../components/ExpressionInput";
import { Split } from "../components/Split";
import type {
  Direction,
  PacketEdit,
  PacketEditKind,
  PacketView,
  ProtocolState,
  ReplacementRule,
} from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { base64ToBytes, desktop, formatHexInput, parseHex, subscription } from "../lib/desktop";
import { newId } from "../lib/ids";
import { registerProjectEditor } from "../lib/projectWrites";

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play"];

/** A request from elsewhere in the workbench to start a rule for some packets. */
export interface RuleRequest {
  expression: string;
  nonce: number;
}

const EDIT_KINDS: Array<{ value: PacketEditKind; labelKey: Parameters<typeof t>[0] }> = [
  { value: "field", labelKey: "replace.kind.field" },
  { value: "field_replace", labelKey: "replace.kind.field_replace" },
  { value: "text", labelKey: "replace.kind.text" },
  { value: "regex", labelKey: "replace.kind.regex" },
  { value: "bytes", labelKey: "replace.kind.bytes" },
  { value: "range", labelKey: "replace.kind.range" },
  { value: "frame", labelKey: "replace.kind.frame" },
];

function blankEdit(kind: PacketEditKind): PacketEdit {
  switch (kind) {
    case "frame":
      return { kind, bytes: "" };
    case "range":
      return { kind, offset: 0, length: 1, bytes: "" };
    case "bytes":
      return { kind, find: "", replace: "", all: true };
    case "text":
      return { kind, find: "", replace: "", all: true, case_insensitive: false };
    case "regex":
      return { kind, pattern: "", replace: "", all: true };
    case "field":
      return { kind, name: "", value: "" };
    default:
      return { kind: "field_replace", name: "", find: "", replace: "", regex: false };
  }
}

/**
 * Rules that rewrite traffic automatically.
 *
 * Rules are saved to the project and handed to the proxy as they change, so a
 * rule is live the moment it is enabled rather than on the next restart.
 */
export function ReplaceView({
  projectKey,
  seed,
  request = null,
  onRequestHandled,
  onError,
}: {
  /** The packet selected in Traffic, offered as a preview subject. */
  projectKey?: string | null;
  seed: PacketView | null;
  request?: RuleRequest | null;
  onRequestHandled?: (nonce: number) => void;
  onError: (error: string) => void;
}) {
  const [rules, setRules] = useState<ReplacementRule[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [expressionError, setExpressionError] = useState<string | null>(null);
  const [sample, setSample] = useState("");
  const [state, setState] = useState<ProtocolState>("play");
  const [direction, setDirection] = useState<Direction>("client_to_server");
  /** The protocol the sample was captured under, so field edits resolve against the right layout. */
  const [sampleVersion, setSampleVersion] = useState<number | null>(null);
  const [preview, setPreview] = useState<{ hex: string; error: string | null }>({ hex: "", error: null });
  /** Rules have arrived from the project; until then a save would overwrite them. */
  const [loaded, setLoaded] = useState(!desktop.isAvailable());
  const saveTimer = useRef(0);
  const pendingRules = useRef<ReplacementRule[] | null>(null);
  useEffect(
    () =>
      registerProjectEditor(async () => {
        window.clearTimeout(saveTimer.current);
        const pending = pendingRules.current;
        if (pending) {
          await desktop.saveReplacementRules(pending, projectKey);
          if (pendingRules.current === pending) pendingRules.current = null;
        }
      }),
    [projectKey],
  );
  useEffect(
    () => () => {
      window.clearTimeout(saveTimer.current);
      const pending = pendingRules.current;
      if (pending)
        void desktop.saveReplacementRules(pending, projectKey).catch((reason) => onError(message(reason)));
    },
    [onError, projectKey],
  );
  const previewRequest = useRef(0);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    let live = true;
    const load = () => {
      void desktop
        .replacementRules()
        .then((stored) => {
          if (!live) return;
          setRules(stored);
          setSelectedId((current) => current ?? stored[0]?.id ?? null);
          setLoaded(true);
        })
        .catch((reason) => onError(message(reason)));
    };
    load();
    const stop = subscription(
      desktop.onMcpChange((topic) => {
        if (topic === "rules") {
          window.clearTimeout(saveTimer.current);
          pendingRules.current = null;
          load();
        }
      }),
    );
    return () => {
      live = false;
      stop();
    };
  }, [onError]);

  const selected = rules.find((rule) => rule.id === selectedId) ?? null;

  // Rules are pushed to the proxy as they are edited; the debounce only keeps
  // one keystroke from becoming one database write.
  const persist = useCallback(
    (next: ReplacementRule[]) => {
      if (!desktop.isAvailable()) return;
      pendingRules.current = next;
      window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        void desktop
          .saveReplacementRules(next, projectKey)
          .then(() => {
            if (pendingRules.current === next) pendingRules.current = null;
          })
          .catch((reason) => onError(message(reason)));
      }, 350);
    },
    [onError, projectKey],
  );

  const update = useCallback(
    (next: ReplacementRule[]) => {
      setRules(next);
      persist(next);
    },
    [persist],
  );

  function patch(change: Partial<ReplacementRule>) {
    if (!selected) return;
    update(rules.map((rule) => (rule.id === selected.id ? { ...rule, ...change } : rule)));
  }

  function addRule(expression = "") {
    const rule: ReplacementRule = {
      id: newId(),
      name: t("replace.rule.default", { index: rules.length + 1 }),
      enabled: false,
      action: "rewrite",
      expression,
      edits: [blankEdit("field")],
    };
    update([...rules, rule]);
    setSelectedId(rule.id);
  }

  // A rule asked for from the history starts disabled with its selector filled in.
  // biome-ignore lint/correctness/useExhaustiveDependencies: each request is handled once, by nonce.
  useEffect(() => {
    if (!request || !loaded) return;
    addRule(request.expression);
    onRequestHandled?.(request.nonce);
  }, [request?.nonce, loaded]);

  function removeRule(id: string) {
    const next = rules.filter((rule) => rule.id !== id);
    update(next);
    if (selectedId === id) setSelectedId(next[0]?.id ?? null);
  }

  async function validateExpression(expression: string) {
    if (!expression.trim() || !desktop.isAvailable()) {
      setExpressionError(null);
      return;
    }
    try {
      await desktop.filterValidate(expression);
      setExpressionError(null);
    } catch (reason) {
      setExpressionError(message(reason));
    }
  }

  const edits = useMemo(() => selected?.edits ?? [], [selected]);

  // The preview runs the same edits the proxy would run, against bytes the
  // operator supplies, so a rule can be checked before it is enabled.
  useEffect(() => {
    const requestId = ++previewRequest.current;
    if (!desktop.isAvailable() || !sample.trim() || !selected) {
      setPreview({ hex: "", error: null });
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const result = await desktop.replacementRulePreview(
            selected,
            parseHex(sample),
            state,
            direction,
            sampleVersion,
            seed?.summary ?? null,
          );
          const text = !result.matched
            ? t("replace.preview.no-match")
            : result.protected
              ? t("replace.preview.protected")
              : result.action === "drop"
                ? t("replace.preview.drop")
                : formatHexInput(base64ToBytes(result.logical_base64));
          if (requestId === previewRequest.current) setPreview({ hex: text, error: null });
        } catch (reason) {
          if (requestId === previewRequest.current) setPreview({ hex: "", error: message(reason) });
        }
      })();
    }, 250);
    return () => window.clearTimeout(timer);
  }, [direction, selected, sample, sampleVersion, state, seed]);

  return (
    <Split
      orientation="columns"
      storageKey="replace"
      initial={[0.26, 0.74]}
      minimum={200}
      className="replace-layout"
    >
      <aside className="rule-list">
        <div className="rule-list-header">
          <span>{t("replace.rules")}</span>
          <button type="button" className="button" onClick={() => addRule()} disabled={!loaded}>
            <Plus size={14} /> {t("replace.new")}
          </button>
        </div>
        {rules.map((rule) => (
          <div className={`rule-card ${rule.id === selectedId ? "selected" : ""}`} key={rule.id}>
            <input
              type="checkbox"
              checked={rule.enabled}
              aria-label={t("replace.enable-rule", { name: rule.name })}
              onChange={(event) =>
                update(
                  rules.map((item) =>
                    item.id === rule.id ? { ...item, enabled: event.target.checked } : item,
                  ),
                )
              }
            />
            <button type="button" className="rule-open" onClick={() => setSelectedId(rule.id)}>
              <strong>{rule.name}</strong>
              <small>
                {rule.expression || t("replace.every-packet")} ·{" "}
                {rule.action === "drop" ? t("replace.action.drop") : rule.edits.length}
              </small>
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label={t("replace.delete-rule", { name: rule.name })}
              onClick={() => removeRule(rule.id)}
            >
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </aside>

      {selected ? (
        <section className="rule-editor">
          <div className="rule-editor-form">
            <label>
              {t("replace.name")}
              <input value={selected.name} onChange={(event) => patch({ name: event.target.value })} />
            </label>
            {/* biome-ignore lint/a11y/noLabelWithoutControl: the label wraps ExpressionInput's input. */}
            <label>
              {t("replace.applies-to")}
              <ExpressionInput
                value={selected.expression}
                placeholder={t("replace.every-packet")}
                ariaLabel={t("replace.applies-to")}
                invalid={expressionError !== null}
                onChange={(expression) => patch({ expression })}
                onBlur={() => void validateExpression(selected.expression)}
              />
            </label>
            <label>
              {t("replace.action")}
              <select
                value={selected.action ?? "rewrite"}
                onChange={(e) => patch({ action: e.target.value as "rewrite" | "drop" })}
              >
                <option value="rewrite">{t("replace.action.rewrite")}</option>
                <option value="drop">{t("replace.action.drop")}</option>
              </select>
            </label>
            <label className="rule-enabled">
              <input
                type="checkbox"
                checked={selected.enabled}
                onChange={(event) => patch({ enabled: event.target.checked })}
              />
              {t("replace.enabled")}
            </label>
          </div>
          {expressionError && (
            <p className="filter-error" role="alert">
              {expressionError}
            </p>
          )}

          {selected.action === "drop" ? (
            <p className="intercept-notice">{t("replace.blocker-note")}</p>
          ) : (
            <div className="rule-edits">
              {edits.map((edit, index) => (
                <EditRow
                  key={index}
                  edit={edit}
                  onChange={(next) => patch({ edits: edits.map((item, at) => (at === index ? next : item)) })}
                  onRemove={() => patch({ edits: edits.filter((_, at) => at !== index) })}
                />
              ))}
              <button
                type="button"
                className="button"
                onClick={() => patch({ edits: [...edits, blankEdit("field")] })}
              >
                <Plus size={14} /> {t("replace.add-edit")}
              </button>
            </div>
          )}

          <div className="rule-preview">
            <div className="rule-preview-controls">
              <label>
                {t("replace.state")}
                <select value={state} onChange={(event) => setState(event.target.value as ProtocolState)}>
                  {STATES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {t("replace.direction")}
                <select value={direction} onChange={(event) => setDirection(event.target.value as Direction)}>
                  <option value="client_to_server">{t("replace.direction.c2s")}</option>
                  <option value="server_to_client">{t("replace.direction.s2c")}</option>
                </select>
              </label>
              <button
                type="button"
                className="button"
                disabled={!seed}
                onClick={() => {
                  if (!seed) return;
                  setSample(formatHexInput(base64ToBytes(seed.bytes_base64)));
                  setSampleVersion(seed.summary.protocol_version);
                  setState(
                    seed.summary.state === "opaque" || seed.summary.state === "closed"
                      ? "play"
                      : seed.summary.state,
                  );
                  setDirection(seed.summary.direction);
                }}
              >
                {t("replace.from-selected")}
              </button>
            </div>
            <div className="rule-preview-panes">
              <label className="rule-preview-pane">
                {t("replace.input")}
                <textarea
                  className="hex-editor"
                  spellCheck={false}
                  value={sample}
                  onChange={(event) => setSample(event.target.value)}
                />
                {sampleVersion !== null && (
                  <small className="filter-hint">
                    {t("replace.sample-version", { version: sampleVersion })}
                  </small>
                )}
              </label>
              <label className="rule-preview-pane">
                {t("replace.result")}
                <textarea
                  className="hex-editor"
                  spellCheck={false}
                  readOnly
                  value={preview.error ?? preview.hex}
                />
              </label>
            </div>
          </div>
        </section>
      ) : (
        <EmptyState title={t("replace.no-rule.title")} detail={t("replace.no-rule.detail")} />
      )}
    </Split>
  );
}

function EditRow({
  edit,
  onChange,
  onRemove,
}: {
  edit: PacketEdit;
  onChange: (edit: PacketEdit) => void;
  onRemove: () => void;
}) {
  return (
    <div className="rule-edit">
      <select
        aria-label={t("replace.edit-kind")}
        value={edit.kind}
        onChange={(event) => onChange(blankEdit(event.target.value as PacketEditKind))}
      >
        {EDIT_KINDS.map((kind) => (
          <option key={kind.value} value={kind.value}>
            {t(kind.labelKey)}
          </option>
        ))}
      </select>

      {edit.kind === "frame" && (
        <label>
          {t("form.bytes")}
          <input
            className="hex"
            spellCheck={false}
            value={edit.bytes}
            onChange={(event) => onChange({ ...edit, bytes: event.target.value })}
            placeholder="00 0f"
          />
        </label>
      )}

      {edit.kind === "range" && (
        <>
          <label>
            {t("form.offset")}
            <input
              type="number"
              min={0}
              value={edit.offset}
              onChange={(event) => onChange({ ...edit, offset: Number(event.target.value) || 0 })}
            />
          </label>
          <label>
            {t("form.length")}
            <input
              type="number"
              min={0}
              value={edit.length}
              onChange={(event) => onChange({ ...edit, length: Number(event.target.value) || 0 })}
            />
          </label>
          <label>
            {t("form.bytes")}
            <input
              className="hex"
              spellCheck={false}
              value={edit.bytes}
              onChange={(event) => onChange({ ...edit, bytes: event.target.value })}
              placeholder="ca fe"
            />
          </label>
        </>
      )}

      {edit.kind === "bytes" && (
        <>
          <label>
            {t("form.find")}
            <input
              className="hex"
              spellCheck={false}
              value={edit.find}
              onChange={(event) => onChange({ ...edit, find: event.target.value })}
              placeholder="de ad"
            />
          </label>
          <label>
            {t("form.replace")}
            <input
              className="hex"
              spellCheck={false}
              value={edit.replace}
              onChange={(event) => onChange({ ...edit, replace: event.target.value })}
              placeholder="be ef"
            />
          </label>
          <Toggle label={t("form.all")} checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
        </>
      )}

      {edit.kind === "text" && (
        <>
          <label>
            {t("form.find")}
            <input value={edit.find} onChange={(event) => onChange({ ...edit, find: event.target.value })} />
          </label>
          <label>
            {t("form.replace")}
            <input
              value={edit.replace}
              onChange={(event) => onChange({ ...edit, replace: event.target.value })}
            />
          </label>
          <Toggle label={t("form.all")} checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
          <Toggle
            label={t("form.match-case")}
            checked={!edit.case_insensitive}
            onChange={(sensitive) => onChange({ ...edit, case_insensitive: !sensitive })}
          />
        </>
      )}

      {edit.kind === "regex" && (
        <>
          <label>
            {t("form.pattern")}
            <input
              className="hex"
              spellCheck={false}
              value={edit.pattern}
              onChange={(event) => onChange({ ...edit, pattern: event.target.value })}
              placeholder="player_?name"
            />
          </label>
          <label>
            {t("form.replace")}
            <input
              value={edit.replace}
              onChange={(event) => onChange({ ...edit, replace: event.target.value })}
              placeholder="$0"
            />
          </label>
          <Toggle label={t("form.all")} checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
        </>
      )}

      {edit.kind === "field" && (
        <>
          <label>
            {t("form.field")}
            <input
              value={edit.name}
              onChange={(event) => onChange({ ...edit, name: event.target.value })}
              placeholder="server address"
            />
          </label>
          <label>
            {t("form.value")}
            <input
              value={edit.value}
              onChange={(event) => onChange({ ...edit, value: event.target.value })}
            />
          </label>
        </>
      )}

      {edit.kind === "field_replace" && (
        <>
          <label>
            {t("form.field")}
            <input
              value={edit.name}
              onChange={(event) => onChange({ ...edit, name: event.target.value })}
              placeholder="message"
            />
          </label>
          <label>
            {t("form.find")}
            <input value={edit.find} onChange={(event) => onChange({ ...edit, find: event.target.value })} />
          </label>
          <label>
            {t("form.replace")}
            <input
              value={edit.replace}
              onChange={(event) => onChange({ ...edit, replace: event.target.value })}
            />
          </label>
          <Toggle
            label={t("filter.regex")}
            checked={edit.regex}
            onChange={(regex) => onChange({ ...edit, regex })}
          />
        </>
      )}

      <button type="button" className="icon-button" aria-label={t("replace.remove-edit")} onClick={onRemove}>
        <Trash2 size={14} />
      </button>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={`rule-toggle ${checked ? "checked" : ""}`}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}
