import { Plus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
  Direction,
  PacketEdit,
  PacketEditKind,
  PacketView,
  ProtocolState,
  ReplacementRule,
} from "../domain/types";
import { EmptyState } from "../components/EmptyState";
import { Split } from "../components/Split";
import { base64ToBytes, desktop, formatHexInput, parseHex } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play"];

const EDIT_KINDS: Array<{ value: PacketEditKind; label: string }> = [
  { value: "field", label: "Set field" },
  { value: "field_replace", label: "Replace in field" },
  { value: "text", label: "Find text" },
  { value: "regex", label: "Regex" },
  { value: "bytes", label: "Find bytes" },
  { value: "range", label: "Byte range" },
  { value: "frame", label: "Whole frame" },
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
  seed,
  onError,
}: {
  /** The packet selected in Traffic, offered as a preview subject. */
  seed: PacketView | null;
  onError: (error: string) => void;
}) {
  const [rules, setRules] = useState<ReplacementRule[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [expressionError, setExpressionError] = useState<string | null>(null);
  const [sample, setSample] = useState("");
  const [state, setState] = useState<ProtocolState>("play");
  const [direction, setDirection] = useState<Direction>("client_to_server");
  const [preview, setPreview] = useState<{ hex: string; error: string | null }>({ hex: "", error: null });
  const saveTimer = useRef(0);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .replacementRules()
      .then((loaded) => {
        setRules(loaded);
        setSelectedId((current) => current ?? loaded[0]?.id ?? null);
      })
      .catch((reason) => onError(message(reason)));
  }, [onError]);

  const selected = rules.find((rule) => rule.id === selectedId) ?? null;

  // Rules are pushed to the proxy as they are edited; the debounce only keeps
  // one keystroke from becoming one database write.
  const persist = useCallback(
    (next: ReplacementRule[]) => {
      if (!desktop.isAvailable()) return;
      window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        void desktop.saveReplacementRules(next).catch((reason) => onError(message(reason)));
      }, 350);
    },
    [onError],
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

  function addRule() {
    const rule: ReplacementRule = {
      id: crypto.randomUUID(),
      name: `Rule ${rules.length + 1}`,
      enabled: false,
      expression: "",
      edits: [blankEdit("field")],
    };
    update([...rules, rule]);
    setSelectedId(rule.id);
  }

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
    if (!desktop.isAvailable() || !sample.trim() || edits.length === 0) {
      setPreview({ hex: "", error: null });
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const bytes = await desktop.replacementPreview(parseHex(sample), state, direction, edits);
          setPreview({ hex: formatHexInput(bytes), error: null });
        } catch (reason) {
          setPreview({ hex: "", error: message(reason) });
        }
      })();
    }, 250);
    return () => window.clearTimeout(timer);
  }, [direction, edits, sample, state]);

  return (
    <Split orientation="columns" storageKey="replace" initial={[0.26, 0.74]} minimum={200} className="replace-layout">
      <aside className="rule-list">
        <div className="rule-list-header">
          <span>Rules</span>
          <button className="button" onClick={addRule}><Plus size={14} /> New</button>
        </div>
        {rules.map((rule) => (
          <div className={`rule-card ${rule.id === selectedId ? "selected" : ""}`} key={rule.id}>
            <input
              type="checkbox"
              checked={rule.enabled}
              aria-label={`Enable ${rule.name}`}
              onChange={(event) =>
                update(rules.map((item) => (item.id === rule.id ? { ...item, enabled: event.target.checked } : item)))
              }
            />
            <button className="rule-open" onClick={() => setSelectedId(rule.id)}>
              <strong>{rule.name}</strong>
              <small>{rule.expression || "every packet"} · {rule.edits.length}</small>
            </button>
            <button className="icon-button" aria-label={`Delete ${rule.name}`} onClick={() => removeRule(rule.id)}>
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </aside>

      {selected ? (
        <section className="rule-editor">
          <div className="rule-editor-form">
            <label>Name<input value={selected.name} onChange={(event) => patch({ name: event.target.value })} /></label>
            <label>
              Applies to
              <input
                value={selected.expression}
                spellCheck={false}
                placeholder="every packet"
                aria-invalid={expressionError !== null}
                onChange={(event) => patch({ expression: event.target.value })}
                onBlur={(event) => void validateExpression(event.target.value)}
              />
            </label>
            <label className="rule-enabled">
              <input type="checkbox" checked={selected.enabled} onChange={(event) => patch({ enabled: event.target.checked })} />
              Enabled
            </label>
          </div>
          {expressionError && <p className="filter-error" role="alert">{expressionError}</p>}

          <div className="rule-edits">
            {edits.map((edit, index) => (
              <EditRow
                key={index}
                edit={edit}
                onChange={(next) => patch({ edits: edits.map((item, at) => (at === index ? next : item)) })}
                onRemove={() => patch({ edits: edits.filter((_, at) => at !== index) })}
              />
            ))}
            <button className="button" onClick={() => patch({ edits: [...edits, blankEdit("field")] })}>
              <Plus size={14} /> Add edit
            </button>
          </div>

          <div className="rule-preview">
            <div className="rule-preview-controls">
              <label>State<select value={state} onChange={(event) => setState(event.target.value as ProtocolState)}>{STATES.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
              <label>Direction<select value={direction} onChange={(event) => setDirection(event.target.value as Direction)}><option value="client_to_server">Client → server</option><option value="server_to_client">Server → client</option></select></label>
              <button
                className="button"
                disabled={!seed}
                onClick={() => {
                  if (!seed) return;
                  setSample(formatHexInput(base64ToBytes(seed.bytes_base64)));
                  setState(seed.summary.state === "opaque" || seed.summary.state === "closed" ? "play" : seed.summary.state);
                  setDirection(seed.summary.direction);
                }}
              >
                From selected packet
              </button>
            </div>
            <div className="rule-preview-panes">
              <label className="rule-preview-pane">
                Input
                <textarea className="hex-editor" spellCheck={false} value={sample} onChange={(event) => setSample(event.target.value)} />
              </label>
              <label className="rule-preview-pane">
                Result
                <textarea className="hex-editor" spellCheck={false} readOnly value={preview.error ?? preview.hex} />
              </label>
            </div>
          </div>
        </section>
      ) : (
        <EmptyState title="No rule selected" detail="Create a rule to rewrite matching packets automatically." />
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
        aria-label="Edit kind"
        value={edit.kind}
        onChange={(event) => onChange(blankEdit(event.target.value as PacketEditKind))}
      >
        {EDIT_KINDS.map((kind) => (
          <option key={kind.value} value={kind.value}>{kind.label}</option>
        ))}
      </select>

      {edit.kind === "frame" && (
        <label>Bytes<input className="hex" spellCheck={false} value={edit.bytes} onChange={(event) => onChange({ ...edit, bytes: event.target.value })} placeholder="00 0f" /></label>
      )}

      {edit.kind === "range" && (
        <>
          <label>Offset<input type="number" min={0} value={edit.offset} onChange={(event) => onChange({ ...edit, offset: Number(event.target.value) || 0 })} /></label>
          <label>Length<input type="number" min={0} value={edit.length} onChange={(event) => onChange({ ...edit, length: Number(event.target.value) || 0 })} /></label>
          <label>Bytes<input className="hex" spellCheck={false} value={edit.bytes} onChange={(event) => onChange({ ...edit, bytes: event.target.value })} placeholder="ca fe" /></label>
        </>
      )}

      {edit.kind === "bytes" && (
        <>
          <label>Find<input className="hex" spellCheck={false} value={edit.find} onChange={(event) => onChange({ ...edit, find: event.target.value })} placeholder="de ad" /></label>
          <label>Replace<input className="hex" spellCheck={false} value={edit.replace} onChange={(event) => onChange({ ...edit, replace: event.target.value })} placeholder="be ef" /></label>
          <Toggle label="All" checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
        </>
      )}

      {edit.kind === "text" && (
        <>
          <label>Find<input value={edit.find} onChange={(event) => onChange({ ...edit, find: event.target.value })} /></label>
          <label>Replace<input value={edit.replace} onChange={(event) => onChange({ ...edit, replace: event.target.value })} /></label>
          <Toggle label="All" checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
          <Toggle label="Aa" checked={!edit.case_insensitive} onChange={(sensitive) => onChange({ ...edit, case_insensitive: !sensitive })} />
        </>
      )}

      {edit.kind === "regex" && (
        <>
          <label>Pattern<input className="hex" spellCheck={false} value={edit.pattern} onChange={(event) => onChange({ ...edit, pattern: event.target.value })} placeholder="player_?name" /></label>
          <label>Replace<input value={edit.replace} onChange={(event) => onChange({ ...edit, replace: event.target.value })} placeholder="$0" /></label>
          <Toggle label="All" checked={edit.all} onChange={(all) => onChange({ ...edit, all })} />
        </>
      )}

      {edit.kind === "field" && (
        <>
          <label>Field<input value={edit.name} onChange={(event) => onChange({ ...edit, name: event.target.value })} placeholder="server address" /></label>
          <label>Value<input value={edit.value} onChange={(event) => onChange({ ...edit, value: event.target.value })} /></label>
        </>
      )}

      {edit.kind === "field_replace" && (
        <>
          <label>Field<input value={edit.name} onChange={(event) => onChange({ ...edit, name: event.target.value })} placeholder="message" /></label>
          <label>Find<input value={edit.find} onChange={(event) => onChange({ ...edit, find: event.target.value })} /></label>
          <label>Replace<input value={edit.replace} onChange={(event) => onChange({ ...edit, replace: event.target.value })} /></label>
          <Toggle label="Regex" checked={edit.regex} onChange={(regex) => onChange({ ...edit, regex })} />
        </>
      )}

      <button className="icon-button" aria-label="Remove edit" onClick={onRemove}><Trash2 size={14} /></button>
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
