import { Filter, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type {
  ContentSearchMode,
  ContentSearchScope,
  Direction,
  Disposition,
  PacketFilter,
  ProtocolState,
  TrafficSource,
} from "../domain/types";
import { EMPTY_FILTER } from "../domain/types";
import { desktop } from "../lib/desktop";
import { Modal } from "./Modal";

const SOURCES: Array<{ value: TrafficSource; label: string }> = [
  { value: "minecraft", label: "Decrypt proxy" },
  { value: "side_channel", label: "Passive capture" },
];

const DIRECTIONS: Array<{ value: Direction; label: string }> = [
  { value: "client_to_server", label: "C → S" },
  { value: "server_to_client", label: "S → C" },
];

const STATES: ProtocolState[] = [
  "handshake",
  "status",
  "login",
  "configuration",
  "play",
  "opaque",
  "closed",
];

const CONTENT_MODES: Array<{ value: ContentSearchMode; label: string }> = [
  { value: "text", label: "Text" },
  { value: "hex", label: "Hex" },
  { value: "regex", label: "Regex" },
];

/** One term per line; the hex placeholder doubles as the range syntax. */
const CONTENT_PLACEHOLDER: Record<ContentSearchMode, string> = {
  text: "minecraft:brand\nvanilla",
  hex: "0a 00 09\n0c-0f",
  regex: "player_?name\nUUID",
};

const CONTENT_SCOPES: Array<{ value: ContentSearchScope; label: string; title: string }> = [
  { value: "contains", label: "Contains", title: "The term appears anywhere in the payload" },
  { value: "equals", label: "Is exactly", title: "The payload is the term and nothing else" },
  { value: "prefix", label: "Starts with", title: "The payload begins with the term" },
  { value: "suffix", label: "Ends with", title: "The payload ends with the term" },
];

const DISPOSITIONS: Disposition[] = [
  "forwarded",
  "dropped",
  "edited",
  "delayed",
  "replayed",
  "observed",
  "failed",
];

/**
 * The history filter: a one-line summary in the toolbar that opens the full set
 * of controls in a modal.
 *
 * Selections are applied as the operator makes them rather than behind an
 * "apply" button — every control maps to a database-side clause, so a change is
 * a new bounded query rather than a re-render of everything loaded.
 */
export function PacketFilterBar({
  filter,
  onChange,
  loaded,
  onError,
}: {
  filter: PacketFilter;
  onChange: (filter: PacketFilter) => void;
  /** Rows currently loaded, shown beside the summary. */
  loaded: number;
  onError: (error: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [expressionText, setExpressionText] = useState(filter.expression);
  const [expressionError, setExpressionError] = useState<string | null>(null);
  const validation = useRef(0);

  // The expression is only committed once it parses, so a half-typed predicate
  // never blanks the table.
  useEffect(() => {
    const text = expressionText.trim();
    if (text === filter.expression) return undefined;
    const requestId = ++validation.current;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          if (text) await desktop.filterValidate(text);
          if (requestId !== validation.current) return;
          setExpressionError(null);
          onChange({ ...filter, expression: text });
        } catch (reason) {
          if (requestId === validation.current) {
            setExpressionError(reason instanceof Error ? reason.message : String(reason));
          }
        }
      })();
    }, 350);
    return () => window.clearTimeout(timer);
  }, [expressionText, filter, onChange]);

  const summary = useMemo(() => describe(filter), [filter]);
  const active = summary !== null;

  function toggle<T>(list: T[], value: T): T[] {
    return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
  }

  function clearAll() {
    setExpressionText("");
    setExpressionError(null);
    onChange({ ...EMPTY_FILTER });
  }

  return (
    <section className={`packet-filter ${active ? "active" : ""}`} aria-label="Packet filter">
      <div className="filter-summary">
        <button className="filter-toggle" onClick={() => setOpen(true)} aria-haspopup="dialog">
          <Filter size={13} aria-hidden="true" />
          <span>{summary ?? "All packets"}</span>
        </button>
        <label className="history-search filter-quick-search">
          <Search size={14} aria-hidden="true" />
          <input
            value={filter.search}
            onChange={(event) => onChange({ ...filter, search: event.target.value })}
            placeholder="Search"
            aria-label="Search packet history"
          />
        </label>
        <span className="filter-count">{loaded.toLocaleString()} loaded</span>
        {active && (
          <button className="link-button" onClick={clearAll}>
            <X size={12} aria-hidden="true" /> Clear
          </button>
        )}
      </div>

      {open && (
        <Modal
          title="Filter"
          onClose={() => setOpen(false)}
          actions={
            <>
              <button className="button" onClick={clearAll} disabled={!active}>
                Clear all
              </button>
              <button className="button primary" onClick={() => setOpen(false)}>
                Done
              </button>
            </>
          }
        >
          <div className="filter-panel">
            <CheckGroup
              title="Traffic source"
              options={SOURCES.map((entry) => ({ ...entry, checked: filter.sources.includes(entry.value) }))}
              onToggle={(value) => onChange({ ...filter, sources: toggle(filter.sources, value) })}
              onAll={(all) => onChange({ ...filter, sources: all ? SOURCES.map((entry) => entry.value) : [] })}
            />
            <CheckGroup
              title="Direction"
              options={DIRECTIONS.map((entry) => ({ ...entry, checked: filter.directions.includes(entry.value) }))}
              onToggle={(value) => onChange({ ...filter, directions: toggle(filter.directions, value) })}
              onAll={(all) => onChange({ ...filter, directions: all ? DIRECTIONS.map((entry) => entry.value) : [] })}
            />
            <CheckGroup
              title="Protocol phase"
              options={STATES.map((value) => ({ value, label: value, checked: filter.states.includes(value) }))}
              onToggle={(value) => onChange({ ...filter, states: toggle(filter.states, value) })}
              onAll={(all) => onChange({ ...filter, states: all ? [...STATES] : [] })}
            />
            <CheckGroup
              title="Result"
              options={DISPOSITIONS.map((value) => ({ value, label: value, checked: filter.dispositions.includes(value) }))}
              onToggle={(value) => onChange({ ...filter, dispositions: toggle(filter.dispositions, value) })}
              onAll={(all) => onChange({ ...filter, dispositions: all ? [...DISPOSITIONS] : [] })}
            />

            <fieldset className="filter-group">
              <legend>Search term</legend>
              <input
                value={filter.search}
                onChange={(event) => onChange({ ...filter, search: event.target.value })}
                placeholder="name, channel, loader, or packet ID"
                aria-label="Filter by search term"
              />
              <div className="filter-switches">
                <Switch
                  label="Regex"
                  checked={filter.searchRegex}
                  onChange={(checked) => onChange({ ...filter, searchRegex: checked })}
                />
                <Switch
                  label="Case sensitive"
                  checked={filter.searchCaseSensitive}
                  onChange={(checked) => onChange({ ...filter, searchCaseSensitive: checked })}
                />
                <Switch
                  label="Negative"
                  checked={filter.searchNegate}
                  onChange={(checked) => onChange({ ...filter, searchNegate: checked })}
                />
              </div>
            </fieldset>

            <fieldset className="filter-group filter-content">
              <legend>Packet content</legend>
              <div className="segmented content-modes" aria-label="Payload search mode">
                {CONTENT_MODES.map((mode) => (
                  <button
                    key={mode.value}
                    className={filter.contentMode === mode.value ? "active" : ""}
                    onClick={() => onChange({ ...filter, contentMode: mode.value })}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
              <div className="segmented content-scopes" aria-label="How much of the payload must match">
                {CONTENT_SCOPES.map((scope) => (
                  <button
                    key={scope.value}
                    className={filter.contentScope === scope.value ? "active" : ""}
                    title={scope.title}
                    onClick={() => onChange({ ...filter, contentScope: scope.value })}
                  >
                    {scope.label}
                  </button>
                ))}
              </div>
              <textarea
                className="content-terms"
                rows={3}
                value={filter.content}
                onChange={(event) => onChange({ ...filter, content: event.target.value })}
                placeholder={CONTENT_PLACEHOLDER[filter.contentMode]}
                aria-label="Search packet payload bytes, one term per line"
                spellCheck={false}
              />
              <div className="filter-switches">
                <Switch
                  label="Case sensitive"
                  checked={filter.contentCaseSensitive}
                  onChange={(checked) => onChange({ ...filter, contentCaseSensitive: checked })}
                />
                <Switch
                  label="Negative"
                  checked={filter.contentNegate}
                  onChange={(checked) => onChange({ ...filter, contentNegate: checked })}
                />
              </div>
            </fieldset>

            <fieldset className="filter-group">
              <legend>Packet name</legend>
              <label className="filter-field">
                Show only
                <input
                  value={filter.includeNames.join(", ")}
                  onChange={(event) => onChange({ ...filter, includeNames: splitList(event.target.value) })}
                  placeholder="chat, custom_payload"
                />
              </label>
              <label className="filter-field">
                Hide
                <input
                  value={filter.excludeNames.join(", ")}
                  onChange={(event) => onChange({ ...filter, excludeNames: splitList(event.target.value) })}
                  placeholder="keep_alive, chunk"
                />
              </label>
            </fieldset>

            <fieldset className="filter-group">
              <legend>Payload size</legend>
              <div className="filter-range">
                <label className="filter-field">
                  Min
                  <input
                    type="number"
                    min={0}
                    value={filter.minSize ?? ""}
                    onChange={(event) => onChange({ ...filter, minSize: parseSize(event.target.value) })}
                    placeholder="0"
                  />
                </label>
                <label className="filter-field">
                  Max
                  <input
                    type="number"
                    min={0}
                    value={filter.maxSize ?? ""}
                    onChange={(event) => onChange({ ...filter, maxSize: parseSize(event.target.value) })}
                    placeholder="any"
                  />
                </label>
                <span className="filter-hint">bytes</span>
              </div>
            </fieldset>

            <fieldset className="filter-group filter-expression">
              <legend>Expression</legend>
              <input
                value={expressionText}
                onChange={(event) => setExpressionText(event.target.value)}
                placeholder="state == play && size > 256 && name ~ chat"
                aria-label="Filter expression"
                aria-invalid={expressionError !== null}
                spellCheck={false}
              />
              {expressionError && (
                <p className="filter-error" role="alert">{expressionError}</p>
              )}
              <ExpressionExamples
                onPick={(text) => {
                  setExpressionText(text);
                  setExpressionError(null);
                }}
                onError={onError}
              />
            </fieldset>
          </div>
        </Modal>
      )}
    </section>
  );
}

function CheckGroup<T extends string>({
  title,
  options,
  onToggle,
  onAll,
}: {
  title: string;
  options: Array<{ value: T; label: string; checked: boolean }>;
  onToggle: (value: T) => void;
  onAll: (all: boolean) => void;
}) {
  const none = options.every((option) => !option.checked);
  return (
    <fieldset className="filter-group">
      <legend>{title}</legend>
      <div className="filter-checks">
        {options.map((option) => (
          <label key={option.value} className={option.checked ? "checked" : ""}>
            <input
              type="checkbox"
              checked={option.checked}
              onChange={() => onToggle(option.value)}
            />
            {option.label}
          </label>
        ))}
      </div>
      <div className="filter-group-actions">
        <button className="link-button" onClick={() => onAll(true)}>All</button>
        <button className="link-button" onClick={() => onAll(false)} disabled={none}>
          Clear
        </button>
      </div>
    </fieldset>
  );
}

function Switch({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={checked ? "checked" : ""}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

/** A few starting points, drawn from what the backend actually accepts. */
function ExpressionExamples({
  onPick,
  onError,
}: {
  onPick: (text: string) => void;
  onError: (error: string) => void;
}) {
  const [examples, setExamples] = useState<string[]>([]);

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    void desktop
      .filterVocabulary()
      .then((vocabulary) => {
        setExamples([
          `state == ${vocabulary.states.includes("play") ? "play" : vocabulary.states[0]}`,
          "size > 1024",
          "name ~ chat",
          `source == ${vocabulary.sources[0] ?? "minecraft"} && direction == client_to_server`,
        ]);
      })
      .catch((reason) => onError(reason instanceof Error ? reason.message : String(reason)));
  }, [onError]);

  if (examples.length === 0) return null;
  return (
    <div className="filter-examples">
      {examples.map((example) => (
        <button key={example} className="filter-example" onClick={() => onPick(example)}>
          {example}
        </button>
      ))}
    </div>
  );
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function parseSize(value: string): number | null {
  if (value.trim() === "") return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

/** How the summary reads a payload search: [plain, negated] per scope. */
const RELATION: Record<ContentSearchScope, [string, string]> = {
  contains: ["with", "without"],
  equals: ["is", "is not"],
  prefix: ["starts with", "not starting with"],
  suffix: ["ends with", "not ending with"],
};

/** A short description of what the filter narrows, or null when it narrows nothing. */
function describe(filter: PacketFilter): string | null {
  const parts: string[] = [];
  if (filter.sources.length > 0) parts.push(filter.sources.length === 1 ? label(filter.sources[0]) : `${filter.sources.length} sources`);
  if (filter.directions.length === 1) parts.push(filter.directions[0] === "client_to_server" ? "C → S" : "S → C");
  if (filter.states.length > 0) parts.push(filter.states.length === 1 ? filter.states[0] : `${filter.states.length} phases`);
  if (filter.dispositions.length > 0) {
    parts.push(filter.dispositions.length === 1 ? filter.dispositions[0] : `${filter.dispositions.length} results`);
  }
  if (filter.search.trim()) {
    const flags = [
      filter.searchRegex ? "regex" : null,
      filter.searchCaseSensitive ? "case" : null,
    ].filter(Boolean);
    const suffix = flags.length > 0 ? ` (${flags.join(", ")})` : "";
    parts.push(`${filter.searchNegate ? "not " : ""}“${filter.search.trim()}”${suffix}`);
  }
  if (filter.includeNames.length > 0) parts.push(`only ${filter.includeNames.length} name(s)`);
  if (filter.excludeNames.length > 0) parts.push(`hiding ${filter.excludeNames.length} name(s)`);
  if (filter.minSize !== null || filter.maxSize !== null) {
    parts.push(`${filter.minSize ?? 0}–${filter.maxSize ?? "∞"} B`);
  }
  const terms = filter.content.split("\n").map((term) => term.trim()).filter(Boolean);
  if (terms.length > 0) {
    const mode = filter.contentMode === "text" ? "" : ` ${filter.contentMode}`;
    const relation = RELATION[filter.contentScope][filter.contentNegate ? 1 : 0];
    const subject = terms.length === 1 ? `“${terms[0]}”` : `any of ${terms.length}`;
    parts.push(`payload${mode} ${relation} ${subject}`);
  }
  if (filter.expression.trim()) parts.push(filter.expression.trim());
  return parts.length > 0 ? parts.join(" · ") : null;
}

function label(source: TrafficSource): string {
  return source === "minecraft" ? "Decrypt proxy" : "Passive capture";
}
