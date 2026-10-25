import { Bookmark, Filter, Search, X } from "lucide-react";
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
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { ExpressionInput } from "./ExpressionInput";
import { Modal } from "./Modal";
import { SavedFilters } from "./SavedFilters";

const SOURCES: Array<{ value: TrafficSource; labelKey: Parameters<typeof t>[0] }> = [
  { value: "minecraft", labelKey: "filter.source.minecraft" },
  { value: "side_channel", labelKey: "filter.source.side_channel" },
];

const DIRECTIONS: Array<{ value: Direction; label: string }> = [
  { value: "client_to_server", label: "C → S" },
  { value: "server_to_client", label: "S → C" },
];

const STATES: ProtocolState[] = ["handshake", "status", "login", "configuration", "play", "opaque", "closed"];

const CONTENT_MODES: Array<{ value: ContentSearchMode; labelKey: Parameters<typeof t>[0] }> = [
  { value: "text", labelKey: "filter.content.mode.text" },
  { value: "hex", labelKey: "filter.content.mode.hex" },
  { value: "regex", labelKey: "filter.content.mode.regex" },
];

/** One term per line; the hex placeholder doubles as the range syntax. */
const CONTENT_PLACEHOLDER: Record<ContentSearchMode, string> = {
  text: "minecraft:brand\nvanilla",
  hex: "0a 00 09\n0c-0f",
  regex: "player_?name\nUUID",
};

const CONTENT_SCOPES: Array<{
  value: ContentSearchScope;
  labelKey: Parameters<typeof t>[0];
  titleKey: Parameters<typeof t>[0];
}> = [
  {
    value: "contains",
    labelKey: "filter.content.scope.contains",
    titleKey: "filter.content.scope.contains.title",
  },
  {
    value: "equals",
    labelKey: "filter.content.scope.equals",
    titleKey: "filter.content.scope.equals.title",
  },
  {
    value: "prefix",
    labelKey: "filter.content.scope.prefix",
    titleKey: "filter.content.scope.prefix.title",
  },
  {
    value: "suffix",
    labelKey: "filter.content.scope.suffix",
    titleKey: "filter.content.scope.suffix.title",
  },
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
  onNotice,
}: {
  filter: PacketFilter;
  onChange: (filter: PacketFilter) => void;
  /** Rows currently loaded, shown beside the summary. */
  loaded: number;
  onError: (error: string) => void;
  onNotice?: (notice: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [expressionText, setExpressionText] = useState(filter.expression);
  const [expressionError, setExpressionError] = useState<string | null>(null);
  /**
   * The payload terms being typed. A payload search decompresses and scans
   * every candidate row, so it runs when applied rather than per keystroke.
   */
  const [contentDraft, setContentDraft] = useState(filter.content);
  const validation = useRef(0);

  // Follow changes made elsewhere — Clear all, or a filter applied from a menu.
  useEffect(() => setContentDraft(filter.content), [filter.content]);
  useEffect(
    () =>
      setExpressionText((current) => (current.trim() === filter.expression ? current : filter.expression)),
    [filter.expression],
  );
  const contentPending = contentDraft !== filter.content;
  const applyContent = () => onChange({ ...filter, content: contentDraft });

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
    setContentDraft("");
    onChange({ ...EMPTY_FILTER });
  }

  return (
    <section className={`packet-filter ${active ? "active" : ""}`} aria-label={t("filter.toggle")}>
      <div className="filter-summary">
        <button type="button" className="filter-toggle" onClick={() => setOpen(true)} aria-haspopup="dialog">
          <Filter size={13} aria-hidden="true" />
          <span>{summary ?? t("filter.all-packets")}</span>
        </button>
        <label className="history-search filter-quick-search">
          <Search size={14} aria-hidden="true" />
          <input
            value={filter.search}
            onChange={(event) => onChange({ ...filter, search: event.target.value })}
            placeholder={t("filter.search.placeholder")}
            aria-label={t("filter.search.aria")}
          />
        </label>
        <button
          type="button"
          className={`filter-chip ${filter.bookmarked ? "on" : ""}`}
          aria-pressed={filter.bookmarked}
          title={t("filter.bookmarked.title")}
          onClick={() => onChange({ ...filter, bookmarked: !filter.bookmarked })}
        >
          <Bookmark size={12} aria-hidden="true" /> {t("filter.bookmarked")}
        </button>
        <span className="filter-count">{t("filter.loaded", { count: loaded.toLocaleString() })}</span>
        {desktop.isAvailable() && (
          <SavedFilters filter={filter} onApply={onChange} onError={onError} onNotice={onNotice} />
        )}
        {active && (
          <button type="button" className="link-button" onClick={clearAll}>
            <X size={12} aria-hidden="true" /> {t("filter.clear")}
          </button>
        )}
      </div>

      {open && (
        <Modal
          title={t("filter.title")}
          onClose={() => setOpen(false)}
          actions={
            <>
              <button type="button" className="button" onClick={clearAll} disabled={!active}>
                {t("filter.clear-all")}
              </button>
              <button type="button" className="button primary" onClick={() => setOpen(false)}>
                {t("filter.done")}
              </button>
            </>
          }
        >
          <div className="filter-panel">
            <CheckGroup
              title={t("filter.group.source")}
              options={SOURCES.map((entry) => ({
                ...entry,
                label: t(entry.labelKey),
                checked: filter.sources.includes(entry.value),
              }))}
              onToggle={(value) => onChange({ ...filter, sources: toggle(filter.sources, value) })}
              onAll={(all) =>
                onChange({ ...filter, sources: all ? SOURCES.map((entry) => entry.value) : [] })
              }
            />
            <CheckGroup
              title={t("filter.group.direction")}
              options={DIRECTIONS.map((entry) => ({
                ...entry,
                checked: filter.directions.includes(entry.value),
              }))}
              onToggle={(value) => onChange({ ...filter, directions: toggle(filter.directions, value) })}
              onAll={(all) =>
                onChange({ ...filter, directions: all ? DIRECTIONS.map((entry) => entry.value) : [] })
              }
            />
            <CheckGroup
              title={t("filter.group.phase")}
              options={STATES.map((value) => ({
                value,
                label: value,
                checked: filter.states.includes(value),
              }))}
              onToggle={(value) => onChange({ ...filter, states: toggle(filter.states, value) })}
              onAll={(all) => onChange({ ...filter, states: all ? [...STATES] : [] })}
            />
            <CheckGroup
              title={t("filter.group.result")}
              options={DISPOSITIONS.map((value) => ({
                value,
                label: value,
                checked: filter.dispositions.includes(value),
              }))}
              onToggle={(value) => onChange({ ...filter, dispositions: toggle(filter.dispositions, value) })}
              onAll={(all) => onChange({ ...filter, dispositions: all ? [...DISPOSITIONS] : [] })}
            />

            <fieldset className="filter-group">
              <legend>{t("filter.group.search-term")}</legend>
              <input
                value={filter.search}
                onChange={(event) => onChange({ ...filter, search: event.target.value })}
                placeholder={t("filter.search-term.placeholder")}
                aria-label={t("filter.search-term.aria")}
              />
              <div className="filter-switches">
                <Switch
                  label={t("filter.regex")}
                  checked={filter.searchRegex}
                  onChange={(checked) => onChange({ ...filter, searchRegex: checked })}
                />
                <Switch
                  label={t("filter.case-sensitive")}
                  checked={filter.searchCaseSensitive}
                  onChange={(checked) => onChange({ ...filter, searchCaseSensitive: checked })}
                />
                <Switch
                  label={t("filter.negative")}
                  checked={filter.searchNegate}
                  onChange={(checked) => onChange({ ...filter, searchNegate: checked })}
                />
              </div>
            </fieldset>

            <fieldset className="filter-group filter-content">
              <legend>{t("filter.group.content")}</legend>
              <div className="segmented content-modes" aria-label={t("filter.content.mode.aria")}>
                {CONTENT_MODES.map((mode) => (
                  <button
                    type="button"
                    key={mode.value}
                    className={filter.contentMode === mode.value ? "active" : ""}
                    onClick={() => onChange({ ...filter, contentMode: mode.value })}
                  >
                    {t(mode.labelKey)}
                  </button>
                ))}
              </div>
              <div className="segmented content-scopes" aria-label={t("filter.content.scope.aria")}>
                {CONTENT_SCOPES.map((scope) => (
                  <button
                    type="button"
                    key={scope.value}
                    className={filter.contentScope === scope.value ? "active" : ""}
                    title={t(scope.titleKey)}
                    onClick={() => onChange({ ...filter, contentScope: scope.value })}
                  >
                    {t(scope.labelKey)}
                  </button>
                ))}
              </div>
              <textarea
                className="content-terms"
                rows={3}
                value={contentDraft}
                onChange={(event) => setContentDraft(event.target.value)}
                onKeyDown={(event) => {
                  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                    event.preventDefault();
                    applyContent();
                  }
                }}
                placeholder={CONTENT_PLACEHOLDER[filter.contentMode]}
                aria-label={t("filter.content.terms.aria")}
                spellCheck={false}
              />
              <div className="filter-apply">
                <button type="button" className="button" disabled={!contentPending} onClick={applyContent}>
                  {t("filter.content.apply")}
                </button>
                <span className="filter-hint">
                  {contentPending ? t("filter.content.pending") : t("filter.content.apply.hint")}
                </span>
              </div>
              <div className="filter-switches">
                <Switch
                  label={t("filter.case-sensitive")}
                  checked={filter.contentCaseSensitive}
                  onChange={(checked) => onChange({ ...filter, contentCaseSensitive: checked })}
                />
                <Switch
                  label={t("filter.negative")}
                  checked={filter.contentNegate}
                  onChange={(checked) => onChange({ ...filter, contentNegate: checked })}
                />
              </div>
            </fieldset>

            <fieldset className="filter-group">
              <legend>{t("filter.group.packet-name")}</legend>
              <label className="filter-field">
                {t("filter.show-only")}
                <NameListInput
                  names={filter.includeNames}
                  onChange={(includeNames) => onChange({ ...filter, includeNames })}
                  placeholder="chat, custom_payload"
                />
              </label>
              <label className="filter-field">
                {t("filter.hide")}
                <NameListInput
                  names={filter.excludeNames}
                  onChange={(excludeNames) => onChange({ ...filter, excludeNames })}
                  placeholder="keep_alive, chunk"
                />
              </label>
            </fieldset>

            <fieldset className="filter-group">
              <legend>{t("filter.group.size")}</legend>
              <div className="filter-range">
                <label className="filter-field">
                  {t("filter.size.min")}
                  <input
                    type="number"
                    min={0}
                    value={filter.minSize ?? ""}
                    onChange={(event) => onChange({ ...filter, minSize: parseSize(event.target.value) })}
                    placeholder="0"
                  />
                </label>
                <label className="filter-field">
                  {t("filter.size.max")}
                  <input
                    type="number"
                    min={0}
                    value={filter.maxSize ?? ""}
                    onChange={(event) => onChange({ ...filter, maxSize: parseSize(event.target.value) })}
                    placeholder={t("filter.size.max.any")}
                  />
                </label>
                <span className="filter-hint">{t("filter.size.unit")}</span>
              </div>
            </fieldset>

            <fieldset className="filter-group filter-expression">
              <legend>{t("filter.group.expression")}</legend>
              <ExpressionInput
                value={expressionText}
                onChange={setExpressionText}
                placeholder="state == play && size > 256 && name ~ chat"
                ariaLabel={t("filter.expression.aria")}
                invalid={expressionError !== null}
              />
              {expressionError && (
                <p className="filter-error" role="alert">
                  {expressionError}
                </p>
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
            <input type="checkbox" checked={option.checked} onChange={() => onToggle(option.value)} />
            {option.label}
          </label>
        ))}
      </div>
      <div className="filter-group-actions">
        <button type="button" className="link-button" onClick={() => onAll(true)}>
          {t("form.all")}
        </button>
        <button type="button" className="link-button" onClick={() => onAll(false)} disabled={none}>
          {t("filter.clear")}
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
        <button type="button" key={example} className="filter-example" onClick={() => onPick(example)}>
          {example}
        </button>
      ))}
    </div>
  );
}

/**
 * A comma-separated list that keeps exactly what was typed.
 *
 * The list used to be re-rendered from the parsed names on every keystroke,
 * so a trailing comma vanished the moment it was typed and a second name could
 * only be pasted.
 */
function NameListInput({
  names,
  onChange,
  placeholder,
}: {
  names: string[];
  onChange: (names: string[]) => void;
  placeholder: string;
}) {
  const [draft, setDraft] = useState(names.join(", "));
  const joined = names.join("\u0000");
  // Follow outside changes only when they mean something different from the draft.
  useEffect(() => {
    setDraft((current) => (splitList(current).join("\u0000") === joined ? current : names.join(", ")));
  }, [joined]);
  return (
    <input
      value={draft}
      onChange={(event) => {
        setDraft(event.target.value);
        const next = splitList(event.target.value);
        if (next.join("\u0000") !== joined) onChange(next);
      }}
      placeholder={placeholder}
    />
  );
}

export function splitList(value: string): string[] {
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
const RELATION: Record<ContentSearchScope, [Parameters<typeof t>[0], Parameters<typeof t>[0]]> = {
  contains: ["filter.summary.payload-with", "filter.summary.without"],
  equals: ["filter.summary.is", "filter.summary.is-not"],
  prefix: ["filter.summary.starts-with", "filter.summary.not-starting-with"],
  suffix: ["filter.summary.ends-with", "filter.summary.not-ending-with"],
};

/** A short description of what the filter narrows, or null when it narrows nothing. */
export function describe(filter: PacketFilter): string | null {
  const parts: string[] = [];
  const source = filter.sources.length === 1 ? filter.sources[0] : undefined;
  if (filter.sources.length > 0)
    parts.push(source ? label(source) : t("filter.summary.sources", { count: filter.sources.length }));
  const direction = filter.directions.length === 1 ? filter.directions[0] : undefined;
  if (direction) parts.push(direction === "client_to_server" ? "C → S" : "S → C");
  const state = filter.states.length === 1 ? filter.states[0] : undefined;
  if (filter.states.length > 0)
    parts.push(state ?? t("filter.summary.phases", { count: filter.states.length }));
  if (filter.dispositions.length > 0) {
    const disposition = filter.dispositions.length === 1 ? filter.dispositions[0] : undefined;
    parts.push(disposition ?? t("filter.summary.results", { count: filter.dispositions.length }));
  }
  if (filter.search.trim()) {
    const flags = [
      filter.searchRegex ? t("filter.regex") : null,
      filter.searchCaseSensitive ? t("filter.summary.case-flag") : null,
    ].filter(Boolean);
    const suffix = flags.length > 0 ? ` (${flags.join(", ")})` : "";
    parts.push(`${filter.searchNegate ? t("filter.summary.not") : ""}“${filter.search.trim()}”${suffix}`);
  }
  if (filter.includeNames.length > 0)
    parts.push(t("filter.summary.only-names", { count: filter.includeNames.length }));
  if (filter.excludeNames.length > 0)
    parts.push(t("filter.summary.hiding-names", { count: filter.excludeNames.length }));
  if (filter.minSize !== null || filter.maxSize !== null) {
    parts.push(`${filter.minSize ?? 0}–${filter.maxSize ?? "∞"} B`);
  }
  const terms = filter.content
    .split("\n")
    .map((term) => term.trim())
    .filter(Boolean);
  if (terms.length > 0) {
    const mode = filter.contentMode === "text" ? "" : ` ${filter.contentMode}`;
    const relation = RELATION[filter.contentScope][filter.contentNegate ? 1 : 0];
    const subject =
      terms.length === 1 ? `“${terms[0]}”` : t("filter.summary.any-of", { count: terms.length });
    parts.push(`${t("filter.summary.payload")}${mode} ${t(relation)} ${subject}`);
  }
  if (filter.expression.trim()) parts.push(filter.expression.trim());
  if (filter.bookmarked) parts.push(t("filter.summary.bookmarked"));
  return parts.length > 0 ? parts.join(" · ") : null;
}

function label(source: TrafficSource): string {
  return t(source === "minecraft" ? "filter.source.minecraft" : "filter.source.side_channel");
}
