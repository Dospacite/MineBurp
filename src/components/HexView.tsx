import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Loader2, Search } from "lucide-react";
import {
  type FormEvent,
  type KeyboardEvent,
  type MouseEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

import type { ByteWindow } from "../domain/types";
import { t } from "../i18n";
import { base64ToBytes, parseHex } from "../lib/desktop";

/**
 * Bytes rendered at once.
 *
 * A hex dump is ~75 characters per 16 bytes, so a 1 MiB packet is a ~5 million
 * character string. Building and laying that out at once is what froze the
 * inspector; 4 KiB is a few hundred lines, which the browser handles
 * instantly, and the rest is a page away.
 */
export const HEX_PAGE_BYTES = 4 * 1024;
const COLUMNS = 16;
/** Search never reads more of a payload than this. */
export const SEARCH_LIMIT = 8 * 1024 * 1024;
const MATCH_LIMIT = 10_000;

/** A span of a payload, in absolute byte offsets. */
export interface ByteRange {
  offset: number;
  length: number;
}

export function HexView({
  sourceKey,
  total,
  initial,
  loadWindow,
  loadAll,
  onBytesChange,
  highlight,
  onSelectionChange,
  emptyLabel,
}: {
  /**
   * Identifies the payload being shown. The view resets on this rather than on
   * the `initial` object's identity, which callers recreate on every render.
   */
  sourceKey: string | number;
  /** Total payload size, which may exceed what is loaded. */
  total: number;
  /** The window already fetched alongside the packet metadata. */
  initial: { offset: number; bytes: Uint8Array } | null;
  /** Fetches another window; null means the payload is no longer available. */
  loadWindow: (offset: number, limit: number) => Promise<ByteWindow | null>;
  /** Reads up to `limit` bytes from the start of the payload, for search. */
  loadAll?: (limit: number) => Promise<Uint8Array>;
  /**
   * Reports the window currently on screen, so a caller's header can act on
   * exactly the bytes the operator is looking at.
   */
  onBytesChange?: (bytes: Uint8Array | null, offset: number) => void;
  /** Bytes to mark — a decoded field the operator picked elsewhere. */
  highlight?: ByteRange | null;
  /** The operator's own byte selection, as it changes. */
  onSelectionChange?: (range: ByteRange | null) => void;
  emptyLabel?: string;
}) {
  const [offset, setOffset] = useState(initial?.offset ?? 0);
  const [bytes, setBytes] = useState<Uint8Array | null>(
    initial ? initial.bytes.slice(0, HEX_PAGE_BYTES) : null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [anchor, setAnchor] = useState<number | null>(null);
  const [focus, setFocus] = useState<number | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [mode, setMode] = useState<"hex" | "text">("hex");
  const [matches, setMatches] = useState<number[]>([]);
  const [matchLength, setMatchLength] = useState(0);
  const [matchIndex, setMatchIndex] = useState(-1);
  const [searchNote, setSearchNote] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);
  const [gotoText, setGotoText] = useState("");
  const seed = useRef(initial);
  seed.current = initial;
  /** Bumped by every page load and payload change; older loads are discarded. */
  const request = useRef(0);
  const grid = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);

  // A new payload resets the view to the window that arrived with it.
  useEffect(() => {
    void sourceKey;
    request.current++;
    setOffset(seed.current?.offset ?? 0);
    setBytes(seed.current ? seed.current.bytes.slice(0, HEX_PAGE_BYTES) : null);
    setError(null);
    setLoading(false);
    setAnchor(null);
    setFocus(null);
    setMatches([]);
    setMatchIndex(-1);
    setSearchNote(null);
  }, [sourceKey]);

  useEffect(() => {
    onBytesChange?.(bytes, offset);
  }, [bytes, offset, onBytesChange]);

  const selection: ByteRange | null =
    anchor === null || focus === null
      ? null
      : { offset: Math.min(anchor, focus), length: Math.abs(anchor - focus) + 1 };
  const selectionKey = selection ? `${selection.offset}:${selection.length}` : "";
  const reportSelection = useRef(onSelectionChange);
  reportSelection.current = onSelectionChange;
  // Keyed on the range's value, not on the object.
  useEffect(() => {
    reportSelection.current?.(selection);
  }, [selectionKey]);

  const pages = Math.max(1, Math.ceil(total / HEX_PAGE_BYTES));
  const page = Math.floor(offset / HEX_PAGE_BYTES);

  const goTo = useCallback(
    async (nextPage: number) => {
      const nextOffset = Math.min(Math.max(0, nextPage), pages - 1) * HEX_PAGE_BYTES;
      const requestId = ++request.current;
      setLoading(true);
      setError(null);
      try {
        const window = await loadWindow(nextOffset, HEX_PAGE_BYTES);
        if (requestId !== request.current) return;
        if (!window) {
          setBytes(null);
          setError(t("hex.gone"));
          return;
        }
        setOffset(window.offset);
        setBytes(base64ToBytes(window.base64));
      } catch (reason) {
        if (requestId === request.current)
          setError(reason instanceof Error ? reason.message : String(reason));
      } finally {
        if (requestId === request.current) setLoading(false);
      }
    },
    [loadWindow, pages],
  );

  /** Pages to `target` when it is not on screen. */
  const reveal = useCallback(
    (target: number) => {
      const shownTo = offset + (bytes?.length ?? 0);
      if (bytes && target >= offset && target < shownTo) return;
      void goTo(Math.floor(target / HEX_PAGE_BYTES));
    },
    [bytes, goTo, offset],
  );

  const highlightOffset = highlight?.offset ?? null;
  // Follows the highlight, not the page.
  useEffect(() => {
    if (highlightOffset !== null) reveal(highlightOffset);
  }, [highlightOffset]);

  // Bring the highlighted or focused byte into view inside the scroll area.
  useLayoutEffect(() => {
    const target = focus ?? highlightOffset;
    if (target === null) return;
    grid.current?.querySelector(`[data-o="${target}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [focus, highlightOffset, bytes]);

  function select(target: number, extend: boolean) {
    const clamped = Math.min(Math.max(0, target), Math.max(0, total - 1));
    if (!extend || anchor === null) setAnchor(clamped);
    setFocus(clamped);
    reveal(clamped);
  }

  function byteAt(event: MouseEvent<HTMLDivElement>): number | null {
    const value = (event.target as HTMLElement).closest<HTMLElement>("[data-o]")?.dataset.o;
    return value === undefined ? null : Number(value);
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const current = focus ?? offset;
    const moves: Record<string, number> = {
      ArrowLeft: -1,
      ArrowRight: 1,
      ArrowUp: -COLUMNS,
      ArrowDown: COLUMNS,
      PageUp: -HEX_PAGE_BYTES,
      PageDown: HEX_PAGE_BYTES,
    };
    const move = moves[event.key];
    if (move !== undefined) {
      event.preventDefault();
      select(current + move, event.shiftKey);
    } else if (event.key === "Home") {
      event.preventDefault();
      select(event.ctrlKey ? 0 : current - (current % COLUMNS), event.shiftKey);
    } else if (event.key === "End") {
      event.preventDefault();
      select(event.ctrlKey ? total - 1 : current - (current % COLUMNS) + COLUMNS - 1, event.shiftKey);
    } else if (event.key === "Escape") {
      setAnchor(null);
      setFocus(null);
    } else if ((event.ctrlKey || event.metaKey) && event.key === "f") {
      event.preventDefault();
      setSearchOpen(true);
    }
  }

  async function runSearch(event?: FormEvent) {
    event?.preventDefault();
    let needle: Uint8Array;
    try {
      needle = mode === "hex" ? parseHex(query) : new TextEncoder().encode(query);
    } catch (reason) {
      setSearchNote(reason instanceof Error ? reason.message : String(reason));
      return;
    }
    if (needle.length === 0) {
      setMatches([]);
      setMatchIndex(-1);
      setSearchNote(null);
      return;
    }
    setSearching(true);
    try {
      const haystack = loadAll
        ? await loadAll(SEARCH_LIMIT)
        : (bytes ?? new Uint8Array()).subarray(0, total - offset);
      const base = loadAll ? 0 : offset;
      const found = findAll(haystack, needle, MATCH_LIMIT).map((at) => at + base);
      setMatches(found);
      setMatchLength(needle.length);
      const covered = base + haystack.length;
      setSearchNote(
        found.length === 0
          ? t("hex.search.none")
          : covered < total
            ? t("hex.search.partial", { count: found.length, searched: covered.toLocaleString() })
            : found.length >= MATCH_LIMIT
              ? t("hex.search.capped", { count: found.length })
              : null,
      );
      const start = focus ?? offset;
      const first = found.findIndex((at) => at >= start);
      const index = found.length === 0 ? -1 : first < 0 ? 0 : first;
      setMatchIndex(index);
      const at = found[index];
      if (at !== undefined) {
        setAnchor(at);
        setFocus(at + needle.length - 1);
        reveal(at);
      }
    } catch (reason) {
      setSearchNote(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setSearching(false);
    }
  }

  function stepMatch(by: 1 | -1) {
    if (matches.length === 0) return;
    const index = (matchIndex + by + matches.length) % matches.length;
    setMatchIndex(index);
    const at = matches[index];
    if (at === undefined) return;
    setAnchor(at);
    setFocus(at + matchLength - 1);
    reveal(at);
  }

  function goToOffset(event: FormEvent) {
    event.preventDefault();
    const target = parseOffset(gotoText);
    if (target === null || target >= total) {
      setSearchNote(t("hex.goto.invalid", { total: total.toLocaleString() }));
      return;
    }
    setSearchNote(null);
    setAnchor(target);
    setFocus(target);
    reveal(target);
  }

  if (total === 0) {
    return <pre className="hex-view">{emptyLabel ?? t("hex.empty")}</pre>;
  }

  const shown = bytes ?? new Uint8Array();
  const marks = pageMarks(offset, shown.length, selection, highlight ?? null, matches, matchLength);

  return (
    <div className="hex-pager">
      <div className="hex-toolbar">
        <form className="hex-goto" onSubmit={goToOffset}>
          <input
            value={gotoText}
            onChange={(event) => setGotoText(event.target.value)}
            placeholder={t("hex.goto.placeholder")}
            aria-label={t("hex.goto")}
            spellCheck={false}
          />
        </form>
        <button
          type="button"
          className={`icon-button ${searchOpen ? "active" : ""}`}
          aria-label={t("hex.search")}
          title={t("hex.search.shortcut")}
          aria-pressed={searchOpen}
          onClick={() => setSearchOpen(!searchOpen)}
        >
          <Search size={13} aria-hidden="true" />
        </button>
        <span className="hex-readout" aria-live="polite">
          {selection ? describeSelection(selection, shown, offset) : t("hex.selection.none")}
        </span>
      </div>
      {searchOpen && (
        <form className="hex-search" onSubmit={(event) => void runSearch(event)}>
          <div className="segmented" aria-label={t("hex.search.mode")}>
            <button type="button" className={mode === "hex" ? "active" : ""} onClick={() => setMode("hex")}>
              {t("filter.content.mode.hex")}
            </button>
            <button type="button" className={mode === "text" ? "active" : ""} onClick={() => setMode("text")}>
              {t("filter.content.mode.text")}
            </button>
          </div>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={mode === "hex" ? "0a 00 09" : "minecraft:brand"}
            aria-label={t("hex.search.term")}
            spellCheck={false}
            // biome-ignore lint/a11y/noAutofocus: the field exists to be typed into the moment it opens.
            autoFocus
          />
          <button type="submit" className="button" disabled={searching}>
            {searching ? <Loader2 className="spin" size={12} aria-hidden="true" /> : t("hex.search.find")}
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={t("hex.search.previous")}
            disabled={matches.length === 0}
            onClick={() => stepMatch(-1)}
          >
            <ChevronUp size={13} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label={t("hex.search.next")}
            disabled={matches.length === 0}
            onClick={() => stepMatch(1)}
          >
            <ChevronDown size={13} aria-hidden="true" />
          </button>
          <span className="hex-search-count">
            {matches.length > 0
              ? t("hex.search.position", { index: matchIndex + 1, count: matches.length })
              : ""}
          </span>
        </form>
      )}
      {searchNote && <p className="hex-note">{searchNote}</p>}
      {bytes ? (
        <div
          className="hex-view hex-grid"
          ref={grid}
          // biome-ignore lint/a11y/noNoninteractiveTabindex: an application region that owns arrow-key byte selection must be focusable.
          tabIndex={0}
          role="application"
          aria-roledescription={t("hex.roledescription")}
          aria-label={t("hex.region")}
          onKeyDown={onKeyDown}
          onMouseDown={(event) => {
            const at = byteAt(event);
            if (at === null) return;
            dragging.current = true;
            select(at, event.shiftKey);
          }}
          onMouseMove={(event) => {
            if (!dragging.current || event.buttons !== 1) return;
            const at = byteAt(event);
            if (at !== null && at !== focus) setFocus(at);
          }}
          onMouseUp={() => {
            dragging.current = false;
          }}
          onMouseLeave={() => {
            dragging.current = false;
          }}
        >
          {rows(shown.length).map((rowStart) => (
            <div className="hex-line" key={offset + rowStart}>
              <span className="hex-address">{(offset + rowStart).toString(16).padStart(6, "0")}</span>
              <span className="hex-bytes">
                {Array.from(shown.subarray(rowStart, rowStart + COLUMNS), (byte, column) => {
                  const at = offset + rowStart + column;
                  return (
                    <span key={at} data-o={at} className={marks(at)}>
                      {byte.toString(16).padStart(2, "0")}
                    </span>
                  );
                })}
              </span>
              <span className="hex-ascii">
                {Array.from(shown.subarray(rowStart, rowStart + COLUMNS), (byte, column) => {
                  const at = offset + rowStart + column;
                  return (
                    <span key={at} data-o={at} className={marks(at)}>
                      {byte >= 32 && byte < 127 ? String.fromCharCode(byte) : "."}
                    </span>
                  );
                })}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <pre className="hex-view">{error ?? t("hex.loading")}</pre>
      )}
      {pages > 1 && (
        <div className="hex-pager-controls">
          <button
            type="button"
            className="icon-button"
            onClick={() => void goTo(page - 1)}
            disabled={page === 0 || loading}
            aria-label={t("hex.previous")}
          >
            <ChevronLeft size={14} />
          </button>
          <span>
            {loading ? <Loader2 className="spin" size={12} /> : null}
            {t("hex.page-status", {
              from: offset.toLocaleString(),
              to: Math.min(total, offset + shown.length).toLocaleString(),
              total: total.toLocaleString(),
            })}
          </span>
          <button
            type="button"
            className="icon-button"
            onClick={() => void goTo(page + 1)}
            disabled={page >= pages - 1 || loading}
            aria-label={t("hex.next")}
          >
            <ChevronRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}

function rows(length: number): number[] {
  const starts: number[] = [];
  for (let at = 0; at < length; at += COLUMNS) starts.push(at);
  return starts;
}

/** Class names per absolute offset for the page on screen. */
function pageMarks(
  pageOffset: number,
  pageLength: number,
  selection: ByteRange | null,
  highlight: ByteRange | null,
  matches: number[],
  matchLength: number,
): (at: number) => string {
  const pageEnd = pageOffset + pageLength;
  const matched = new Set<number>();
  for (const start of matches) {
    if (start >= pageEnd || start + matchLength <= pageOffset) continue;
    for (let at = start; at < start + matchLength; at++) matched.add(at);
  }
  const inside = (range: ByteRange | null, at: number) =>
    range !== null && at >= range.offset && at < range.offset + range.length;
  return (at) => {
    const classes: string[] = [];
    if (inside(highlight, at)) classes.push("hl");
    if (matched.has(at)) classes.push("match");
    if (inside(selection, at)) classes.push("sel");
    return classes.join(" ");
  };
}

/** Every start offset of `needle` in `haystack`, up to `limit` of them. */
export function findAll(haystack: Uint8Array, needle: Uint8Array, limit = MATCH_LIMIT): number[] {
  const found: number[] = [];
  const first = needle[0];
  if (first === undefined) return found;
  outer: for (let at = haystack.indexOf(first); at >= 0 && at <= haystack.length - needle.length; ) {
    for (let index = 1; index < needle.length; index++) {
      if (haystack[at + index] !== needle[index]) {
        at = haystack.indexOf(first, at + 1);
        continue outer;
      }
    }
    found.push(at);
    if (found.length >= limit) break;
    at = haystack.indexOf(first, at + 1);
  }
  return found;
}

/** Reads `0x1a`, `1ah`, or `26` as an offset. */
export function parseOffset(text: string): number | null {
  const value = text.trim().toLowerCase();
  if (!value) return null;
  if (/^0x[0-9a-f]+$/.test(value)) return Number.parseInt(value.slice(2), 16);
  if (/^[0-9a-f]+h$/.test(value)) return Number.parseInt(value.slice(0, -1), 16);
  if (/^\d+$/.test(value)) return Number.parseInt(value, 10);
  return null;
}

function describeSelection(range: ByteRange, page: Uint8Array, pageOffset: number): string {
  const start = range.offset;
  const end = range.offset + range.length - 1;
  const where =
    range.length === 1
      ? t("hex.selection.one", { offset: hex(start), decimal: start })
      : t("hex.selection.many", { from: hex(start), to: hex(end), count: range.length });
  const local = start - pageOffset;
  if (range.length > 4 || local < 0 || local + range.length > page.length) return where;
  let value = 0;
  for (let index = 0; index < range.length; index++) value = value * 256 + (page[local + index] ?? 0);
  return `${where} · ${t("hex.selection.value", { value })}`;
}

function hex(value: number): string {
  return `0x${value.toString(16)}`;
}
