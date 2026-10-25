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
import { filterArgs } from "./desktop";

/**
 * A filter in the shape the backend validates and stores: the history query
 * arguments without the connection, cursors, or page size, which belong to
 * where the operator is rather than to what they are looking for.
 */
export function toSavedPayload(filter: PacketFilter): Record<string, unknown> {
  const {
    connectionId: _connection,
    offset: _offset,
    limit: _limit,
    beforeId: _before,
    afterId: _after,
    ...rest
  } = filterArgs({ ...filter, search: filter.search.trim() });
  return rest;
}

/**
 * Reads a stored filter back. Anything missing or of the wrong type falls back
 * to "no filter" for that control, so a filter saved by an older build still
 * applies.
 */
export function fromSavedPayload(payload: Record<string, unknown>): PacketFilter {
  const text = (key: string) => (typeof payload[key] === "string" ? (payload[key] as string) : "");
  const flag = (key: string) => payload[key] === true;
  const list = <T extends string>(key: string): T[] =>
    Array.isArray(payload[key])
      ? (payload[key] as unknown[]).filter((v): v is T => typeof v === "string")
      : [];
  const size = (key: string) => {
    const value = payload[key];
    return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
  };
  const oneOf = <T extends string>(key: string, values: readonly T[], fallback: T): T =>
    values.includes(payload[key] as T) ? (payload[key] as T) : fallback;
  return {
    ...EMPTY_FILTER,
    search: text("search"),
    searchRegex: flag("searchRegex"),
    searchCaseSensitive: flag("searchCaseSensitive"),
    searchNegate: flag("searchNegate"),
    directions: list<Direction>("directions"),
    states: list<ProtocolState>("states"),
    sources: list<TrafficSource>("sources"),
    dispositions: list<Disposition>("dispositions"),
    includeNames: list("includeNames"),
    excludeNames: list("excludeNames"),
    minSize: size("minSize"),
    maxSize: size("maxSize"),
    expression: text("expression"),
    content: text("content"),
    contentMode: oneOf<ContentSearchMode>("contentMode", ["text", "hex", "regex"], "text"),
    contentScope: oneOf<ContentSearchScope>(
      "contentScope",
      ["contains", "equals", "prefix", "suffix"],
      "contains",
    ),
    contentCaseSensitive: flag("contentCaseSensitive"),
    contentNegate: flag("contentNegate"),
    bookmarked: flag("bookmarked"),
  };
}
