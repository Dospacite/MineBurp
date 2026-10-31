import type { TimeMode } from "../domain/types";
import type { MessageKey } from "../i18n";
import { newId } from "./ids";

export type ColumnId =
  | "sequence"
  | "time"
  | "connection"
  | "flow"
  | "state"
  | "id"
  | "packet"
  | "bytes"
  | "result";

export interface ColumnSetting {
  id: ColumnId;
  visible: boolean;
}

export interface DecodedColumn {
  id: string;
  label: string;
  path: string;
  visible: boolean;
}
export interface TableSettings {
  customColumns?: DecodedColumn[];
  columns: ColumnSetting[];
  timeMode: TimeMode;
  /** The whole matching history oldest first, instead of newest first. */
  oldestFirst: boolean;
}

/** Track width and header label per column; the packet name takes what is left. */
export const COLUMN_DEFINITIONS: Record<ColumnId, { width: string; label: MessageKey }> = {
  sequence: { width: "56px", label: "table.column.sequence" },
  time: { width: "112px", label: "table.column.time" },
  connection: { width: "120px", label: "table.column.connection" },
  flow: { width: "60px", label: "table.column.flow" },
  state: { width: "88px", label: "table.column.state" },
  id: { width: "56px", label: "table.column.id" },
  packet: { width: "minmax(130px, 1fr)", label: "table.column.packet" },
  bytes: { width: "64px", label: "table.column.bytes" },
  result: { width: "84px", label: "table.column.result" },
};

const ORDER: ColumnId[] = [
  "sequence",
  "time",
  "connection",
  "flow",
  "state",
  "id",
  "packet",
  "bytes",
  "result",
];
const HIDDEN_BY_DEFAULT = new Set<ColumnId>(["connection", "id"]);

export const DEFAULT_TABLE_SETTINGS: TableSettings = {
  columns: ORDER.map((id) => ({ id, visible: !HIDDEN_BY_DEFAULT.has(id) })),
  timeMode: "relative",
  oldestFirst: false,
};

const STORAGE_KEY = "mineburp.table";

/**
 * Reads the stored column layout, tolerating anything a previous version or a
 * hand edit left behind: unknown ids are dropped and new columns are appended
 * in their default position, so adding a column never hides an old setting.
 */
export function loadTableSettings(): TableSettings {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null");
    if (!parsed || typeof parsed !== "object") return DEFAULT_TABLE_SETTINGS;
    const { columns, timeMode, oldestFirst, customColumns } = parsed as Record<string, unknown>;
    return {
      customColumns: normaliseDecodedColumns(customColumns),
      columns: normaliseColumns(Array.isArray(columns) ? columns : []),
      timeMode:
        timeMode === "absolute" || timeMode === "delta" || timeMode === "relative" ? timeMode : "relative",
      oldestFirst: oldestFirst === true,
    };
  } catch {
    return DEFAULT_TABLE_SETTINGS;
  }
}

export function storeTableSettings(settings: TableSettings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    window.dispatchEvent(new Event("mineburp:table-settings"));
  } catch {
    // A convenience only.
  }
}

export function normaliseColumns(input: unknown[]): ColumnSetting[] {
  const seen = new Set<ColumnId>();
  const result: ColumnSetting[] = [];
  for (const entry of input) {
    if (!entry || typeof entry !== "object") continue;
    const { id, visible } = entry as Record<string, unknown>;
    if (typeof id !== "string" || !(id in COLUMN_DEFINITIONS) || seen.has(id as ColumnId)) continue;
    seen.add(id as ColumnId);
    result.push({ id: id as ColumnId, visible: visible !== false });
  }
  for (const id of ORDER) {
    if (!seen.has(id)) result.push({ id, visible: !HIDDEN_BY_DEFAULT.has(id) });
  }
  // The packet name is what a row is; it cannot be hidden.
  return result.map((column) => (column.id === "packet" ? { ...column, visible: true } : column));
}

export function gridTemplate(columns: ColumnSetting[]): string {
  return columns
    .filter((column) => column.visible)
    .map((column) => COLUMN_DEFINITIONS[column.id].width)
    .join(" ");
}

/**
 * The narrowest a row can be before its columns collide: every fixed track
 * plus the packet column's minimum, plus the row's horizontal padding. A pane
 * narrower than this scrolls the table sideways instead of overlapping cells.
 */
export function gridMinWidth(columns: ColumnSetting[]): number {
  const ROW_PADDING = 22;
  return columns
    .filter((column) => column.visible)
    .reduce((total, column) => {
      const pixels = /(\d+)px/.exec(COLUMN_DEFINITIONS[column.id].width);
      return total + (pixels ? Number(pixels[1]) : 0);
    }, ROW_PADDING);
}

export function moveColumn(columns: ColumnSetting[], id: ColumnId, by: -1 | 1): ColumnSetting[] {
  const index = columns.findIndex((column) => column.id === id);
  const target = index + by;
  if (index < 0 || target < 0 || target >= columns.length) return columns;
  const next = [...columns];
  const [moved] = next.splice(index, 1);
  if (moved) next.splice(target, 0, moved);
  return next;
}

export function normaliseDecodedColumns(input: unknown): DecodedColumn[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  return input
    .filter(
      (v): v is DecodedColumn =>
        !!v &&
        typeof v === "object" &&
        typeof v.id === "string" &&
        !seen.has(v.id) &&
        !!seen.add(v.id) &&
        typeof v.path === "string" &&
        v.path.length <= 256 &&
        typeof v.label === "string" &&
        v.label.length <= 80,
    )
    .slice(0, 8)
    .map((v) => ({ ...v, visible: v.visible !== false }));
}
export function addDecodedColumn(path: string): void {
  const settings = loadTableSettings();
  const existing = settings.customColumns ?? [];
  if (existing.some((c) => c.path === path)) return;
  if (existing.length >= 8) throw new Error("A table can have at most eight decoded-field columns");
  storeTableSettings({
    ...settings,
    customColumns: [...existing, { id: newId(), path, label: path.slice(0, 80), visible: true }],
  });
}
