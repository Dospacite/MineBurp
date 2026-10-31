import type { AttackMode, PacketEdit } from "../domain/types";

export interface AttackPosition {
  id?: string;
  field: string;
  payloads: string;
  offset?: number;
  length?: number;
}

export function payloadLists(positions: AttackPosition[]): string[][] {
  return positions.map((p) => p.payloads.replace(/\r/g, "").split("\n"));
}

export function caseEdits(
  mode: AttackMode,
  positions: AttackPosition[],
  lists: string[][],
  row: Array<number | null>,
): PacketEdit[] {
  const edits: PacketEdit[] = [];
  for (const [position, index] of row.entries()) {
    if (index === null) continue;
    const target = positions[position];
    const value = lists[mode === "battering_ram" ? 0 : position]?.[index];
    if (!target || value === undefined) throw new Error("Invalid attack plan index");
    if (target.field === "@raw")
      edits.push({ kind: "range", offset: target.offset ?? 0, length: target.length ?? 0, bytes: value });
    else edits.push({ kind: "field", name: target.field, value });
  }
  // Raw positions refer to the original frame. Replace from right to left so
  // resizing a later range cannot move an earlier range.
  return edits.sort((a, b) => (a.kind === "range" && b.kind === "range" ? b.offset - a.offset : 0));
}

export function validatePositions(positions: AttackPosition[]): boolean {
  if (!positions.length) return false;
  const raw = positions.filter((p) => p.field === "@raw");
  if (raw.length && raw.length !== positions.length) return false;
  if (!raw.length) return new Set(positions.map((p) => p.field)).size === positions.length;
  const sorted = [...raw].sort((a, b) => (a.offset ?? 0) - (b.offset ?? 0));
  return sorted.every(
    (p, i) =>
      Number.isInteger(p.offset) &&
      Number.isInteger(p.length) &&
      (p.offset ?? -1) >= 0 &&
      (p.length ?? 0) > 0 &&
      (i === 0 || (sorted[i - 1]?.offset ?? 0) + (sorted[i - 1]?.length ?? 0) <= (p.offset ?? 0)),
  );
}

export function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
}
