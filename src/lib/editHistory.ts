import type { RepeaterEditHistory } from "../domain/types";

const BUDGET = 2 * 1024 * 1024;
function trim(values: string[]): string[] {
  const result = values.slice(-100);
  let size = result.reduce((n, v) => n + v.length, 0);
  while (size > BUDGET && result.length) {
    size -= result.shift()?.length ?? 0;
  }
  return result;
}
export function initialHistory(hex: string): RepeaterEditHistory {
  return {
    original_available: hex.length <= BUDGET,
    original: hex.length <= BUDGET ? hex : "",
    past: [],
    future: [],
    revisions: [],
  };
}
const typingTimes = new WeakMap<RepeaterEditHistory, number>();
export function recordEdit(
  history: RepeaterEditHistory,
  before: string,
  after: string,
  typing = false,
): RepeaterEditHistory {
  if (before === after) return history;
  const now = Date.now();
  const coalesce = typing && now - (typingTimes.get(history) ?? -Infinity) < 600;
  const next = { ...history, past: coalesce ? history.past : trim([...history.past, before]), future: [] };
  if (typing) typingTimes.set(next, now);
  return next;
}
export function undoEdit(
  history: RepeaterEditHistory,
  current: string,
): { history: RepeaterEditHistory; hex: string } | null {
  const previous = history.past.at(-1);
  return previous === undefined
    ? null
    : {
        hex: previous,
        history: { ...history, past: history.past.slice(0, -1), future: trim([...history.future, current]) },
      };
}
export function redoEdit(
  history: RepeaterEditHistory,
  current: string,
): { history: RepeaterEditHistory; hex: string } | null {
  const next = history.future.at(-1);
  return next === undefined
    ? null
    : {
        hex: next,
        history: { ...history, past: trim([...history.past, current]), future: history.future.slice(0, -1) },
      };
}
export function namedRevision(history: RepeaterEditHistory, name: string, hex: string): RepeaterEditHistory {
  if (!name.trim() || name.length > 80 || hex.length > BUDGET)
    throw new Error("Use a revision name of 1–80 characters and a frame smaller than 2 MiB of hex");
  const revisions = [
    ...history.revisions.filter((r) => r.name !== name.trim()),
    { name: name.trim(), hex },
  ].slice(-20);
  while (revisions.reduce((n, r) => n + r.hex.length, 0) > BUDGET) revisions.shift();
  return { ...history, revisions };
}
