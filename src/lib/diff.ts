/** One run of a byte diff: bytes both sides share, or bytes only one side has. */
export type DiffRun =
  | { kind: "equal"; aOffset: number; bOffset: number; length: number }
  | { kind: "delete"; aOffset: number; length: number }
  | { kind: "insert"; bOffset: number; length: number };

/** Inputs larger than this are compared position by position instead. */
export const SEQUENCE_DIFF_LIMIT = 64 * 1024;
/** Edit distance at which the sequence diff gives up and falls back. */
const MAX_EDITS = 4_000;

/**
 * Diffs two byte strings.
 *
 * Myers' algorithm, so an inserted byte — a longer string, a grown VarInt —
 * shows as one insertion rather than every following byte reading as changed.
 * Large or very different inputs fall back to a positional comparison, which
 * is what an operator comparing two same-shaped packets expects anyway.
 */
export function diffBytes(a: Uint8Array, b: Uint8Array): { runs: DiffRun[]; positional: boolean } {
  if (a.length <= SEQUENCE_DIFF_LIMIT && b.length <= SEQUENCE_DIFF_LIMIT) {
    const runs = myers(a, b);
    if (runs) return { runs, positional: false };
  }
  return { runs: positional(a, b), positional: true };
}

function myers(a: Uint8Array, b: Uint8Array): DiffRun[] | null {
  const n = a.length;
  const m = b.length;
  const max = Math.min(n + m, MAX_EDITS);
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  for (let d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x =
        k === -d || (k !== d && (v[offset + k - 1] ?? 0) < (v[offset + k + 1] ?? 0))
          ? (v[offset + k + 1] ?? 0)
          : (v[offset + k - 1] ?? 0) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) {
        x++;
        y++;
      }
      v[offset + k] = x;
      if (x >= n && y >= m) return backtrack(trace, n, m, offset);
    }
  }
  return null;
}

type Step = "equal" | "delete" | "insert";

function backtrack(trace: Int32Array[], n: number, m: number, offset: number): DiffRun[] {
  const steps: Array<{ step: Step; x: number; y: number }> = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const v = trace[d] as Int32Array;
    const k = x - y;
    const previousK =
      k === -d || (k !== d && (v[offset + k - 1] ?? 0) < (v[offset + k + 1] ?? 0)) ? k + 1 : k - 1;
    const previousX = v[offset + previousK] ?? 0;
    const previousY = previousX - previousK;
    while (x > previousX && y > previousY) {
      x--;
      y--;
      steps.push({ step: "equal", x, y });
    }
    if (d > 0) {
      if (x === previousX) steps.push({ step: "insert", x, y: y - 1 });
      else steps.push({ step: "delete", x: x - 1, y });
    }
    x = previousX;
    y = previousY;
  }
  steps.reverse();
  return compress(steps);
}

function compress(steps: Array<{ step: Step; x: number; y: number }>): DiffRun[] {
  const runs: DiffRun[] = [];
  for (const { step, x, y } of steps) {
    const last = runs.at(-1);
    if (last && last.kind === step) {
      last.length++;
      continue;
    }
    if (step === "equal") runs.push({ kind: "equal", aOffset: x, bOffset: y, length: 1 });
    else if (step === "delete") runs.push({ kind: "delete", aOffset: x, length: 1 });
    else runs.push({ kind: "insert", bOffset: y, length: 1 });
  }
  return runs;
}

function positional(a: Uint8Array, b: Uint8Array): DiffRun[] {
  const steps: Array<{ step: Step; x: number; y: number }> = [];
  const shared = Math.min(a.length, b.length);
  for (let index = 0; index < shared; index++) {
    if (a[index] === b[index]) steps.push({ step: "equal", x: index, y: index });
    else {
      steps.push({ step: "delete", x: index, y: index });
      steps.push({ step: "insert", x: index, y: index });
    }
  }
  for (let index = shared; index < a.length; index++) steps.push({ step: "delete", x: index, y: shared });
  for (let index = shared; index < b.length; index++) steps.push({ step: "insert", x: shared, y: index });
  // Interleaved delete/insert pairs compress poorly; regroup each changed span.
  const runs: DiffRun[] = [];
  let index = 0;
  while (index < steps.length) {
    const current = steps[index] as { step: Step; x: number; y: number };
    if (current.step === "equal") {
      const last = runs.at(-1);
      if (last?.kind === "equal") last.length++;
      else runs.push({ kind: "equal", aOffset: current.x, bOffset: current.y, length: 1 });
      index++;
      continue;
    }
    let deleted = 0;
    let inserted = 0;
    const aStart = current.x;
    const bStart = current.y;
    while (index < steps.length && steps[index]?.step !== "equal") {
      if (steps[index]?.step === "delete") deleted++;
      else inserted++;
      index++;
    }
    if (deleted) runs.push({ kind: "delete", aOffset: aStart, length: deleted });
    if (inserted) runs.push({ kind: "insert", bOffset: bStart, length: inserted });
  }
  return runs;
}

/** Number of bytes that differ, counting each inserted or deleted byte once. */
export function changedBytes(runs: DiffRun[]): number {
  return runs.reduce((sum, run) => (run.kind === "equal" ? sum : sum + run.length), 0);
}

/**
 * Flattens decoded fields into `path → text` pairs so two decodes can be laid
 * side by side. Key order is preserved, which is the wire order where the
 * backend keeps it.
 */
export function flattenFields(
  value: unknown,
  prefix = "",
  into = new Map<string, string>(),
): Map<string, string> {
  if (value !== null && typeof value === "object") {
    const entries = Array.isArray(value)
      ? value.map((item, index) => [`[${index}]`, item] as const)
      : Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) into.set(prefix || "(root)", Array.isArray(value) ? "[]" : "{}");
    for (const [key, item] of entries) {
      const path = prefix ? (key.startsWith("[") ? `${prefix}${key}` : `${prefix}.${key}`) : key;
      flattenFields(item, path, into);
    }
    return into;
  }
  into.set(prefix || "(root)", value === null || value === undefined ? "—" : String(value));
  return into;
}

export interface FieldDiffRow {
  path: string;
  a: string | undefined;
  b: string | undefined;
  changed: boolean;
}

export function diffFields(a: unknown, b: unknown): FieldDiffRow[] {
  const left = flattenFields(a ?? {});
  const right = flattenFields(b ?? {});
  const paths = [...left.keys(), ...[...right.keys()].filter((key) => !left.has(key))];
  return paths.map((path) => {
    const av = left.get(path);
    const bv = right.get(path);
    return { path, a: av, b: bv, changed: av !== bv };
  });
}
