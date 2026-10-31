import type { AttackMode, PacketView, SequenceAnalysis } from "../domain/types";
import type { AttackPosition } from "./intruder";
export interface IntruderAttempt {
  index: number;
  payloads: string;
  bytes: number;
  elapsed: number;
  result: string;
  observed: number;
  observedBytes: number;
}
export interface IntruderDocument {
  seed: PacketView | null;
  positions: AttackPosition[];
  mode: AttackMode;
  connection: string;
  windowMs: number;
  results: IntruderAttempt[];
  progress: string;
  previewHex: string;
}
export const EMPTY_INTRUDER: IntruderDocument = {
  seed: null,
  positions: [],
  mode: "sniper",
  connection: "",
  windowMs: 250,
  results: [],
  progress: "",
  previewHex: "",
};
export interface SequencerDocument {
  seed: PacketView | null;
  field: string;
  samples: string;
  analysis: SequenceAnalysis | null;
  status: string;
}
export const EMPTY_SEQUENCER: SequencerDocument = {
  seed: null,
  field: "",
  samples: "",
  analysis: null,
  status: "",
};
function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function seed(value: unknown): boolean {
  return (
    value === null ||
    (object(value) &&
      object(value.summary) &&
      Number.isSafeInteger(value.summary.id) &&
      typeof value.summary.connection_id === "string" &&
      typeof value.summary.state === "string" &&
      typeof value.summary.direction === "string" &&
      typeof value.bytes_base64 === "string")
  );
}
export function isIntruderDocument(value: unknown): value is IntruderDocument {
  if (
    !object(value) ||
    !seed(value.seed) ||
    !Array.isArray(value.positions) ||
    value.positions.length > 16 ||
    !Array.isArray(value.results) ||
    value.results.length > 1000
  )
    return false;
  return (
    ["sniper", "battering_ram", "pitchfork", "cluster_bomb"].includes(String(value.mode)) &&
    typeof value.connection === "string" &&
    typeof value.windowMs === "number" &&
    value.windowMs >= 50 &&
    value.windowMs <= 60000 &&
    typeof value.progress === "string" &&
    typeof value.previewHex === "string" &&
    value.positions.every(
      (p) => object(p) && typeof p.field === "string" && typeof p.payloads === "string",
    ) &&
    value.results.every(
      (r) =>
        object(r) &&
        ["index", "bytes", "elapsed", "observed", "observedBytes"].every((k) => typeof r[k] === "number") &&
        typeof r.payloads === "string" &&
        typeof r.result === "string",
    )
  );
}
export function isSequencerDocument(value: unknown): value is SequencerDocument {
  if (
    !object(value) ||
    !seed(value.seed) ||
    typeof value.field !== "string" ||
    typeof value.samples !== "string" ||
    typeof value.status !== "string"
  )
    return false;
  if (value.analysis === null) return true;
  const a = value.analysis;
  return (
    object(a) &&
    ["samples", "unique", "duplicates", "min_length", "max_length", "adjacent_equal"].every(
      (k) => typeof a[k] === "number",
    ) &&
    (a.serial_correlation === null || typeof a.serial_correlation === "number") &&
    Array.isArray(a.positions) &&
    a.positions.length <= 4096 &&
    a.positions.every(
      (p) =>
        object(p) &&
        ["offset", "samples", "distinct", "entropy_bits", "most_common_fraction"].every(
          (k) => typeof p[k] === "number",
        ),
    )
  );
}
