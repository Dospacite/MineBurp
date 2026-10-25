import type { TimeMode } from "../domain/types";

/** Wall-clock time with millisecond precision, in the operator's time zone. */
export function formatAbsolute(micros: number): string {
  const date = new Date(Math.floor(micros / 1_000));
  const pad = (value: number, width = 2) => String(value).padStart(width, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(
    date.getMilliseconds(),
    3,
  )}`;
}

/** Seconds with microsecond precision, signed so a reference after the row reads negative. */
export function formatSeconds(micros: number, signed = false): string {
  const sign = micros < 0 ? "−" : signed ? "+" : "";
  const magnitude = Math.abs(micros);
  const seconds = Math.floor(magnitude / 1_000_000);
  const fraction = String(magnitude % 1_000_000).padStart(6, "0");
  return `${sign}${seconds}.${fraction}`;
}

/**
 * The time column for one row.
 *
 * `reference` anchors relative time; `previous` is the row that came before
 * this one in capture order, which in a newest-first table is the row below.
 */
export function formatPacketTime(
  micros: number,
  mode: TimeMode,
  reference: number | null,
  previous: number | null,
): string {
  switch (mode) {
    case "absolute":
      return formatAbsolute(micros);
    case "relative":
      return reference === null ? "—" : formatSeconds(micros - reference);
    case "delta":
      return previous === null ? formatSeconds(0, true) : formatSeconds(micros - previous, true);
  }
}
