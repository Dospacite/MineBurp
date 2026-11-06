import { useCallback, useEffect, useRef, useState } from "react";
import type { Direction, FieldSpan, PacketLayout, ProtocolState } from "../domain/types";
import { desktop, formatHexInput, parseHex, tryParseHex } from "../lib/desktop";

/** Serializes typed edits, resolving spans again after each change in frame length. */
export function useFrameEditor(
  hex: string,
  state: ProtocolState,
  direction: Direction,
  version: number | null,
  identity: string | number | null,
  apply: (hex: string) => void,
  onError: (error: string) => void,
) {
  const latest = useRef({ hex, state, direction, version, identity, apply });
  latest.current = { hex, state, direction, version, identity, apply };
  const queue = useRef<Promise<void>>(Promise.resolve());
  const [decoded, setDecoded] = useState<{
    hex: string;
    identity: typeof identity;
    state: ProtocolState;
    direction: Direction;
    version: number | null;
    layout: PacketLayout;
  } | null>(null);
  const [decoding, setDecoding] = useState(false);
  useEffect(() => {
    let live = true;
    setDecoding(true);
    const timer = window.setTimeout(async () => {
      try {
        const bytes = tryParseHex(hex).bytes;
        const layout = bytes?.length ? await desktop.packetLayout(bytes, state, direction, version) : null;
        if (live) setDecoded(layout ? { hex, identity, state, direction, version, layout } : null);
      } catch {
        if (live) setDecoded(null);
      } finally {
        if (live) setDecoding(false);
      }
    }, 150);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [hex, state, direction, version, identity]);
  const commitField = useCallback(
    (field: FieldSpan, value: string | boolean) => {
      const id = latest.current.identity;
      const run = queue.current
        .catch(() => undefined)
        .then(async () => {
          const before = latest.current;
          if (before.identity !== id) throw new Error("The selected frame changed. Commit the edit again.");
          const layout = await desktop.packetLayout(
            parseHex(before.hex),
            before.state,
            before.direction,
            before.version,
          );
          const span = layout.fields.find((item) => item.name === field.name);
          if (!span) throw new Error("The edited field is no longer in this frame.");
          const next = formatHexInput(await desktop.fieldEdit(parseHex(before.hex), span, value));
          if (latest.current.identity !== id || latest.current.hex !== before.hex)
            throw new Error("The frame changed during the edit.");
          latest.current = { ...latest.current, hex: next };
          before.apply(next);
        });
      queue.current = run;
      void run.catch((reason: unknown) => onError(String(reason)));
      // A failed commit blocks sends, but a later edit may recover.
      queue.current = run.catch((reason: unknown) => {
        throw reason;
      });
      void queue.current.catch(() => undefined);
      return run;
    },
    [onError],
  );
  const flush = useCallback(() => queue.current, []);
  const latestHex = useCallback(() => latest.current.hex, []);
  return {
    layout:
      decoded?.hex === hex &&
      decoded.identity === identity &&
      decoded.state === state &&
      decoded.direction === direction &&
      decoded.version === version
        ? decoded.layout
        : null,
    decoding,
    commitField,
    flush,
    latestHex,
  };
}
