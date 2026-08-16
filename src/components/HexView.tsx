import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { ByteWindow } from "../domain/types";
import { base64ToBytes, formatHex } from "../lib/desktop";

/**
 * Bytes rendered at once.
 *
 * A hex dump is ~75 characters per 16 bytes, so a 1 MiB packet is a ~5 million
 * character string. Building and laying that out in one `<pre>` is what froze
 * the inspector; 4 KiB is a few hundred lines, which the browser handles
 * instantly, and the rest is a page away.
 */
export const HEX_PAGE_BYTES = 4 * 1024;

export function HexView({
  sourceKey,
  total,
  initial,
  loadWindow,
  onBytesChange,
  emptyLabel = "Empty frame",
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
  /**
   * Reports the window currently on screen, so a caller's header can act on
   * exactly the bytes the operator is looking at rather than on the page that
   * happened to arrive with the packet.
   */
  onBytesChange?: (bytes: Uint8Array | null) => void;
  emptyLabel?: string;
}) {
  const [offset, setOffset] = useState(initial?.offset ?? 0);
  const [bytes, setBytes] = useState<Uint8Array | null>(
    initial ? initial.bytes.slice(0, HEX_PAGE_BYTES) : null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seed = useRef(initial);
  seed.current = initial;

  // A new payload resets the view to the window that arrived with it.
  useEffect(() => {
    setOffset(seed.current?.offset ?? 0);
    setBytes(seed.current ? seed.current.bytes.slice(0, HEX_PAGE_BYTES) : null);
    setError(null);
  }, [sourceKey]);

  useEffect(() => {
    onBytesChange?.(bytes);
  }, [bytes, onBytesChange]);

  const pages = Math.max(1, Math.ceil(total / HEX_PAGE_BYTES));
  const page = Math.floor(offset / HEX_PAGE_BYTES);

  async function goTo(nextPage: number) {
    const nextOffset = Math.min(Math.max(0, nextPage), pages - 1) * HEX_PAGE_BYTES;
    if (nextOffset === offset && bytes) return;
    setLoading(true);
    setError(null);
    try {
      const window = await loadWindow(nextOffset, HEX_PAGE_BYTES);
      if (!window) {
        setBytes(null);
        setError("Bytes no longer retained");
        return;
      }
      setOffset(window.offset);
      setBytes(base64ToBytes(window.base64));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  }

  if (total === 0) {
    return <pre className="hex-view">{emptyLabel}</pre>;
  }

  return (
    <div className="hex-pager">
      <pre className="hex-view">
        {bytes ? formatHex(bytes, 16, offset) : error ?? "Loading…"}
      </pre>
      {pages > 1 && (
        <div className="hex-pager-controls">
          <button
            className="icon-button"
            onClick={() => void goTo(page - 1)}
            disabled={page === 0 || loading}
            aria-label="Previous byte range"
          >
            <ChevronLeft size={14} />
          </button>
          <span>
            {loading ? <Loader2 className="spin" size={12} /> : null}
            {offset.toLocaleString()}–
            {Math.min(total, offset + (bytes?.length ?? 0)).toLocaleString()} of{" "}
            {total.toLocaleString()}
          </span>
          <button
            className="icon-button"
            onClick={() => void goTo(page + 1)}
            disabled={page >= pages - 1 || loading}
            aria-label="Next byte range"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
