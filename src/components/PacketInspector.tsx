import { Copy, Send } from "lucide-react";
import { useMemo, useState } from "react";

import type { ByteWindow, PacketView } from "../domain/types";
import { base64ToBytes, desktop, formatHex, formatRawHex } from "../lib/desktop";
import { DecodedFields } from "./DecodedFields";
import { EmptyState } from "./EmptyState";
import { HEX_PAGE_BYTES, HexView } from "./HexView";
import { Split } from "./Split";

export function PacketInspector({
  packet,
  onRepeater,
  onError,
}: {
  packet: PacketView | null;
  onRepeater: () => void;
  onError: (error: string) => void;
}) {
  const loaded = useMemo(
    () => (packet ? base64ToBytes(packet.bytes_base64) : new Uint8Array()),
    [packet],
  );
  /** The page the hex view is showing, which paging can move off `loaded`. */
  const [visible, setVisible] = useState<Uint8Array | null>(null);

  if (!packet) {
    return <EmptyState title="No packet selected" detail="Select a row to inspect it." />;
  }

  const { summary, insight } = packet;

  async function copy(text: string) {
    try {
      // Copies what is loaded rather than re-reading the whole payload, so the
      // clipboard never has to hold a multi-megabyte dump.
      await navigator.clipboard.writeText(text);
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  const shown = visible ?? loaded;

  return (
    <section className="inspector">
      <header className="inspector-header">
        <div className="inspector-meta">
          <span className={`direction ${summary.direction}`}>
            {summary.direction === "client_to_server" ? "C → S" : "S → C"}
          </span>
          <span>{packet.total_bytes.toLocaleString()} B</span>
        </div>
        <div className="button-row">
          <button
            className="icon-button"
            title="Copy hex dump"
            aria-label="Copy hex dump"
            onClick={() => void copy(formatHex(loaded, 16, packet.bytes_offset))}
          >
            <Copy size={15} aria-hidden="true" />
          </button>
          <button className="button" onClick={onRepeater}>
            <Send size={14} aria-hidden="true" /> Repeater
          </button>
        </div>
      </header>
      <Split orientation="rows" storageKey="inspector" initial={[0.45, 0.55]} minimum={110} className="inspector-body">
        <div className="inspector-section">
          <h3>Decoded fields</h3>
          <div className="inspector-scroll">
            <DecodedFields insight={insight} schema={packet.stored_decoded} />
          </div>
        </div>
        <div className="inspector-section">
          <header className="section-header">
            <h3>Bytes</h3>
            <button
              className="link-button"
              title={
                packet.total_bytes > shown.length
                  ? "Copy the bytes on screen as hex"
                  : "Copy the payload as hex"
              }
              aria-label="Copy raw hex"
              disabled={shown.length === 0}
              onClick={() => void copy(formatRawHex(shown))}
            >
              <Copy size={12} aria-hidden="true" /> Raw hex
            </button>
          </header>
          <HexView
            sourceKey={summary.id}
            total={packet.total_bytes}
            initial={{ offset: packet.bytes_offset, bytes: loaded }}
            loadWindow={(offset, limit): Promise<ByteWindow | null> =>
              desktop.packetBytes(summary.id, offset, Math.min(limit, HEX_PAGE_BYTES))
            }
            onBytesChange={setVisible}
          />
        </div>
      </Split>
    </section>
  );
}
