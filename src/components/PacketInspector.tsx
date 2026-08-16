import { Copy, Send, ShieldAlert } from "lucide-react";
import { useMemo } from "react";

import type { ByteWindow, PacketView } from "../domain/types";
import { base64ToBytes, desktop, formatHex } from "../lib/desktop";
import { DecodedFields } from "./DecodedFields";
import { EmptyState } from "./EmptyState";
import { HEX_PAGE_BYTES, HexView } from "./HexView";

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

  if (!packet) {
    return <EmptyState title="No packet selected" detail="Select a row to inspect its raw frame and decoded fields." />;
  }

  const { summary, insight } = packet;
  const title = insight.label ?? summary.name ?? `Packet ${summary.packet_id ?? "raw"}`;
  const signedChatRisk = summary.state === "play" && (summary.protocol_version ?? 0) >= 759;
  const modIntegrityRisk = (insight.loader ?? summary.loader) !== null || (insight.channel ?? summary.channel) !== null;

  async function copyHex() {
    if (!packet) return;
    try {
      // Copies what is loaded rather than re-reading the whole payload, so the
      // clipboard never has to hold a multi-megabyte dump.
      await navigator.clipboard.writeText(formatHex(loaded, 16, packet.bytes_offset));
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  return (
    <section className="inspector">
      <header className="inspector-header">
        <div>
          <span className="eyebrow">Packet {summary.sequence}</span>
          <h2>{title}</h2>
        </div>
        <div className="button-row">
          <button className="icon-button" title="Copy loaded hex" aria-label="Copy loaded packet hex" onClick={() => void copyHex()}>
            <Copy size={15} aria-hidden="true" />
          </button>
          <button className="button" onClick={onRepeater}>
            <Send size={14} aria-hidden="true" /> Send to Repeater
          </button>
        </div>
      </header>
      <dl className="metadata-grid">
        <div><dt>Direction</dt><dd>{summary.direction.replaceAll("_", " ")}</dd></div>
        <div><dt>State</dt><dd>{summary.state}</dd></div>
        <div><dt>Packet ID</dt><dd>{summary.packet_id ?? "—"}</dd></div>
        <div><dt>Wire</dt><dd>{packet.wire.compressed ? "compressed" : "plain"}{packet.wire.encrypted ? ", encrypted" : ""}</dd></div>
        {(insight.channel ?? summary.channel) && (
          <div><dt>Channel</dt><dd title={insight.channel ?? summary.channel ?? ""}>{insight.channel ?? summary.channel}</dd></div>
        )}
        <div><dt>Size</dt><dd>{packet.total_bytes.toLocaleString()} B</dd></div>
      </dl>
      <div className="inspector-section">
        <h3>Decoded fields</h3>
        <div className="inspector-scroll">
          <DecodedFields insight={insight} />
          {packet.stored_decoded !== null && (
            <details className="stored-decode">
              <summary>Schema-pack decode from capture time</summary>
              <pre className="json-view">{JSON.stringify(packet.stored_decoded, null, 2)}</pre>
            </details>
          )}
          {packet.stored_decode_error && <p className="muted">{packet.stored_decode_error}</p>}
        </div>
      </div>
      <div className="inspector-section">
        <h3>Raw logical frame</h3>
        <HexView
          sourceKey={summary.id}
          total={packet.total_bytes}
          initial={{ offset: packet.bytes_offset, bytes: loaded }}
          loadWindow={(offset, limit): Promise<ByteWindow | null> =>
            desktop.packetBytes(summary.id, offset, Math.min(limit, HEX_PAGE_BYTES))
          }
        />
      </div>
      {(signedChatRisk || modIntegrityRisk) && (
        <aside className="integrity-warning" aria-label="Packet modification safety warning">
          <ShieldAlert size={16} aria-hidden="true" />
          <div>
            <strong>Forward unchanged unless you have verified the integrity contract.</strong>
            <p>{signedChatRisk ? "Modern play traffic can contain signed chat or command data; changing it can invalidate signatures or disconnect the client." : "Mod and plugin traffic can use certificate pinning or its own integrity checks; changing it can disconnect the client."}</p>
          </div>
        </aside>
      )}
    </section>
  );
}
