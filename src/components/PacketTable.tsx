import type { ReactNode } from "react";

import type { PacketSummary } from "../domain/types";
import { VirtualRows, type VirtualRowsHandle } from "./VirtualRows";

/** Must match `.packet-row` in styles.css: virtualization needs a fixed height. */
export const PACKET_ROW_HEIGHT = 34;

export function PacketTable({
  packets,
  selectedId,
  onSelect,
  footer,
  onScrollStateChange,
  handleRef,
}: {
  packets: readonly PacketSummary[];
  /**
   * The clicked row's id. Held by the caller rather than derived from the
   * fetched packet so the highlight lands immediately, on exactly one row, and
   * does not move if a slower request for a different row resolves later.
   */
  selectedId: number | null;
  onSelect: (id: number) => void;
  footer?: ReactNode;
  onScrollStateChange?: (atTop: boolean) => void;
  handleRef?: (handle: VirtualRowsHandle | null) => void;
}) {
  return (
    <VirtualRows
      className="packet-table"
      ariaLabel="Captured packets"
      items={packets}
      rowHeight={PACKET_ROW_HEIGHT}
      onScrollStateChange={onScrollStateChange}
      handleRef={handleRef}
      header={
        <div className="packet-row packet-header" role="row">
          <span role="columnheader">#</span>
          <span role="columnheader">Flow</span>
          <span role="columnheader">State</span>
          <span role="columnheader">Packet</span>
          <span role="columnheader">Bytes</span>
          <span role="columnheader">Result</span>
        </div>
      }
      footer={footer}
      renderRow={(packet) => (
        <button
          className={`packet-row ${selectedId === packet.id ? "selected" : ""}`}
          role="row"
          key={packet.id}
          aria-selected={selectedId === packet.id}
          onClick={() => onSelect(packet.id)}
        >
          <span role="cell">{packet.sequence}</span>
          <span role="cell" className={`direction ${packet.direction}`}>
            {packet.direction === "client_to_server" ? "C → S" : "S → C"}
          </span>
          <span role="cell">{packet.state}</span>
          <span role="cell" className="packet-name">
            {packet.name ?? (packet.packet_id === null ? "raw stream" : `0x${packet.packet_id.toString(16)}`)}
          </span>
          <span role="cell">{packet.size}</span>
          <span role="cell" className={`disposition ${packet.disposition}`}>{packet.disposition}</span>
        </button>
      )}
    />
  );
}
