import { type MouseEvent, memo, type ReactNode, useMemo } from "react";

import type { PacketSummary } from "../domain/types";
import { t } from "../i18n";
import { formatAbsolute, formatSeconds } from "../lib/time";
import { PACKET_ROW_HEIGHT } from "./PacketTable";
import { rowNavigationKeyHandler, VirtualRows, type VirtualRowsHandle } from "./VirtualRows";

/**
 * One connection read as a dialogue: client packets in the left lane, server
 * packets in the right, each with the time since the packet before it — the
 * view Wireshark calls Follow Stream, over decoded frames instead of bytes.
 *
 * It renders the same rows as the table, so filtering, paging, and following
 * behave identically; only the presentation changes.
 */
export const ConversationList = memo(function ConversationList({
  packets,
  selectedId,
  onSelect,
  onRowMenu,
  footer,
  onScrollStateChange,
  handleRef,
  oldestFirst = false,
}: {
  packets: readonly PacketSummary[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onRowMenu?: (packet: PacketSummary, x: number, y: number) => void;
  footer?: ReactNode;
  onScrollStateChange?: (atTop: boolean) => void;
  handleRef?: (handle: VirtualRowsHandle | null) => void;
  /** Rows run oldest to newest; otherwise newest to oldest. */
  oldestFirst?: boolean;
}) {
  const navigate = useMemo(
    () => rowNavigationKeyHandler(packets.length, PACKET_ROW_HEIGHT),
    [packets.length],
  );
  const selectedIndex = packets.findIndex((packet) => packet.id === selectedId);
  const activeIndex = selectedIndex >= 0 ? selectedIndex : 0;

  const menu = (event: MouseEvent<HTMLElement>, packet: PacketSummary) => {
    if (!onRowMenu) return;
    event.preventDefault();
    onSelect(packet.id);
    onRowMenu(packet, event.clientX, event.clientY);
  };

  return (
    <VirtualRows
      className="packet-table conversation"
      ariaLabel={t("conversation.title")}
      items={packets}
      rowHeight={PACKET_ROW_HEIGHT}
      getKey={(packet) => packet.id}
      activeIndex={packets.length > 0 ? activeIndex : undefined}
      onScrollStateChange={onScrollStateChange}
      handleRef={handleRef}
      header={
        <div className="conversation-row packet-header" role="row" aria-rowindex={1}>
          <span role="columnheader">{t("conversation.client")}</span>
          <span role="columnheader">{t("conversation.delta")}</span>
          <span role="columnheader">{t("conversation.server")}</span>
        </div>
      }
      footer={footer}
      renderRow={(packet, index) => {
        // The packet before this one in time, whichever way the rows run.
        const previous = packets[oldestFirst ? index - 1 : index + 1];
        const delta = previous ? packet.timestamp_micros - previous.timestamp_micros : 0;
        const turned = previous !== undefined && previous.direction !== packet.direction;
        const lane = (
          <span className="conversation-packet">
            <strong>
              {packet.name ??
                (packet.packet_id === null ? t("table.raw-stream") : `0x${packet.packet_id.toString(16)}`)}
            </strong>
            <small>
              {packet.size} B · {packet.state}
            </small>
          </span>
        );
        return (
          <div
            className={`conversation-row ${selectedId === packet.id ? "selected" : ""} ${turned ? "turn" : ""}`}
            role="row"
            aria-rowindex={index + 2}
            aria-selected={selectedId === packet.id}
            tabIndex={index === activeIndex ? 0 : -1}
            onClick={() => onSelect(packet.id)}
            onContextMenu={(event) => menu(event, packet)}
            onKeyDown={(event) => {
              if (event.target !== event.currentTarget) return;
              const next = navigate(event, index);
              const target = next === null ? undefined : packets[next];
              if (target) onSelect(target.id);
              else if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onSelect(packet.id);
              } else if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
                event.preventDefault();
                const rect = event.currentTarget.getBoundingClientRect();
                onRowMenu?.(packet, rect.left + 24, rect.bottom);
              }
            }}
          >
            <span role="gridcell" className="conversation-lane client">
              {packet.direction === "client_to_server" ? lane : null}
            </span>
            <span
              role="gridcell"
              className="conversation-delta packet-mono"
              title={formatAbsolute(packet.timestamp_micros)}
            >
              {formatSeconds(delta, true)}
            </span>
            <span role="gridcell" className="conversation-lane server">
              {packet.direction === "server_to_client" ? lane : null}
            </span>
          </div>
        );
      }}
    />
  );
});
