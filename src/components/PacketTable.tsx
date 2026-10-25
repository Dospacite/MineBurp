import { Bookmark } from "lucide-react";
import {
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent,
  memo,
  type ReactNode,
  useCallback,
  useMemo,
} from "react";

import type { PacketAnnotation, PacketSummary, TimeMode } from "../domain/types";
import { t } from "../i18n";
import { annotationColorStyle } from "../lib/annotations";
import {
  COLUMN_DEFINITIONS,
  type ColumnId,
  type ColumnSetting,
  DEFAULT_TABLE_SETTINGS,
  gridTemplate,
} from "../lib/columns";
import { formatPacketTime } from "../lib/time";
import { rowNavigationKeyHandler, VirtualRows, type VirtualRowsHandle } from "./VirtualRows";

/** Must match `.packet-row` in styles.css: virtualization needs a fixed height. */
export const PACKET_ROW_HEIGHT = 34;

/** Keyboard commands a row understands besides navigation. */
export type RowCommand = "repeater" | "copy-hex" | "compare" | "bookmark";

export const PacketTable = memo(function PacketTable({
  packets,
  selectedId,
  onSelect,
  footer,
  onScrollStateChange,
  handleRef,
  columns = DEFAULT_TABLE_SETTINGS.columns,
  timeMode = "relative",
  timeReference = null,
  connectionLabels,
  onRowMenu,
  onRowCommand,
  annotations,
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
  columns?: ColumnSetting[];
  timeMode?: TimeMode;
  /** Timestamp relative times count from; null shows no relative time. */
  timeReference?: number | null;
  /** Readable names for connection ids, for the connection column. */
  connectionLabels?: ReadonlyMap<string, string>;
  /** Opens the row menu at a screen position. */
  onRowMenu?: (packet: PacketSummary, x: number, y: number) => void;
  onRowCommand?: (command: RowCommand, packet: PacketSummary) => void;
  /** Bookmarks and colours of the loaded rows, by packet id. */
  annotations?: ReadonlyMap<number, PacketAnnotation>;
}) {
  const visibleColumns = useMemo(() => columns.filter((column) => column.visible), [columns]);
  const template = useMemo(() => gridTemplate(columns), [columns]);
  const selectedIndex = useMemo(
    () => (selectedId === null ? -1 : packets.findIndex((packet) => packet.id === selectedId)),
    [packets, selectedId],
  );
  // One tab stop for the whole grid: the selected row, or the first.
  const activeIndex = selectedIndex >= 0 ? selectedIndex : 0;
  const navigate = useMemo(
    () => rowNavigationKeyHandler(packets.length, PACKET_ROW_HEIGHT),
    [packets.length],
  );

  const onRowKeyDown = useCallback(
    (event: KeyboardEvent<HTMLElement>, index: number, packet: PacketSummary) => {
      if (event.target !== event.currentTarget) return;
      const next = navigate(event, index);
      if (next !== null) {
        // Moving the cursor selects, as it does in Wireshark: the inspector
        // follows the keyboard rather than waiting for Enter.
        const target = packets[next];
        if (target && target.id !== selectedId) onSelect(target.id);
        return;
      }
      const modifier = event.ctrlKey || event.metaKey;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        onSelect(packet.id);
      } else if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
        event.preventDefault();
        const rect = event.currentTarget.getBoundingClientRect();
        onRowMenu?.(packet, rect.left + 24, rect.bottom);
      } else if (modifier && !event.shiftKey && event.key.toLowerCase() === "r") {
        event.preventDefault();
        onRowCommand?.("repeater", packet);
      } else if (modifier && event.shiftKey && event.key.toLowerCase() === "c") {
        event.preventDefault();
        onRowCommand?.("copy-hex", packet);
      } else if (modifier && !event.shiftKey && event.key.toLowerCase() === "d") {
        event.preventDefault();
        onRowCommand?.("compare", packet);
      } else if (modifier && !event.shiftKey && event.key.toLowerCase() === "b") {
        event.preventDefault();
        onRowCommand?.("bookmark", packet);
      }
    },
    [navigate, onRowCommand, onRowMenu, onSelect, packets, selectedId],
  );

  const onContextMenu = useCallback(
    (event: MouseEvent<HTMLElement>, packet: PacketSummary) => {
      if (!onRowMenu) return;
      event.preventDefault();
      if (packet.id !== selectedId) onSelect(packet.id);
      onRowMenu(packet, event.clientX, event.clientY);
    },
    [onRowMenu, onSelect, selectedId],
  );

  const cell = (id: ColumnId, packet: PacketSummary, index: number): ReactNode => {
    switch (id) {
      case "sequence":
        return packet.sequence;
      case "time": {
        const previous = packets[index + 1]?.timestamp_micros ?? null;
        return formatPacketTime(packet.timestamp_micros, timeMode, timeReference, previous);
      }
      case "connection":
        return connectionLabels?.get(packet.connection_id) ?? packet.connection_id.slice(0, 8);
      case "flow":
        return packet.direction === "client_to_server" ? t("flow.c2s") : t("flow.s2c");
      case "state":
        return packet.state;
      case "id":
        return packet.packet_id === null ? "—" : `0x${packet.packet_id.toString(16).padStart(2, "0")}`;
      case "packet": {
        const name =
          packet.name ??
          (packet.packet_id === null ? t("table.raw-stream") : `0x${packet.packet_id.toString(16)}`);
        const annotation = annotations?.get(packet.id);
        if (!annotation?.bookmarked && !annotation?.note) return name;
        return (
          <>
            {annotation.bookmarked && (
              <Bookmark size={11} className="row-bookmark" aria-label={t("annotation.bookmarked")} />
            )}
            {name}
            {annotation.note && (
              <span className="row-note" title={annotation.note}>
                {annotation.note}
              </span>
            )}
          </>
        );
      }
      case "bytes":
        return packet.size;
      case "result":
        return packet.disposition;
    }
  };

  const cellClass = (id: ColumnId, packet: PacketSummary): string | undefined => {
    switch (id) {
      case "flow":
        return `direction ${packet.direction}`;
      case "packet":
        return "packet-name";
      case "result":
        return `disposition ${packet.disposition}`;
      case "time":
      case "id":
      case "connection":
        return "packet-mono";
      default:
        return undefined;
    }
  };

  return (
    <VirtualRows
      className="packet-table"
      ariaLabel={t("table.caption")}
      items={packets}
      rowHeight={PACKET_ROW_HEIGHT}
      getKey={(packet) => packet.id}
      activeIndex={packets.length > 0 ? activeIndex : undefined}
      onScrollStateChange={onScrollStateChange}
      handleRef={handleRef}
      style={{ "--packet-columns": template } as CSSProperties}
      header={
        <div className="packet-row packet-header" role="row" aria-rowindex={1}>
          {visibleColumns.map((column) => (
            <span role="columnheader" key={column.id}>
              {column.id === "time"
                ? t(`table.column.time.${timeMode}`)
                : t(COLUMN_DEFINITIONS[column.id].label)}
            </span>
          ))}
        </div>
      }
      footer={footer}
      renderRow={(packet, index) => {
        const mark = annotationColorStyle(annotations?.get(packet.id)?.color);
        return (
          <div
            className={`packet-row ${selectedId === packet.id ? "selected" : ""} ${mark.className}`}
            style={mark.style}
            role="row"
            aria-rowindex={index + 2}
            aria-selected={selectedId === packet.id}
            tabIndex={index === activeIndex ? 0 : -1}
            onClick={() => onSelect(packet.id)}
            onContextMenu={(event) => onContextMenu(event, packet)}
            onKeyDown={(event) => onRowKeyDown(event, index, packet)}
          >
            {visibleColumns.map((column) => (
              <span role="gridcell" key={column.id} className={cellClass(column.id, packet)}>
                {cell(column.id, packet, index)}
              </span>
            ))}
          </div>
        );
      }}
    />
  );
});
