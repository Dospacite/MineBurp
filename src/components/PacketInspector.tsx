import {
  Bookmark,
  BookmarkCheck,
  Check,
  ClipboardCopy,
  Copy,
  Download,
  GitCompare,
  Loader2,
  Send,
  StickyNote,
} from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ByteWindow, FieldSpan, PacketLayout, PacketView } from "../domain/types";
import { t } from "../i18n";
import { annotationColorStyle, annotationStore, useAnnotations } from "../lib/annotations";
import {
  base64ToBytes,
  copyText,
  desktop,
  downloadBytes,
  formatBase64,
  formatCArray,
  formatHex,
  formatRawHex,
  readPayload,
} from "../lib/desktop";
import { formatAbsolute } from "../lib/time";
import { AnnotationEditor } from "./AnnotationEditor";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { DecodedFields } from "./DecodedFields";
import { EmptyState } from "./EmptyState";
import { FieldTree, fieldAt } from "./FieldTree";
import { addToFinding } from "./FindingPicker";
import { type ByteRange, HEX_PAGE_BYTES, HexView } from "./HexView";
import { SelectionToolbar } from "./SelectionToolbar";
import { Split } from "./Split";

/** Text copies stop here; the binary download always takes the whole payload. */
export const COPY_LIMIT = 4 * 1024 * 1024;

export type CopyFormat = "dump" | "hex" | "base64" | "c" | "json";

const TAB_KEY = "mineburp.inspector.tab";

export const PacketInspector = memo(function PacketInspector({
  packet,
  onRepeater,
  onCompare,
  onError,
  onNotice,
}: {
  packet: PacketView | null;
  onRepeater: (packet: PacketView) => void;
  /** Sets this packet as one side of the comparison. */
  onCompare?: (id: number) => void;
  onError: (error: string) => void;
  onNotice?: (notice: string) => void;
}) {
  const loaded = useMemo(() => (packet ? base64ToBytes(packet.bytes_base64) : new Uint8Array()), [packet]);
  /** The page the hex view is showing, which paging can move off `loaded`. */
  const [visible, setVisible] = useState<{ bytes: Uint8Array; offset: number } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const [tab, setTab] = useState<"fields" | "structure">(() =>
    localStorage.getItem(TAB_KEY) === "structure" ? "structure" : "fields",
  );
  const [layout, setLayout] = useState<PacketLayout | null>(null);
  const [selectedField, setSelectedField] = useState<FieldSpan | null>(null);
  const [marked, setMarked] = useState<ByteRange | null>(null);
  const layoutRequest = useRef(0);
  const packetId = packet?.summary.id ?? null;
  const [annotating, setAnnotating] = useState(false);
  const annotation = useAnnotations().get(packetId ?? -1) ?? null;

  useEffect(() => {
    setAnnotating(false);
    if (packetId === null || !desktop.isAvailable()) return;
    annotationStore
      .ensure([packetId])
      .catch((reason) => onError(reason instanceof Error ? reason.message : String(reason)));
  }, [packetId, onError]);

  // The structure view needs offsets, which only `packet_layout` reports.
  useEffect(() => {
    const requestId = ++layoutRequest.current;
    setLayout(null);
    setMarked(null);
    setSelectedField(null);
    setVisible(null);
    if (!packet || !desktop.isAvailable()) return;
    const { state, direction, protocol_version } = packet.summary;
    if (state === "opaque" || state === "closed" || loaded.length === 0) return;
    // `loaded` is only the leading window; a larger packet is walked from the
    // stored payload so the structure covers all of it.
    const whole = packet.bytes_offset === 0 && loaded.length >= packet.total_bytes;
    void (
      whole
        ? desktop.packetLayout(loaded, state, direction, protocol_version)
        : desktop.packetLayoutStored(packet.summary.id)
    )
      .then((next) => {
        if (requestId === layoutRequest.current) setLayout(next);
      })
      .catch(() => undefined);
  }, [packet, loaded]);

  const onBytesChange = useCallback((bytes: Uint8Array | null, offset: number) => {
    setVisible(bytes ? { bytes, offset } : null);
  }, []);

  const onHexSelection = useCallback(
    (range: ByteRange | null) => {
      setMarked(range);
      const field = range && layout ? fieldAt(layout.fields, range.offset) : null;
      setSelectedField(
        range && field && range.offset === field.offset && range.length === field.length ? field : null,
      );
    },
    [layout],
  );

  const onFieldSelect = useCallback(
    (field: FieldSpan) => {
      setMarked({ offset: field.offset, length: field.length });
      setSelectedField(
        layout?.fields.find(
          (item) => item.name === field.name && item.offset === field.offset && item.length === field.length,
        ) ?? null,
      );
    },
    [layout],
  );

  const loadWindow = useCallback(
    (offset: number, limit: number): Promise<ByteWindow | null> =>
      packetId === null
        ? Promise.resolve(null)
        : desktop.packetBytes(packetId, offset, Math.min(limit, HEX_PAGE_BYTES)),
    [packetId],
  );

  const loadAll = useCallback(
    async (limit: number) => {
      if (!packet) return new Uint8Array();
      if (packet.bytes_offset === 0 && loaded.length >= Math.min(limit, packet.total_bytes)) return loaded;
      return (await readPayload(packet.summary.id, limit)).bytes;
    },
    [loaded, packet],
  );

  if (!packet) {
    return <EmptyState title={t("inspector.none.title")} detail={t("inspector.none.detail")} />;
  }

  const { summary, insight, wire } = packet;

  /** The whole payload up to `limit`, reusing the window that came with the packet when it is enough. */
  async function payload(limit: number): Promise<{ bytes: Uint8Array; complete: boolean }> {
    if (!packet) return { bytes: new Uint8Array(), complete: true };
    if (packet.bytes_offset === 0 && loaded.length >= packet.total_bytes) {
      return { bytes: loaded.subarray(0, Math.min(limit, loaded.length)), complete: loaded.length <= limit };
    }
    const result = await readPayload(packet.summary.id, limit);
    return { bytes: result.bytes, complete: result.complete };
  }

  async function copyAs(format: CopyFormat) {
    if (!packet) return;
    setBusy(format);
    try {
      const { bytes, complete } = await payload(COPY_LIMIT);
      await copyText(renderCopy(format, bytes, packet));
      flash(format);
      if (!complete) {
        onNotice?.(
          t("inspector.copy.partial", {
            copied: bytes.length.toLocaleString(),
            total: packet.total_bytes.toLocaleString(),
          }),
        );
      }
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  }

  async function copyPage() {
    if (!visible) return;
    try {
      await copyText(formatRawHex(visible.bytes));
      flash("page");
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  async function download() {
    if (!packet) return;
    setBusy("download");
    try {
      const { bytes } = await payload(Number.POSITIVE_INFINITY);
      downloadBytes(bytes, `packet-${packet.summary.id}.bin`);
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(null);
    }
  }

  function flash(key: string) {
    setCopied(key);
    window.setTimeout(() => setCopied((value) => (value === key ? null : value)), 1500);
  }

  const copyItems: MenuItem[] = [
    { label: t("copy.as.dump"), onSelect: () => void copyAs("dump") },
    { label: t("copy.as.hex"), onSelect: () => void copyAs("hex") },
    { label: t("copy.as.base64"), onSelect: () => void copyAs("base64") },
    { label: t("copy.as.c"), onSelect: () => void copyAs("c") },
    { label: t("copy.as.json"), onSelect: () => void copyAs("json") },
  ];

  const pageEnd = visible ? visible.offset + visible.bytes.length : 0;
  const name =
    insight.label ??
    insight.name ??
    summary.name ??
    (summary.packet_id === null ? t("table.raw-stream") : `0x${summary.packet_id.toString(16)}`);
  const markedKey = marked ? `${marked.offset}:${marked.length}` : null;

  return (
    <section className="inspector">
      <header className="inspector-header">
        <div className="inspector-meta">
          <span className={`direction ${summary.direction}`}>
            {summary.direction === "client_to_server" ? t("flow.c2s") : t("flow.s2c")}
          </span>
          <span>{packet.total_bytes.toLocaleString()} B</span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className={`icon-button ${annotation?.bookmarked ? "on" : ""}`}
            title={annotation?.bookmarked ? t("menu.bookmark.remove") : t("menu.bookmark")}
            aria-label={annotation?.bookmarked ? t("menu.bookmark.remove") : t("menu.bookmark")}
            aria-pressed={annotation?.bookmarked ?? false}
            onClick={() =>
              void annotationStore
                .toggleBookmark(summary.id)
                .catch((reason) => onError(reason instanceof Error ? reason.message : String(reason)))
            }
          >
            {annotation?.bookmarked ? (
              <BookmarkCheck size={15} aria-hidden="true" />
            ) : (
              <Bookmark size={15} aria-hidden="true" />
            )}
          </button>
          <button
            type="button"
            className="icon-button"
            title={t("menu.annotate")}
            aria-label={t("menu.annotate")}
            onClick={() => setAnnotating(true)}
          >
            <StickyNote size={15} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="icon-button"
            title={t("inspector.copy-as")}
            aria-label={t("inspector.copy-as")}
            aria-haspopup="menu"
            disabled={busy !== null}
            onClick={(event) => {
              const rect = event.currentTarget.getBoundingClientRect();
              setMenu({ x: rect.left, y: rect.bottom + 4 });
            }}
          >
            {busy && busy !== "download" ? (
              <Loader2 className="spin" size={15} aria-hidden="true" />
            ) : copied && copied !== "page" ? (
              <Check size={15} aria-hidden="true" />
            ) : (
              <ClipboardCopy size={15} aria-hidden="true" />
            )}
          </button>
          <button
            type="button"
            className="icon-button"
            title={t("inspector.download")}
            aria-label={t("inspector.download")}
            disabled={packet.total_bytes === 0 || busy !== null}
            onClick={() => void download()}
          >
            {busy === "download" ? (
              <Loader2 className="spin" size={15} aria-hidden="true" />
            ) : (
              <Download size={15} aria-hidden="true" />
            )}
          </button>
          {onCompare && (
            <button
              type="button"
              className="icon-button"
              title={t("inspector.compare")}
              aria-label={t("inspector.compare")}
              onClick={() => onCompare(summary.id)}
            >
              <GitCompare size={15} aria-hidden="true" />
            </button>
          )}
          <button
            type="button"
            className="button"
            onClick={() => onRepeater(packet)}
            title={t("menu.repeater.title")}
          >
            <Send size={14} aria-hidden="true" />
            <span className="button-label">{t("inspector.repeater")}</span>
          </button>
          <button type="button" onClick={() => addToFinding([{ kind: "packet", id: summary.id }])}>
            {t("findings.add")}
          </button>
        </div>
      </header>
      {annotating && (
        <AnnotationEditor packetId={summary.id} onClose={() => setAnnotating(false)} onError={onError} />
      )}
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={copyItems}
          label={t("inspector.copy-as")}
          onClose={() => setMenu(null)}
        />
      )}
      <div className="inspector-info">
        <div className="inspector-title">
          <strong>{name}</strong>
          <span
            className={`identification ${insight.identification}`}
            title={t(`identification.${insight.identification}.title`)}
          >
            {t(`identification.${insight.identification}`)}
          </span>
        </div>
        {insight.summary && <p className="inspector-summary">{insight.summary}</p>}
        {annotation?.note && (
          <p
            className={`inspector-note ${annotationColorStyle(annotation.color).className}`}
            style={annotationColorStyle(annotation.color).style}
          >
            {annotation.note}
          </p>
        )}
        <dl className="inspector-facts">
          <Fact label={t("info.time")} value={formatAbsolute(summary.timestamp_micros)} />
          <Fact label={t("info.state")} value={summary.state} />
          <Fact
            label={t("info.id")}
            value={
              summary.packet_id === null ? "—" : `0x${summary.packet_id.toString(16)} (${summary.packet_id})`
            }
          />
          <Fact label={t("info.protocol")} value={summary.protocol_version?.toString() ?? "—"} />
          <Fact label={t("info.result")} value={summary.disposition} />
          <Fact
            label={t("info.wire")}
            value={t("info.wire.value", {
              frame: wire.frame_length.toLocaleString(),
              logical: wire.logical_length.toLocaleString(),
            })}
          />
          {(insight.channel ?? summary.channel) && (
            <Fact label={t("info.channel")} value={insight.channel ?? summary.channel ?? ""} />
          )}
          {(insight.loader ?? summary.loader) && (
            <Fact label={t("info.loader")} value={insight.loader ?? summary.loader ?? ""} />
          )}
          {summary.flow && (
            <Fact
              label={t("info.flow")}
              value={`${summary.flow.transport} ${summary.flow.local_address} → ${summary.flow.remote_address}${
                summary.flow.process_id === null ? "" : ` · pid ${summary.flow.process_id}`
              }`}
            />
          )}
        </dl>
        <div className="inspector-flags">
          {wire.compressed && <span className="flag">{t("info.flag.compressed")}</span>}
          {wire.encrypted && <span className="flag">{t("info.flag.encrypted")}</span>}
          {wire.truncated && <span className="flag warn">{t("info.flag.truncated")}</span>}
        </div>
        {insight.error && (
          <p className="inspector-error" role="note">
            {t("info.decode-error", { error: insight.error })}
          </p>
        )}
        {packet.schema_decode_error && (
          <p className="inspector-error" role="note">
            {t("info.schema-error", { error: packet.schema_decode_error })}
          </p>
        )}
      </div>
      <div className="inspector-selection">
        <SelectionToolbar packet={packet} range={marked} field={selectedField} onError={onError} />
      </div>
      <Split
        orientation="rows"
        storageKey="inspector"
        initial={[0.45, 0.55]}
        minimum={110}
        className="inspector-body"
      >
        <div className="inspector-section">
          <div className="section-tabs" role="tablist" aria-label={t("inspector.fields")}>
            {(["fields", "structure"] as const).map((key) => (
              <button
                type="button"
                role="tab"
                key={key}
                aria-selected={tab === key}
                className={tab === key ? "active" : ""}
                onClick={() => {
                  setTab(key);
                  localStorage.setItem(TAB_KEY, key);
                }}
              >
                {key === "fields" ? t("inspector.fields") : t("structure.title")}
              </button>
            ))}
          </div>
          <div className="inspector-scroll" role="tabpanel">
            {tab === "fields" ? (
              <DecodedFields
                insight={insight}
                schema={packet.schema_decoded}
                selectFieldNames={layout?.fields.map((field) => field.name) ?? []}
                onSelectField={(name) => {
                  const field = layout?.fields.find((f) => f.name === name);
                  if (field) onFieldSelect(field);
                }}
              />
            ) : (
              <FieldTree layout={layout} selected={markedKey} onSelect={onFieldSelect} />
            )}
          </div>
        </div>
        <div className="inspector-section">
          <header className="section-header">
            <h3>{t("inspector.bytes")}</h3>
            <button
              type="button"
              className="link-button"
              title={t("inspector.copy-page.title")}
              disabled={!visible || visible.bytes.length === 0}
              onClick={() => void copyPage()}
            >
              {copied === "page" ? (
                <Check size={12} aria-hidden="true" />
              ) : (
                <Copy size={12} aria-hidden="true" />
              )}{" "}
              {packet.total_bytes > (visible?.bytes.length ?? 0)
                ? t("inspector.copy-page", {
                    from: (visible?.offset ?? 0).toLocaleString(),
                    to: pageEnd.toLocaleString(),
                  })
                : t("inspector.raw-hex")}
            </button>
          </header>
          <HexView
            sourceKey={summary.id}
            total={packet.total_bytes}
            initial={{ offset: packet.bytes_offset, bytes: loaded }}
            loadWindow={loadWindow}
            loadAll={loadAll}
            onBytesChange={onBytesChange}
            highlight={marked}
            onSelectionChange={onHexSelection}
          />
        </div>
      </Split>
    </section>
  );
});

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

/** One packet's bytes in a copyable format. JSON also carries the summary and decode. */
export function renderCopy(format: CopyFormat, bytes: Uint8Array, packet: PacketView | null): string {
  switch (format) {
    case "dump":
      return formatHex(bytes, 16, 0);
    case "hex":
      return formatRawHex(bytes);
    case "base64":
      return formatBase64(bytes);
    case "c":
      return formatCArray(bytes, packet?.summary.name?.replace(/\W/g, "_") || "packet");
    case "json":
      return JSON.stringify(
        {
          ...(packet ? { summary: packet.summary, fields: packet.insight.fields } : {}),
          size: packet?.total_bytes ?? bytes.length,
          bytes_hex: formatRawHex(bytes).replaceAll(" ", ""),
          complete: packet ? bytes.length >= packet.total_bytes : true,
        },
        null,
        2,
      );
  }
}
