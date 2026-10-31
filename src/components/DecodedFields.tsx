import { memo, useMemo, useState } from "react";

import type { PacketInsight } from "../domain/types";
import { t } from "../i18n";

/** Characters of a single field value shown before it is collapsed. */
const VALUE_LIMIT = 400;
/** Stream entries listed before the rest are summarised. */
const STREAM_LIMIT = 40;

/** Renders a decode as readable fields rather than a JSON blob. */
export const DecodedFields = memo(function DecodedFields({
  insight,
  /** Fields a user-supplied schema pack decoded, shown alongside the built-in ones. */
  schema,
  onSelectField,
  selectFieldNames,
}: {
  insight: PacketInsight;
  schema?: unknown;
  onSelectField?: (name: string) => void;
  selectFieldNames?: string[];
}) {
  // A schema field with a built-in field's name replaces it in place rather
  // than listing the name twice.
  const entries = [
    ...new Map<string, unknown>([
      ...(insight.fields ? Object.entries(insight.fields) : []),
      ...(schema && typeof schema === "object" && !Array.isArray(schema)
        ? Object.entries(schema as Record<string, unknown>)
        : []),
    ]),
  ];

  if (entries.length === 0 && insight.stream.length === 0) {
    return <p className="decoded-empty">{t("fields.none")}</p>;
  }

  return (
    <div className="decoded">
      {entries.length > 0 && (
        <dl className="decoded-grid">
          {entries.map(([key, value]) => (
            <div key={key}>
              <dt>
                {onSelectField && (!selectFieldNames || selectFieldNames.includes(key)) ? (
                  <button type="button" className="field-select-button" onClick={() => onSelectField(key)}>
                    {key.replaceAll("_", " ")}
                  </button>
                ) : (
                  key.replaceAll("_", " ")
                )}
              </dt>
              <dd>
                <FieldValue value={value} />
              </dd>
            </div>
          ))}
        </dl>
      )}

      {insight.stream.length > 0 && (
        <ol className="decoded-stream">
          {insight.stream.slice(0, STREAM_LIMIT).map((packet) => (
            <li key={packet.offset}>
              <span className="stream-offset">+{packet.offset}</span>
              <span className="stream-name">
                {packet.name ??
                  (packet.packet_id === null ? t("stream.unknown") : `0x${packet.packet_id.toString(16)}`)}
              </span>
              <span className="stream-summary">{packet.summary ?? `${packet.length} B`}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
});

/**
 * Shows control characters as their Unicode control pictures, so a Forge
 * handshake address reads `host␀FORGE` instead of hiding the NUL.
 */
export function visibleControls(text: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point.
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, (control) =>
    String.fromCharCode(control === "\u007f" ? 0x2421 : 0x2400 + control.charCodeAt(0)),
  );
}

function FieldValue({ value }: { value: unknown }) {
  const [expanded, setExpanded] = useState(false);
  // Serialising a large decoded value (NBT, a chunk's block entities) is the
  // expensive part of rendering a field, so it is done once per value.
  const text = useMemo(
    () =>
      typeof value === "string"
        ? visibleControls(value)
        : value === null
          ? "—"
          : typeof value === "object"
            ? JSON.stringify(value)
            : String(value),
    [value],
  );

  if (text.length <= VALUE_LIMIT) return <span className="field-value">{text}</span>;
  return (
    <span className="field-value">
      {expanded ? text : `${text.slice(0, VALUE_LIMIT)}…`}{" "}
      <button type="button" className="link-button" onClick={() => setExpanded(!expanded)}>
        {expanded ? t("fields.less") : t("fields.more")}
      </button>
    </span>
  );
}
