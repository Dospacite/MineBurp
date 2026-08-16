import { useState } from "react";

import type { PacketInsight } from "../domain/types";

/** Characters of a single field value shown before it is collapsed. */
const VALUE_LIMIT = 400;
/** Stream entries listed before the rest are summarised. */
const STREAM_LIMIT = 40;

/** Renders a decode as readable fields rather than a JSON blob. */
export function DecodedFields({
  insight,
  /** Fields a user-supplied schema pack decoded, shown alongside the built-in ones. */
  schema,
}: {
  insight: PacketInsight;
  schema?: unknown;
}) {
  const entries = [
    ...(insight.fields ? Object.entries(insight.fields) : []),
    ...(schema && typeof schema === "object" && !Array.isArray(schema)
      ? Object.entries(schema as Record<string, unknown>)
      : []),
  ];

  if (entries.length === 0 && insight.stream.length === 0) {
    return <p className="decoded-empty">No decoded fields</p>;
  }

  return (
    <div className="decoded">
      {entries.length > 0 && (
        <dl className="decoded-grid">
          {entries.map(([key, value]) => (
            <div key={key}>
              <dt>{key.replaceAll("_", " ")}</dt>
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
                  (packet.packet_id === null ? "unknown" : `0x${packet.packet_id.toString(16)}`)}
              </span>
              <span className="stream-summary">{packet.summary ?? `${packet.length} B`}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function FieldValue({ value }: { value: unknown }) {
  const [expanded, setExpanded] = useState(false);
  const text =
    typeof value === "string"
      ? value
      : value === null
        ? "—"
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);

  if (text.length <= VALUE_LIMIT) return <span className="field-value">{text}</span>;
  return (
    <span className="field-value">
      {expanded ? text : `${text.slice(0, VALUE_LIMIT)}…`}{" "}
      <button className="link-button" onClick={() => setExpanded(!expanded)}>
        {expanded ? "less" : "more"}
      </button>
    </span>
  );
}
