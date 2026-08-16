import { Info, ShieldAlert } from "lucide-react";
import { useState } from "react";

import type { PacketInsight } from "../domain/types";

/** Characters of a single field value shown before it is collapsed. */
const VALUE_LIMIT = 400;
/** Stream entries listed before the rest are summarised. */
const STREAM_LIMIT = 40;

/**
 * Renders a decode as readable fields rather than a JSON blob.
 *
 * The old inspector printed `JSON.stringify(decoded, null, 2)`, which for a
 * large decode is both slow to build and hard to read.
 */
export function DecodedFields({ insight }: { insight: PacketInsight }) {
  const entries = insight.fields ? Object.entries(insight.fields) : [];

  return (
    <div className="decoded">
      {insight.summary && (
        <p className="decoded-summary">
          {insight.summary}
          <span className={`decode-badge ${insight.identification}`}>
            {insight.identification === "registry"
              ? "identified by packet id"
              : insight.identification === "structure"
                ? "identified by body shape"
                : "not identified"}
          </span>
        </p>
      )}

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
        <section className="decoded-stream">
          <h4>Frames in this payload</h4>
          <ol>
            {insight.stream.slice(0, STREAM_LIMIT).map((packet) => (
              <li key={packet.offset}>
                <span className="stream-offset">+{packet.offset}</span>
                <span className="stream-name">
                  {packet.name ??
                    (packet.packet_id === null ? "unknown" : `0x${packet.packet_id.toString(16)}`)}
                </span>
                <span className="stream-summary">{packet.summary ?? `${packet.length} bytes`}</span>
              </li>
            ))}
          </ol>
          {insight.stream.length > STREAM_LIMIT && (
            <p className="muted">
              …and {insight.stream.length - STREAM_LIMIT} more frames in this payload.
            </p>
          )}
        </section>
      )}

      {insight.error && (
        <p className="decode-error">
          <ShieldAlert size={13} aria-hidden="true" /> {insight.error}
        </p>
      )}

      {insight.notes.map((note) => (
        <p className="decode-note" key={note}>
          <Info size={13} aria-hidden="true" /> {note}
        </p>
      ))}
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
        {expanded ? "show less" : `show all ${text.length.toLocaleString()} characters`}
      </button>
    </span>
  );
}
