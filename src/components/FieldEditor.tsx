import { useEffect, useState } from "react";

import type { FieldKind, FieldSpan, PacketLayout } from "../domain/types";
import { t } from "../i18n";

/**
 * The decoded, editable view of a frame.
 *
 * Each row is one span of the frame's bytes. Committing an edit asks the
 * backend to re-encode that span and splice it back in, so the hex and the
 * decoded values are always two views of the same buffer rather than two
 * copies that can drift apart.
 */
export function FieldEditor({
  layout,
  onCommit,
  busy,
}: {
  layout: PacketLayout | null;
  onCommit: (field: FieldSpan, value: string | boolean) => void;
  busy: boolean;
}) {
  if (!layout || layout.fields.length === 0) {
    return <p className="decoded-empty">{t("fields.none")}</p>;
  }

  return (
    <div className={`field-editor ${busy ? "busy" : ""}`}>
      {layout.fields.map((field) => (
        <FieldRow
          key={`${field.offset}-${field.name}`}
          field={field}
          onCommit={(value) => onCommit(field, value)}
        />
      ))}
    </div>
  );
}

function FieldRow({ field, onCommit }: { field: FieldSpan; onCommit: (value: string | boolean) => void }) {
  const [draft, setDraft] = useState(() => text(field.value));

  // A re-decode after any edit replaces the values under the editor, so the
  // draft follows the frame rather than the keystrokes that produced it.
  useEffect(() => setDraft(text(field.value)), [field.value]);

  if (field.kind === "bool") {
    return (
      <label className="field-row field-boolean">
        <span className="field-name">{field.name}</span>
        <input
          type="checkbox"
          checked={field.value === true}
          onChange={(event) => onCommit(event.target.checked)}
        />
        <span className="field-kind">{field.kind}</span>
      </label>
    );
  }

  if (isNbt(field.kind)) {
    return (
      <label className="field-row field-nbt">
        <span className="field-name">{field.name}</span>
        <textarea
          className="field-input nbt-json"
          spellCheck={false}
          rows={Math.min(18, Math.max(2, draft.split("\n").length))}
          value={draft}
          placeholder={t("fields.nbt.absent")}
          title={t("fields.nbt.hint")}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => draft !== text(field.value) && onCommit(draft)}
          onKeyDown={(event) => {
            // Enter adds lines; Ctrl/Cmd+Enter commits, as Escape discards.
            if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
              event.preventDefault();
              event.stopPropagation();
              event.currentTarget.blur();
            }
            if (event.key === "Escape") setDraft(text(field.value));
          }}
        />
        <span className="field-kind">nbt</span>
      </label>
    );
  }

  // A single-line input drops line breaks, so text holding one (a chat line,
  // a sign) is edited in a textarea or it would lose them on commit.
  const multiline =
    field.kind === "bytes" || field.kind === "prefixed_bytes" || draft.length > 96 || draft.includes("\n");

  return (
    <label className="field-row">
      <span className="field-name">{field.name}</span>
      {multiline ? (
        <textarea
          className={`field-input ${field.kind === "string" ? "" : "hex"}`}
          spellCheck={false}
          rows={Math.min(12, Math.max(draft.split("\n").length, Math.ceil(draft.length / 64)) || 1)}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => draft !== text(field.value) && onCommit(draft)}
        />
      ) : (
        <input
          className={`field-input ${numeric(field.kind) ? "numeric" : ""}`}
          spellCheck={false}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => draft !== text(field.value) && onCommit(draft)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              event.currentTarget.blur();
            }
            if (event.key === "Escape") setDraft(text(field.value));
          }}
        />
      )}
      <span className="field-kind">{field.kind}</span>
    </label>
  );
}

function text(value: FieldSpan["value"]): string {
  return value === null ? "" : String(value);
}

function numeric(kind: FieldKind): boolean {
  return !["string", "bytes", "prefixed_bytes", "bool", "nbt", "named_nbt", "prefixed_nbt"].includes(kind);
}

function isNbt(kind: FieldKind): boolean {
  return kind === "nbt" || kind === "named_nbt" || kind === "prefixed_nbt";
}
