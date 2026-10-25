import { useState } from "react";

import { t } from "../i18n";
import { ANNOTATION_COLORS, type AnnotationStore, annotationStore } from "../lib/annotations";
import { Modal } from "./Modal";

/** Mirrors the backend's note limit, so an oversized note is refused before it is sent. */
const MAX_NOTE_BYTES = 16 * 1024;

/** Edits one packet's bookmark, colour, and note. */
export function AnnotationEditor({
  packetId,
  store = annotationStore,
  onClose,
  onError,
}: {
  packetId: number;
  store?: AnnotationStore;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const current = store.get(packetId);
  const [bookmarked, setBookmarked] = useState(current?.bookmarked ?? false);
  const [color, setColor] = useState<string | null>(current?.color ?? null);
  const [note, setNote] = useState(current?.note ?? "");
  const [saving, setSaving] = useState(false);
  const noteBytes = new TextEncoder().encode(note).length;
  const tooLong = noteBytes > MAX_NOTE_BYTES;

  async function save(next: { bookmarked: boolean; color: string | null; note: string | null }) {
    setSaving(true);
    try {
      await store.update(packetId, next);
      onClose();
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      title={t("annotation.title", { id: packetId })}
      onClose={onClose}
      actions={
        <>
          <button
            type="button"
            className="button"
            disabled={saving || !current}
            onClick={() => void save({ bookmarked: false, color: null, note: null })}
          >
            {t("annotation.clear")}
          </button>
          <button
            type="button"
            className="button primary"
            disabled={saving || tooLong}
            onClick={() => void save({ bookmarked, color, note: note.trim() ? note : null })}
          >
            {t("annotation.save")}
          </button>
        </>
      }
    >
      <div className="annotation-editor">
        <label className="annotation-bookmark">
          <input
            type="checkbox"
            checked={bookmarked}
            onChange={(event) => setBookmarked(event.target.checked)}
          />
          {t("annotation.bookmarked")}
        </label>
        <fieldset className="annotation-colors">
          <legend>{t("annotation.color")}</legend>
          <button
            type="button"
            className={`swatch none ${color === null ? "active" : ""}`}
            aria-pressed={color === null}
            onClick={() => setColor(null)}
          >
            {t("annotation.color.none")}
          </button>
          {ANNOTATION_COLORS.map((name) => (
            <button
              type="button"
              key={name}
              className={`swatch mark-${name} ${color === name ? "active" : ""}`}
              aria-pressed={color === name}
              aria-label={t(`annotation.color.${name}`)}
              title={t(`annotation.color.${name}`)}
              onClick={() => setColor(name)}
            />
          ))}
        </fieldset>
        <label className="annotation-note">
          {t("annotation.note")}
          <textarea
            rows={5}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder={t("annotation.note.placeholder")}
            aria-invalid={tooLong || undefined}
          />
        </label>
        {tooLong && (
          <p className="filter-error" role="alert">
            {t("annotation.note.too-long", { limit: MAX_NOTE_BYTES.toLocaleString() })}
          </p>
        )}
      </div>
    </Modal>
  );
}
