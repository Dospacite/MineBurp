import { Bookmark } from "lucide-react";
import { useEffect, useState } from "react";

import type { PacketAnnotation } from "../domain/types";
import { t } from "../i18n";
import { annotationColorStyle, annotationStore, useAnnotations } from "../lib/annotations";
import { desktop } from "../lib/desktop";
import { formatAbsolute } from "../lib/time";
import { Modal } from "./Modal";

/** How many annotations the list loads; the backend allows up to 10 000. */
const LIST_LIMIT = 2_000;

/**
 * Every annotated packet in the project, newest first. Choosing one selects it
 * in the history's inspector.
 */
export function BookmarksDialog({
  onSelect,
  onClose,
  onError,
}: {
  onSelect: (packetId: number) => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [rows, setRows] = useState<PacketAnnotation[] | null>(null);
  // Edits made elsewhere while the list is open show up in it.
  const live = useAnnotations();

  useEffect(() => {
    let current = true;
    void desktop
      .packetAnnotationsList(LIST_LIMIT)
      .then((list) => current && setRows(list))
      .catch((reason) => {
        if (current) {
          setRows([]);
          onError(reason instanceof Error ? reason.message : String(reason));
        }
      });
    return () => {
      current = false;
    };
  }, [onError]);

  const entries = (rows ?? [])
    .map((row) => live.get(row.packetId) ?? (annotationStore.has(row.packetId) ? null : row))
    .filter((row): row is PacketAnnotation => row !== null);

  return (
    <Modal title={t("bookmarks.title")} wide onClose={onClose}>
      {rows === null ? (
        <p className="decoded-empty">{t("bookmarks.loading")}</p>
      ) : entries.length === 0 ? (
        <p className="decoded-empty">{t("bookmarks.empty")}</p>
      ) : (
        <ul className="bookmark-list">
          {entries.map((entry) => {
            const mark = annotationColorStyle(entry.color);
            return (
              <li key={entry.packetId}>
                <button
                  type="button"
                  className={`bookmark-entry ${mark.className}`}
                  style={mark.style}
                  onClick={() => {
                    onSelect(entry.packetId);
                    onClose();
                  }}
                >
                  <span className="bookmark-id">
                    {entry.bookmarked && <Bookmark size={12} aria-label={t("annotation.bookmarked")} />}#
                    {entry.packetId}
                  </span>
                  <span className="bookmark-note">{entry.note ?? t("bookmarks.no-note")}</span>
                  <time className="bookmark-time">{formatAbsolute(entry.updatedAtMicros)}</time>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </Modal>
  );
}
