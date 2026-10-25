import { useEffect, useState } from "react";

import type { DeleteSummary, PacketHistoryQuery } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { formatBytes } from "../lib/format";
import { Modal } from "./Modal";

/**
 * Confirms deleting every packet the current filter matches.
 *
 * The count comes from the same filter the delete will run with, so what the
 * dialog says is what goes. A filter that narrows nothing is the whole
 * project, and the dialog says so in as many words.
 */
export function DeleteHistoryDialog({
  query,
  scope,
  narrowed,
  onDeleted,
  onClose,
  onError,
}: {
  query: PacketHistoryQuery;
  /** A readable description of the filter and connection. */
  scope: string;
  /** False when neither a filter nor a connection narrows the history. */
  narrowed: boolean;
  onDeleted: (summary: DeleteSummary) => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [count, setCount] = useState<{ packets: number; bytes: number } | null>(null);
  const [prune, setPrune] = useState(true);
  const [busy, setBusy] = useState(false);
  const queryKey = JSON.stringify(query);

  useEffect(() => {
    let current = true;
    setCount(null);
    void desktop
      .trafficStats(JSON.parse(queryKey), { maxBuckets: 1, top: 1 })
      .then((stats) => current && setCount({ packets: stats.totalPackets, bytes: stats.totalBytes }))
      .catch((reason) => current && onError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      current = false;
    };
  }, [onError, queryKey]);

  async function confirm() {
    setBusy(true);
    try {
      const summary = await desktop.packetsDelete(JSON.parse(queryKey), prune);
      onDeleted(summary);
      onClose();
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={t("delete.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={onClose}>
            {t("form.cancel")}
          </button>
          <button
            type="button"
            className="button danger"
            disabled={busy || count === null || count.packets === 0}
            onClick={() => void confirm()}
          >
            {count === null
              ? t("delete.confirm.pending")
              : t("delete.confirm", { count: count.packets.toLocaleString() })}
          </button>
        </>
      }
    >
      <div className="delete-history">
        {!narrowed && (
          <p className="delete-warning" role="alert">
            {t("delete.everything")}
          </p>
        )}
        <p>{t("delete.scope", { scope })}</p>
        <p aria-live="polite">
          {count === null
            ? t("delete.counting")
            : count.packets === 0
              ? t("delete.nothing")
              : t("delete.count", {
                  count: count.packets.toLocaleString(),
                  bytes: formatBytes(count.bytes),
                })}
        </p>
        <label className="filter-field inline">
          <input type="checkbox" checked={prune} onChange={(event) => setPrune(event.target.checked)} />
          {t("delete.prune")}
        </label>
        <p className="filter-hint">{t("delete.hint")}</p>
      </div>
    </Modal>
  );
}
