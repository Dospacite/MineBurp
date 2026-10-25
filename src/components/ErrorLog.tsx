import type { LogEntry } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { copyText } from "../lib/desktop";
import { formatAbsolute } from "../lib/time";
import { Modal } from "./Modal";

/**
 * Every error and notice of the session, newest first.
 *
 * The toast shows one message at a time, so a burst of failures used to leave
 * only the last one readable.
 */
export function ErrorLog({
  entries,
  onClear,
  onClose,
  onError,
}: {
  entries: LogEntry[];
  onClear: () => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const text = entries
    .map(
      (entry) =>
        `${formatAbsolute(entry.at * 1_000)} ${entry.tone.toUpperCase()}${entry.count > 1 ? ` ×${entry.count}` : ""} ${entry.text}`,
    )
    .join("\n");

  return (
    <Modal
      title={t("log.title")}
      wide
      onClose={onClose}
      actions={
        <>
          <button
            type="button"
            className="button"
            disabled={entries.length === 0}
            onClick={() => void copyText(text).catch((reason) => onError(String(reason)))}
          >
            {t("log.copy")}
          </button>
          <button type="button" className="button" disabled={entries.length === 0} onClick={onClear}>
            {t("log.clear")}
          </button>
          <button type="button" className="button primary" onClick={onClose}>
            {t("filter.done")}
          </button>
        </>
      }
    >
      {entries.length === 0 ? (
        <p className="decoded-empty">{t("log.empty")}</p>
      ) : (
        <ol className="error-log">
          {entries.map((entry) => (
            <li key={entry.id} className={entry.tone}>
              <time dateTime={new Date(entry.at).toISOString()}>{formatAbsolute(entry.at * 1_000)}</time>
              <span className="error-log-tone">{t(`log.tone.${entry.tone}`)}</span>
              <span className="error-log-text">{entry.text}</span>
              {entry.count > 1 && <span className="error-log-count">×{entry.count}</span>}
            </li>
          ))}
        </ol>
      )}
    </Modal>
  );
}
