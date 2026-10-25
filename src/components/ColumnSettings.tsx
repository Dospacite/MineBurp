import { ArrowDown, ArrowUp } from "lucide-react";

import type { TimeMode } from "../domain/types";
import { t } from "../i18n";
import { COLUMN_DEFINITIONS, DEFAULT_TABLE_SETTINGS, moveColumn, type TableSettings } from "../lib/columns";
import { Modal } from "./Modal";

const TIME_MODES: TimeMode[] = ["absolute", "relative", "delta"];

/** Shows, hides, and orders the history columns, and picks how time reads. */
export function ColumnSettings({
  settings,
  onChange,
  onClose,
}: {
  settings: TableSettings;
  onChange: (settings: TableSettings) => void;
  onClose: () => void;
}) {
  const { columns } = settings;
  return (
    <Modal
      title={t("columns.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={() => onChange(DEFAULT_TABLE_SETTINGS)}>
            {t("columns.reset")}
          </button>
          <button type="button" className="button primary" onClick={onClose}>
            {t("filter.done")}
          </button>
        </>
      }
    >
      <fieldset className="filter-group">
        <legend>{t("columns.time-mode")}</legend>
        <div className="segmented">
          {TIME_MODES.map((mode) => (
            <button
              type="button"
              key={mode}
              className={settings.timeMode === mode ? "active" : ""}
              aria-pressed={settings.timeMode === mode}
              onClick={() => onChange({ ...settings, timeMode: mode })}
            >
              {t(`columns.time-mode.${mode}`)}
            </button>
          ))}
        </div>
        <p className="filter-hint">{t("columns.time-mode.hint")}</p>
      </fieldset>
      <fieldset className="filter-group">
        <legend>{t("columns.visible")}</legend>
        <ul className="column-list">
          {columns.map((column, index) => (
            <li key={column.id}>
              <label>
                <input
                  type="checkbox"
                  checked={column.visible}
                  disabled={column.id === "packet"}
                  onChange={(event) =>
                    onChange({
                      ...settings,
                      columns: columns.map((item) =>
                        item.id === column.id ? { ...item, visible: event.target.checked } : item,
                      ),
                    })
                  }
                />
                {t(COLUMN_DEFINITIONS[column.id].label)}
              </label>
              <button
                type="button"
                className="icon-button"
                aria-label={t("columns.move-up", { name: t(COLUMN_DEFINITIONS[column.id].label) })}
                disabled={index === 0}
                onClick={() => onChange({ ...settings, columns: moveColumn(columns, column.id, -1) })}
              >
                <ArrowUp size={13} aria-hidden="true" />
              </button>
              <button
                type="button"
                className="icon-button"
                aria-label={t("columns.move-down", { name: t(COLUMN_DEFINITIONS[column.id].label) })}
                disabled={index === columns.length - 1}
                onClick={() => onChange({ ...settings, columns: moveColumn(columns, column.id, 1) })}
              >
                <ArrowDown size={13} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      </fieldset>
    </Modal>
  );
}
