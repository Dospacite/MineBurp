import { ArrowDown, ArrowUp } from "lucide-react";
import { useState } from "react";
import type { TimeMode } from "../domain/types";
import { t } from "../i18n";
import { COLUMN_DEFINITIONS, DEFAULT_TABLE_SETTINGS, moveColumn, type TableSettings } from "../lib/columns";
import { newId } from "../lib/ids";
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
  const [path, setPath] = useState("");
  const custom = settings.customColumns ?? [];
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
      <fieldset className="filter-group">
        <legend>{t("columns.decoded")}</legend>
        <p>{t("columns.decoded-note")}</p>
        {custom.map((column) => (
          <div className="decoded-column-setting" key={column.id}>
            <label>
              <input
                type="checkbox"
                checked={column.visible}
                onChange={(e) =>
                  onChange({
                    ...settings,
                    customColumns: custom.map((c) =>
                      c.id === column.id ? { ...c, visible: e.target.checked } : c,
                    ),
                  })
                }
              />
              {t("columns.show")}
            </label>
            <input
              aria-label={t("columns.label")}
              maxLength={80}
              value={column.label}
              onChange={(e) =>
                onChange({
                  ...settings,
                  customColumns: custom.map((c) =>
                    c.id === column.id ? { ...c, label: e.target.value } : c,
                  ),
                })
              }
            />
            <input
              aria-label={t("columns.path")}
              maxLength={256}
              value={column.path}
              onChange={(e) =>
                onChange({
                  ...settings,
                  customColumns: custom.map((c) => (c.id === column.id ? { ...c, path: e.target.value } : c)),
                })
              }
            />
            <button
              type="button"
              className="button"
              onClick={() =>
                onChange({ ...settings, customColumns: custom.filter((c) => c.id !== column.id) })
              }
            >
              {t("columns.remove")}
            </button>
          </div>
        ))}
        <label>
          {t("columns.path")}
          <input
            value={path}
            maxLength={256}
            onChange={(e) => setPath(e.target.value)}
            placeholder="data[0].slot"
          />
        </label>
        <button
          type="button"
          className="button"
          disabled={!path.trim() || custom.length >= 8}
          onClick={() => {
            const value = path.trim();
            onChange({
              ...settings,
              customColumns: [
                ...custom,
                { id: newId(), path: value, label: value.slice(0, 80), visible: true },
              ],
            });
            setPath("");
          }}
        >
          {t("columns.add")}
        </button>
      </fieldset>
    </Modal>
  );
}
