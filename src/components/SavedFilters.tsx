import { BookmarkPlus, ListFilter, Settings2, Trash2 } from "lucide-react";
import { useCallback, useRef, useState } from "react";

import type { PacketFilter, SavedFilter } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { fromSavedPayload, toSavedPayload } from "../lib/savedFilters";
import { ContextMenu, type MenuItem } from "./ContextMenu";
import { Modal } from "./Modal";

/**
 * Named filters stored in the project: a menu to apply one, save the current
 * filter, or open the list to rename and delete them.
 */
export function SavedFilters({
  filter,
  onApply,
  onError,
  onNotice,
}: {
  filter: PacketFilter;
  onApply: (filter: PacketFilter) => void;
  onError: (error: string) => void;
  onNotice?: (notice: string) => void;
}) {
  const [saved, setSaved] = useState<SavedFilter[] | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const [dialog, setDialog] = useState<"save" | "manage" | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const fail = useCallback(
    (reason: unknown) => onError(reason instanceof Error ? reason.message : String(reason)),
    [onError],
  );

  const load = useCallback(async () => {
    try {
      const list = await desktop.savedFilters();
      setSaved([...list].sort((a, b) => a.name.localeCompare(b.name)));
    } catch (reason) {
      setSaved([]);
      fail(reason);
    }
  }, [fail]);

  function openMenu() {
    const rect = button.current?.getBoundingClientRect();
    setMenu({ x: rect?.left ?? 0, y: rect?.bottom ?? 0 });
    void load();
  }

  const items: MenuItem[] = [{ kind: "heading", label: t("saved.heading") }];
  if (saved === null) {
    items.push({ label: t("saved.loading"), disabled: true, onSelect: () => undefined });
  } else if (saved.length === 0) {
    items.push({ label: t("saved.none"), disabled: true, onSelect: () => undefined });
  } else {
    for (const entry of saved) {
      items.push({
        label: entry.name,
        icon: <ListFilter size={13} />,
        onSelect: () => {
          onApply(fromSavedPayload(entry.filter));
          onNotice?.(t("saved.applied", { name: entry.name }));
        },
      });
    }
  }
  items.push(
    { kind: "separator" },
    { label: t("saved.save"), icon: <BookmarkPlus size={13} />, onSelect: () => setDialog("save") },
    {
      label: t("saved.manage"),
      icon: <Settings2 size={13} />,
      disabled: !saved || saved.length === 0,
      onSelect: () => setDialog("manage"),
    },
  );

  return (
    <>
      <button
        type="button"
        className="link-button saved-filters-button"
        ref={button}
        aria-haspopup="menu"
        aria-expanded={menu !== null}
        onClick={openMenu}
      >
        <ListFilter size={12} aria-hidden="true" /> {t("saved.button")}
      </button>
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          label={t("saved.heading")}
          items={items}
          onClose={() => setMenu(null)}
        />
      )}
      {dialog === "save" && (
        <SaveFilterDialog
          existing={saved ?? []}
          onSave={async (name) => {
            const match = saved?.find((entry) => entry.name === name);
            await desktop.savedFilterSave({ id: match?.id ?? null, name, filter: toSavedPayload(filter) });
            onNotice?.(t("saved.saved", { name }));
            await load();
          }}
          onClose={() => setDialog(null)}
          onError={fail}
        />
      )}
      {dialog === "manage" && saved && (
        <ManageFiltersDialog
          saved={saved}
          onApply={(entry) => onApply(fromSavedPayload(entry.filter))}
          onRename={async (entry, name) => {
            await desktop.savedFilterSave({ id: entry.id, name, filter: entry.filter });
            await load();
          }}
          onDelete={async (entry) => {
            await desktop.savedFilterDelete(entry.id);
            await load();
          }}
          onClose={() => setDialog(null)}
          onError={fail}
        />
      )}
    </>
  );
}

function SaveFilterDialog({
  existing,
  onSave,
  onClose,
  onError,
}: {
  existing: SavedFilter[];
  onSave: (name: string) => Promise<void>;
  onClose: () => void;
  onError: (reason: unknown) => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const trimmed = name.trim();
  const replaces = existing.some((entry) => entry.name === trimmed);

  async function submit() {
    if (!trimmed || busy) return;
    setBusy(true);
    try {
      await onSave(trimmed);
      onClose();
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={t("saved.save.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={onClose}>
            {t("form.cancel")}
          </button>
          <button
            type="button"
            className="button primary"
            disabled={!trimmed || busy}
            onClick={() => void submit()}
          >
            {replaces ? t("saved.save.replace") : t("saved.save.confirm")}
          </button>
        </>
      }
    >
      <label className="filter-field">
        {t("saved.name")}
        <input
          value={name}
          maxLength={120}
          onChange={(event) => setName(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void submit();
            }
          }}
          placeholder={t("saved.name.placeholder")}
        />
      </label>
      {replaces && <p className="filter-hint">{t("saved.save.replaces", { name: trimmed })}</p>}
    </Modal>
  );
}

function ManageFiltersDialog({
  saved,
  onApply,
  onRename,
  onDelete,
  onClose,
  onError,
}: {
  saved: SavedFilter[];
  onApply: (entry: SavedFilter) => void;
  onRename: (entry: SavedFilter, name: string) => Promise<void>;
  onDelete: (entry: SavedFilter) => Promise<void>;
  onClose: () => void;
  onError: (reason: unknown) => void;
}) {
  const [names, setNames] = useState<Record<string, string>>({});

  async function commit(entry: SavedFilter) {
    const name = (names[entry.id] ?? entry.name).trim();
    if (!name || name === entry.name) return;
    try {
      await onRename(entry, name);
    } catch (reason) {
      onError(reason);
    }
  }

  return (
    <Modal
      title={t("saved.manage.title")}
      onClose={onClose}
      actions={
        <button type="button" className="button primary" onClick={onClose}>
          {t("filter.done")}
        </button>
      }
    >
      {saved.length === 0 ? (
        <p className="decoded-empty">{t("saved.none")}</p>
      ) : (
        <ul className="saved-filter-list">
          {saved.map((entry) => (
            <li key={entry.id}>
              <input
                aria-label={t("saved.rename", { name: entry.name })}
                value={names[entry.id] ?? entry.name}
                maxLength={120}
                onChange={(event) => setNames((current) => ({ ...current, [entry.id]: event.target.value }))}
                onBlur={() => void commit(entry)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void commit(entry);
                  }
                }}
              />
              <button
                type="button"
                className="button"
                onClick={() => {
                  onApply(entry);
                  onClose();
                }}
              >
                {t("saved.apply")}
              </button>
              <button
                type="button"
                className="icon-button"
                aria-label={t("saved.delete", { name: entry.name })}
                title={t("saved.delete", { name: entry.name })}
                onClick={() => void onDelete(entry).catch(onError)}
              >
                <Trash2 size={13} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  );
}
