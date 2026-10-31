import { useEffect, useRef, useState } from "react";
import { t } from "../i18n";
import { Modal } from "./Modal";
export interface PaletteCommand {
  id: string;
  label: string;
  keywords?: string;
  run: () => void;
  disabled?: boolean;
}
export function CommandPalette({ commands, onClose }: { commands: PaletteCommand[]; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const matches = commands
    .filter((c) => `${c.label} ${c.keywords ?? ""}`.toLowerCase().includes(query.toLowerCase()))
    .slice(0, 80);
  useEffect(() => {
    const id = requestAnimationFrame(() => input.current?.focus());
    return () => cancelAnimationFrame(id);
  }, []);
  const active = Math.min(index, Math.max(0, matches.length - 1));
  const activeCommandId = matches[active]?.id;
  useEffect(() => {
    if (activeCommandId)
      document.getElementById(`palette-${activeCommandId}`)?.scrollIntoView?.({ block: "nearest" });
  }, [activeCommandId]);
  const run = (command: PaletteCommand) => {
    if (command.disabled) return;
    onClose();
    command.run();
  };
  return (
    <Modal title={t("palette.title")} onClose={onClose}>
      <input
        ref={input}
        className="palette-search"
        role="combobox"
        aria-expanded="true"
        aria-controls="palette-options"
        aria-autocomplete="list"
        aria-activedescendant={matches[active] ? `palette-${matches[active]?.id}` : undefined}
        aria-label={t("palette.search")}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setIndex(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setIndex(
              (active + (e.key === "ArrowDown" ? 1 : -1) + matches.length) % Math.max(1, matches.length),
            );
          } else if (e.key === "Enter") {
            e.preventDefault();
            const command = matches[active];
            if (command) run(command);
          }
        }}
      />
      <div id="palette-options" role="listbox" aria-label={t("palette.results")} className="palette-options">
        {matches.map((command, i) => (
          <button
            type="button"
            role="option"
            aria-selected={i === active}
            aria-disabled={command.disabled}
            className={i === active ? "active" : ""}
            id={`palette-${command.id}`}
            key={command.id}
            onClick={() => run(command)}
            disabled={command.disabled}
          >
            {command.label}
          </button>
        ))}
      </div>
      {!matches.length && <p role="status">{t("palette.empty")}</p>}
    </Modal>
  );
}
