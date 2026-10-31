import { type FormEvent, useEffect, useRef, useState } from "react";

import { t } from "../i18n";
import { Modal } from "./Modal";

/** Reads `123` or `#123` as a packet id; anything else is not one. */
export function parsePacketId(text: string): number | null {
  const match = /^#?\s*(\d{1,15})$/.exec(text.trim());
  return match?.[1] ? Number(match[1]) : null;
}

/** Asks for a packet number and hands it to the history to jump to. */
export function GoToPacketDialog({
  initial,
  onGo,
  onClose,
}: {
  /** Prefilled id, typically the selected packet's. */
  initial: number | null;
  onGo: (id: number) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState(initial === null ? "" : String(initial));
  const input = useRef<HTMLInputElement>(null);
  const id = parsePacketId(text);

  // The modal focuses itself when it opens; this runs after it, so the caret
  // lands in the field ready for a number.
  useEffect(() => {
    input.current?.focus();
    input.current?.select();
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (id === null) return;
    onClose();
    onGo(id);
  }

  return (
    <Modal
      title={t("goto.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={onClose}>
            {t("form.cancel")}
          </button>
          <button type="submit" form="goto-packet" className="button primary" disabled={id === null}>
            {t("goto.go")}
          </button>
        </>
      }
    >
      <form id="goto-packet" className="annotation-editor" onSubmit={submit}>
        <label className="filter-field">
          {t("goto.label")}
          <input
            ref={input}
            inputMode="numeric"
            spellCheck={false}
            value={text}
            placeholder="1234"
            aria-invalid={text.trim() !== "" && id === null ? true : undefined}
            onChange={(event) => setText(event.target.value)}
          />
        </label>
        <p className="muted">{t("goto.hint")}</p>
      </form>
    </Modal>
  );
}
