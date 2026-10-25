import { X } from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import { t } from "../i18n";

const FOCUSABLE =
  "a[href], button:not([disabled]), textarea, input, select, details summary, [tabindex]:not([tabindex='-1'])";

/**
 * A centred dialog with a scrolling body.
 *
 * The body scrolls rather than the page: a dialog that grows past the window is
 * the one case where content taller than the viewport is expected, and the
 * header and its actions have to stay reachable while it does.
 *
 * Focus is trapped while the dialog is open — Tab cycles inside it instead of
 * escaping into the live traffic behind it — and returns to whatever held it
 * when the dialog opened.
 */
export function Modal({
  title,
  children,
  actions,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const surface = useRef<HTMLDivElement>(null);
  // Callers pass an inline closure, so `onClose` is a new function on every one
  // of their renders — and a dialog over live traffic re-renders constantly.
  // Reading it through a ref keeps the effects below off that identity.
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        close.current();
        return;
      }
      if (event.key !== "Tab" || !surface.current) return;
      const focusable = Array.from(surface.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (element) => element.offsetParent !== null || element === document.activeElement,
      );
      if (focusable.length === 0) {
        event.preventDefault();
        surface.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      const active = document.activeElement;
      if (event.shiftKey && (active === first || active === surface.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Focus moves to the dialog when it opens and never again: re-focusing on a
  // later render would take the caret away from whatever the operator is typing.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    surface.current?.focus();
    return () => previous?.focus();
  }, []);

  return (
    <div className="modal-scrim" onPointerDown={(event) => event.target === event.currentTarget && onClose()}>
      <div
        className={`modal ${wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={surface}
      >
        <header className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="icon-button" onClick={onClose} aria-label={t("modal.close")}>
            <X size={15} aria-hidden="true" />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {actions && <footer className="modal-actions">{actions}</footer>}
      </div>
    </div>
  );
}
