import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";

/**
 * A centred dialog with a scrolling body.
 *
 * The body scrolls rather than the page: a dialog that grows past the window is
 * the one case where content taller than the viewport is expected, and the
 * header and its actions have to stay reachable while it does.
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
      if (event.key === "Escape") close.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Focus moves to the dialog when it opens and never again: re-focusing on a
  // later render would take the caret away from whatever the operator is typing.
  useEffect(() => {
    surface.current?.focus();
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
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={15} aria-hidden="true" />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {actions && <footer className="modal-actions">{actions}</footer>}
      </div>
    </div>
  );
}
