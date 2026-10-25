import { type KeyboardEvent, type ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";

export type MenuItem =
  | {
      kind?: "item";
      label: string;
      shortcut?: string;
      icon?: ReactNode;
      disabled?: boolean;
      onSelect: () => void;
    }
  | { kind: "separator" }
  | { kind: "heading"; label: string };

/**
 * A menu at a point on screen, for right-click and the context-menu key.
 *
 * Arrow keys move through the enabled items, Enter activates, Escape and any
 * click outside close it, and focus returns to whatever opened it.
 */
export function ContextMenu({
  x,
  y,
  items,
  label,
  onClose,
}: {
  x: number;
  y: number;
  items: MenuItem[];
  label: string;
  onClose: () => void;
}) {
  const menu = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ left: x, top: y });
  const close = useRef(onClose);
  close.current = onClose;

  // Keep the menu on screen: flip it left or up when it would overflow.
  useLayoutEffect(() => {
    const element = menu.current;
    if (!element) return;
    const { width, height } = element.getBoundingClientRect();
    setPosition({
      left: Math.max(4, x + width > window.innerWidth ? x - width : x),
      top: Math.max(4, y + height > window.innerHeight ? y - height : y),
    });
  }, [x, y]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    menu.current?.querySelector<HTMLElement>("[role='menuitem']:not([aria-disabled='true'])")?.focus();
    const onPointer = (event: PointerEvent) => {
      if (menu.current && !menu.current.contains(event.target as Node)) close.current();
    };
    const onBlur = () => close.current();
    document.addEventListener("pointerdown", onPointer, true);
    window.addEventListener("blur", onBlur);
    window.addEventListener("resize", onBlur);
    return () => {
      document.removeEventListener("pointerdown", onPointer, true);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("resize", onBlur);
      previous?.focus?.();
    };
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const entries = Array.from(
      menu.current?.querySelectorAll<HTMLElement>("[role='menuitem']:not([aria-disabled='true'])") ?? [],
    );
    const current = entries.indexOf(document.activeElement as HTMLElement);
    let next: number | null = null;
    switch (event.key) {
      case "ArrowDown":
        next = (current + 1) % entries.length;
        break;
      case "ArrowUp":
        next = (current - 1 + entries.length) % entries.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = entries.length - 1;
        break;
      case "Escape":
      case "Tab":
        event.preventDefault();
        event.stopPropagation();
        onClose();
        return;
      default:
        return;
    }
    event.preventDefault();
    entries[next]?.focus();
  }

  return (
    <div
      className="context-menu"
      role="menu"
      aria-label={label}
      ref={menu}
      style={{ left: position.left, top: position.top }}
      onKeyDown={onKeyDown}
      onContextMenu={(event) => event.preventDefault()}
    >
      {items.map((item, index) => {
        if (item.kind === "separator") {
          // biome-ignore lint/suspicious/noArrayIndexKey: separators have no identity of their own.
          return <hr key={`separator-${index}`} />;
        }
        if (item.kind === "heading") {
          return (
            <div key={`heading-${item.label}`} className="context-menu-heading" role="presentation">
              {item.label}
            </div>
          );
        }
        return (
          <button
            type="button"
            role="menuitem"
            key={item.label}
            tabIndex={-1}
            aria-disabled={item.disabled || undefined}
            className="context-menu-item"
            onClick={() => {
              if (item.disabled) return;
              onClose();
              item.onSelect();
            }}
          >
            <span className="context-menu-icon" aria-hidden="true">
              {item.icon}
            </span>
            <span>{item.label}</span>
            {item.shortcut && <kbd>{item.shortcut}</kbd>}
          </button>
        );
      })}
    </div>
  );
}
