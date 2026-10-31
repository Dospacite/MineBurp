import {
  type CSSProperties,
  type FocusEvent,
  type KeyboardEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

/** Rows rendered beyond the viewport so scrolling does not flash blank space. */
const OVERSCAN = 12;

export interface VirtualRowsHandle {
  scrollToTop: () => void;
  /**
   * Brings a row into view and reports the element to focus. `center` puts
   * it in the middle of the viewport, for a jump to a row far from the last
   * one; the default scrolls as little as possible.
   */
  revealRow: (index: number, align?: "nearest" | "center") => HTMLElement | null;
}

/**
 * Renders only the rows that are actually on screen.
 *
 * The packet tables used to mount a DOM node per captured packet. At Minecraft
 * traffic rates that is tens of thousands of nodes, and every arriving batch
 * relaid out all of them — the single biggest reason the app became unusable
 * under load. Row height is fixed, so the visible window is arithmetic rather
 * than measurement.
 *
 * Scroll position drives which rows render, so it updates at most once per
 * animation frame: a fast wheel over tens of thousands of rows otherwise
 * schedules a React render per event, which is itself enough to jank.
 */
export function VirtualRows<T>({
  items,
  rowHeight,
  renderRow,
  getKey,
  activeIndex,
  header,
  footer,
  className,
  ariaLabel,
  style,
  /** Suspends scroll-following while the operator is reading older rows. */
  onScrollStateChange,
  handleRef,
}: {
  items: readonly T[];
  rowHeight: number;
  renderRow: (item: T, index: number) => ReactNode;
  /**
   * A stable key per item. Keying the wrapper by position remounted every row
   * whenever rows were prepended, which also threw away keyboard focus.
   */
  getKey?: (item: T) => string | number;
  /**
   * The row holding the grid's single tab stop. When it is scrolled out of
   * the rendered window the viewport takes the tab stop instead and hands
   * focus to the row on arrival, so the grid is never unreachable by Tab.
   */
  activeIndex?: number;
  header?: ReactNode;
  footer?: ReactNode;
  className?: string;
  ariaLabel?: string;
  style?: CSSProperties;
  onScrollStateChange?: (atTop: boolean) => void;
  handleRef?: (handle: VirtualRowsHandle | null) => void;
}) {
  const viewport = useRef<HTMLDivElement | null>(null);
  const headerBox = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(0);
  const frame = useRef(0);

  useLayoutEffect(() => {
    const element = viewport.current;
    if (!element) return undefined;
    const observer = new ResizeObserver(() => setHeight(element.clientHeight));
    observer.observe(element);
    setHeight(element.clientHeight);
    return () => observer.disconnect();
  }, []);

  useEffect(() => () => cancelAnimationFrame(frame.current), []);

  useEffect(() => {
    if (!handleRef) return undefined;
    handleRef({
      scrollToTop: () => {
        if (viewport.current) viewport.current.scrollTop = 0;
      },
      revealRow: (index, align = "nearest") => {
        const element = viewport.current;
        if (!element) return null;
        const top = index * rowHeight;
        const bottom = top + rowHeight;
        if (align === "center") {
          element.scrollTop = Math.max(0, top - (element.clientHeight - rowHeight) / 2);
        } else if (top < element.scrollTop) {
          element.scrollTop = top;
        } else if (bottom > element.scrollTop + element.clientHeight) {
          element.scrollTop = bottom - element.clientHeight;
        }
        // The indexed wrapper is layout-transparent; the row inside is what
        // takes focus.
        const wrapper = element.querySelector<HTMLElement>(`[data-row-index="${index}"]`);
        return (wrapper?.firstElementChild as HTMLElement | null) ?? wrapper ?? null;
      },
    });
    return () => handleRef(null);
  }, [handleRef, rowHeight]);

  const onScroll = useCallback(() => {
    // Rows wider than a narrow pane scroll sideways; the header follows at once
    // so the columns never drift apart, even between animation frames.
    if (headerBox.current && viewport.current) headerBox.current.scrollLeft = viewport.current.scrollLeft;
    if (frame.current) return;
    frame.current = requestAnimationFrame(() => {
      frame.current = 0;
      const element = viewport.current;
      if (!element) return;
      setScrollTop(element.scrollTop);
      onScrollStateChange?.(element.scrollTop <= rowHeight);
    });
  }, [onScrollStateChange, rowHeight]);

  const visibleCount = Math.ceil((height || rowHeight * 20) / rowHeight) + OVERSCAN * 2;
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const last = Math.min(items.length, first + visibleCount);
  const windowRows = items.slice(first, last);

  const rowStyle = useCallback(
    (index: number): CSSProperties => ({ transform: `translateY(${index * rowHeight}px)` }),
    [rowHeight],
  );

  const activeRendered = activeIndex === undefined || (activeIndex >= first && activeIndex < last);

  const onViewportFocus = useCallback(
    (event: FocusEvent<HTMLDivElement>) => {
      if (event.target !== event.currentTarget || activeIndex === undefined) return;
      const element = viewport.current;
      if (!element || items.length === 0) return;
      element.scrollTop = Math.max(0, activeIndex * rowHeight - element.clientHeight / 2);
      requestAnimationFrame(() => {
        const wrapper = element.querySelector<HTMLElement>(`[data-row-index="${activeIndex}"]`);
        (wrapper?.firstElementChild as HTMLElement | null)?.focus();
      });
    },
    [activeIndex, items.length, rowHeight],
  );

  return (
    <div
      className={className}
      role="grid"
      aria-label={ariaLabel}
      aria-rowcount={items.length + (header ? 1 : 0)}
      style={style}
    >
      {header && (
        <div className="virtual-header" ref={headerBox}>
          {header}
        </div>
      )}
      {/* biome-ignore lint/a11y/noStaticElementInteractions: the viewport holds the grid's tab stop only while the active row is scrolled out of the window. */}
      <div
        className="virtual-viewport"
        ref={viewport}
        onScroll={onScroll}
        tabIndex={activeRendered ? -1 : 0}
        onFocus={onViewportFocus}
      >
        <div className="virtual-canvas" style={{ height: items.length * rowHeight }}>
          <div className="virtual-window" style={rowStyle(first)}>
            {windowRows.map((item, index) => (
              <div
                key={getKey ? getKey(item) : first + index}
                data-row-index={first + index}
                style={{ display: "contents" }}
              >
                {renderRow(item, first + index)}
              </div>
            ))}
          </div>
        </div>
      </div>
      {footer}
    </div>
  );
}

/**
 * Moves row focus with the arrow keys inside a virtualized grid.
 *
 * Returns the row it moved to, or null when the key was not a navigation key,
 * so a caller can make navigation select as well as focus.
 */
export function rowNavigationKeyHandler(rowCount: number, rowHeight: number) {
  return (event: KeyboardEvent<HTMLElement>, index: number): number | null => {
    let next: number | null = null;
    switch (event.key) {
      case "ArrowDown":
        next = Math.min(rowCount - 1, index + 1);
        break;
      case "ArrowUp":
        next = Math.max(0, index - 1);
        break;
      case "PageDown":
        next = Math.min(rowCount - 1, index + 15);
        break;
      case "PageUp":
        next = Math.max(0, index - 15);
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = rowCount - 1;
        break;
      default:
        return null;
    }
    event.preventDefault();
    // React clears `currentTarget` once the handler returns, and the focus
    // below may run a frame later.
    const grid = event.currentTarget.closest("[role='grid']");
    const focusable = (row: number): HTMLElement | null => {
      const wrapper = grid?.querySelector<HTMLElement>(`[data-row-index="${row}"]`);
      return (wrapper?.firstElementChild as HTMLElement | null) ?? wrapper ?? null;
    };
    if (next !== index) {
      const target = focusable(next);
      if (target) {
        target.focus();
      } else {
        // The row is outside the rendered window; scroll to it first. The
        // scroll event renders it, and focus follows on the next frame.
        const viewport = grid?.querySelector<HTMLElement>(".virtual-viewport");
        if (viewport) {
          const destination = next;
          viewport.scrollTop = Math.max(0, destination * rowHeight - viewport.clientHeight / 2);
          requestAnimationFrame(() => requestAnimationFrame(() => focusable(destination)?.focus()));
        }
      }
    }
    return next;
  };
}
