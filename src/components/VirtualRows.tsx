import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

/** Rows rendered beyond the viewport so scrolling does not flash blank space. */
const OVERSCAN = 12;

export interface VirtualRowsHandle {
  scrollToTop: () => void;
}

/**
 * Renders only the rows that are actually on screen.
 *
 * The packet tables used to mount a DOM node per captured packet. At Minecraft
 * traffic rates that is tens of thousands of nodes, and every arriving batch
 * relaid out all of them — the single biggest reason the app became unusable
 * under load. Row height is fixed, so the visible window is arithmetic rather
 * than measurement.
 */
export function VirtualRows<T>({
  items,
  rowHeight,
  renderRow,
  header,
  footer,
  className,
  ariaLabel,
  /** Suspends scroll-following while the operator is reading older rows. */
  onScrollStateChange,
  handleRef,
}: {
  items: readonly T[];
  rowHeight: number;
  renderRow: (item: T, index: number) => ReactNode;
  header?: ReactNode;
  footer?: ReactNode;
  className?: string;
  ariaLabel?: string;
  onScrollStateChange?: (atTop: boolean) => void;
  handleRef?: (handle: VirtualRowsHandle | null) => void;
}) {
  const viewport = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(0);

  useLayoutEffect(() => {
    const element = viewport.current;
    if (!element) return undefined;
    const observer = new ResizeObserver(() => setHeight(element.clientHeight));
    observer.observe(element);
    setHeight(element.clientHeight);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!handleRef) return undefined;
    handleRef({
      scrollToTop: () => {
        if (viewport.current) viewport.current.scrollTop = 0;
      },
    });
    return () => handleRef(null);
  }, [handleRef]);

  const onScroll = useCallback(() => {
    const element = viewport.current;
    if (!element) return;
    setScrollTop(element.scrollTop);
    onScrollStateChange?.(element.scrollTop <= rowHeight);
  }, [onScrollStateChange, rowHeight]);

  const visibleCount = Math.ceil((height || rowHeight * 20) / rowHeight) + OVERSCAN * 2;
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
  const last = Math.min(items.length, first + visibleCount);
  const window = items.slice(first, last);

  return (
    <div className={className} role="table" aria-label={ariaLabel} aria-rowcount={items.length}>
      {header}
      <div className="virtual-viewport" ref={viewport} onScroll={onScroll}>
        <div className="virtual-canvas" style={{ height: items.length * rowHeight }}>
          <div className="virtual-window" style={{ transform: `translateY(${first * rowHeight}px)` }}>
            {window.map((item, index) => renderRow(item, first + index))}
          </div>
        </div>
      </div>
      {footer}
    </div>
  );
}
