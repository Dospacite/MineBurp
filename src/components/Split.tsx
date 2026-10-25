import { Children, Fragment, type ReactNode, useCallback, useRef, useState } from "react";

/**
 * A resizable row or column of panes.
 *
 * Sizes are fractions of the container rather than pixels, so a pane keeps its
 * share of the window when the window itself is resized, and every pane still
 * participates in the parent's height instead of collapsing to its content.
 * A `storageKey` makes a drag stick across sessions.
 */
export function Split({
  orientation,
  children,
  initial,
  minimum = 140,
  storageKey,
  className = "",
}: {
  orientation: "columns" | "rows";
  children: ReactNode;
  /** Starting fractions, one per pane. Defaults to an even split. */
  initial?: number[];
  /** Smallest a pane may be dragged to, in pixels. */
  minimum?: number;
  storageKey?: string;
  className?: string;
}) {
  const panes = Children.toArray(children).filter(Boolean);
  const container = useRef<HTMLDivElement>(null);
  const [sizes, setSizes] = useState<number[]>(() => restore(storageKey, panes.length, initial));
  const latest = useRef(sizes);
  latest.current = sizes;

  // A pane count that no longer matches the stored split (a pane appeared or
  // disappeared) falls back to an even split rather than rendering a broken
  // template.
  const fractions = sizes.length === panes.length ? sizes : even(panes.length);

  const applyDelta = useCallback(
    (index: number, pixels: number, base?: number[]) => {
      const box = container.current?.getBoundingClientRect();
      if (!box) return;
      const total = orientation === "columns" ? box.width : box.height;
      if (total <= 0) return;
      const floor = minimum / total;
      const start = base ?? latest.current;
      const current = start[index];
      const following = start[index + 1];
      if (current === undefined || following === undefined) return;
      let delta = pixels / total;
      delta = Math.max(delta, floor - current);
      delta = Math.min(delta, following - floor);
      if (!Number.isFinite(delta) || delta === 0) return;
      const next = [...start];
      next[index] = current + delta;
      next[index + 1] = following - delta;
      latest.current = next;
      setSizes(next);
    },
    [minimum, orientation],
  );

  function drag(index: number, event: React.PointerEvent) {
    event.preventDefault();
    const origin = orientation === "columns" ? event.clientX : event.clientY;
    // Every move is measured against the split as it was when the drag began,
    // so a slow drag cannot accumulate rounding drift.
    const start = latest.current;
    const move = (moved: PointerEvent) => {
      applyDelta(index, (orientation === "columns" ? moved.clientX : moved.clientY) - origin, start);
    };
    const stop = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
      document.body.classList.remove("dragging-split");
      persist(storageKey, latest.current);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop);
    document.body.classList.add("dragging-split");
  }

  function key(index: number, event: React.KeyboardEvent) {
    const back = orientation === "columns" ? "ArrowLeft" : "ArrowUp";
    const forward = orientation === "columns" ? "ArrowRight" : "ArrowDown";
    if (event.key !== back && event.key !== forward) return;
    event.preventDefault();
    applyDelta(index, event.key === back ? -24 : 24);
    persist(storageKey, latest.current);
  }

  const template = fractions
    .flatMap((size, index) => (index === 0 ? [`${size}fr`] : ["6px", `${size}fr`]))
    .join(" ");

  return (
    <div
      className={`split split-${orientation} ${className}`}
      ref={container}
      style={orientation === "columns" ? { gridTemplateColumns: template } : { gridTemplateRows: template }}
    >
      {panes.map((pane, index) => (
        <Fragment key={index}>
          {index > 0 && (
            <div
              className="split-handle"
              role="separator"
              tabIndex={0}
              aria-orientation={orientation === "columns" ? "vertical" : "horizontal"}
              aria-label="Resize panes"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(((sizes[index - 1] ?? 0) + (sizes[index] ?? 0)) * 100)}
              onPointerDown={(event) => drag(index - 1, event)}
              onKeyDown={(event) => key(index - 1, event)}
            />
          )}
          <div className="split-pane">{pane}</div>
        </Fragment>
      ))}
    </div>
  );
}

function even(count: number): number[] {
  return Array.from({ length: count }, () => 1 / count);
}

function restore(key: string | undefined, count: number, initial?: number[]): number[] {
  const fallback = initial && initial.length === count ? initial : even(count);
  if (!key) return fallback;
  try {
    const stored: unknown = JSON.parse(window.localStorage.getItem(`mineburp.split.${key}`) ?? "");
    if (
      Array.isArray(stored) &&
      stored.length === count &&
      stored.every((value) => typeof value === "number" && value > 0)
    ) {
      return stored as number[];
    }
  } catch {
    // A malformed or absent entry is not worth reporting; the default applies.
  }
  return fallback;
}

function persist(key: string | undefined, sizes: number[]) {
  if (!key) return;
  try {
    window.localStorage.setItem(`mineburp.split.${key}`, JSON.stringify(sizes));
  } catch {
    // Storage being unavailable only costs the layout its memory.
  }
}
