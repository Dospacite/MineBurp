import { useEffect, useSyncExternalStore } from "react";
import type { DecodedColumnStore } from "../lib/decodedColumns";
export function DecodedColumnCell({
  store,
  id,
  index,
}: {
  store: DecodedColumnStore;
  id: number;
  index: number;
}) {
  const values = useSyncExternalStore(store.subscribe, () => store.get(id));
  useEffect(() => {
    store.ensure(id);
  }, [store, id]);
  const value = values?.[index];
  const text =
    values === undefined
      ? "…"
      : value === null || value === undefined
        ? "—"
        : typeof value === "string"
          ? value
          : JSON.stringify(value);
  return (
    // biome-ignore lint/a11y/useSemanticElements: cells belong to a virtualized ARIA grid, not an HTML table.
    <span role="gridcell" tabIndex={-1} className="packet-mono decoded-column-cell" title={text}>
      {text}
    </span>
  );
}
