import { desktop } from "./desktop";

/** Only mounted rows request values. Requests are batched and cached per table/project. */
export function createDecodedColumnStore(
  path: string | null,
  paths: string[],
  onError?: (error: string) => void,
) {
  const cache = new Map<number, Array<unknown | null>>();
  const pending = new Set<number>();
  const inFlight = new Set<number>();
  const listeners = new Set<() => void>();
  let timer: ReturnType<typeof setTimeout> | null = null;
  let busy = false;
  let generation = 0;
  const notify = () => {
    for (const listener of listeners) listener();
  };
  async function drain() {
    timer = null;
    if (busy || !path || !pending.size) return;
    busy = true;
    const version = generation;
    const ids = [...pending].slice(0, 32);
    for (const id of ids) {
      pending.delete(id);
      inFlight.add(id);
    }
    try {
      const result = await desktop.packetFieldValues(path, ids, paths);
      if (version === generation)
        for (const id of ids) cache.set(id, result[String(id)] ?? paths.map(() => null));
    } catch (error) {
      for (const id of ids)
        cache.set(
          id,
          paths.map(() => null),
        );
      onError?.(error instanceof Error ? error.message : String(error));
    } finally {
      busy = false;
      for (const id of ids) inFlight.delete(id);
      while (cache.size > 2000) {
        const first = cache.keys().next().value;
        if (first !== undefined) cache.delete(first);
      }
      notify();
      if (pending.size) timer = setTimeout(() => void drain(), 20);
    }
  }
  return {
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    get(id: number) {
      return cache.get(id);
    },
    ensure(id: number) {
      if (cache.has(id) || pending.has(id) || inFlight.has(id) || !path || !paths.length) return;
      pending.add(id);
      if (timer === null && !busy) timer = setTimeout(() => void drain(), 20);
    },
    dispose() {
      generation++;
      inFlight.clear();
      if (timer !== null) clearTimeout(timer);
      timer = null;
      listeners.clear();
      pending.clear();
    },
  };
}
export type DecodedColumnStore = ReturnType<typeof createDecodedColumnStore>;
