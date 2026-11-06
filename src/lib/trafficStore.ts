import { useSyncExternalStore } from "react";

let signal = 0;
const listeners = new Set<() => void>();
export function notifyTrafficAppend() {
  signal++;
  for (const listener of listeners) listener();
}
const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};
export function useTrafficAppend() {
  return useSyncExternalStore(subscribe, () => signal);
}

import type { ConnectionSnapshot } from "../domain/types";

let connections: ConnectionSnapshot[] = [];
const connectionListeners = new Set<() => void>();
export function publishConnections(next: ConnectionSnapshot[]) {
  if (JSON.stringify(next) === JSON.stringify(connections)) return;
  connections = next;
  for (const listener of connectionListeners) listener();
}
export function useTrafficConnections() {
  return useSyncExternalStore(
    (listener) => {
      connectionListeners.add(listener);
      return () => {
        connectionListeners.delete(listener);
      };
    },
    () => connections,
  );
}
