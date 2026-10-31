import { useCallback, useEffect, useRef, useState } from "react";
import { desktop } from "../lib/desktop";
import { registerProjectEditor } from "../lib/projectWrites";
import { message } from "./useMineBurp";

/** Autosaves inside the project. Late loads and saves cannot overwrite newer edits. */
export function useProjectDocument<T>(
  path: string | null,
  key: "intruder" | "sequencer",
  initial: T,
  validate: (value: unknown) => value is T,
  onError: (error: string) => void,
) {
  const [entry, setEntry] = useState({ path, value: initial, ready: !desktop.isAvailable(), dirty: false });
  const [status, setStatus] = useState<"loading" | "saving" | "saved" | "error">("loading");
  const current = useRef(entry);
  const transition = useCallback((change: (latest: typeof entry) => typeof entry) => {
    const next = change(current.current);
    current.current = next;
    setEntry(next);
  }, []);
  const initialRef = useRef(initial);
  initialRef.current = initial;
  const validateRef = useRef(validate);
  validateRef.current = validate;
  const errorRef = useRef(onError);
  errorRef.current = onError;
  const queue = useRef(Promise.resolve());
  const flush = useCallback(async () => {
    const snapshot = current.current;
    if (!snapshot.path || !snapshot.dirty || !desktop.isAvailable()) return;
    if (!snapshot.ready) throw new Error("Wait for saved work to finish loading before changing projects");
    const expectedPath = snapshot.path;
    setStatus("saving");
    const write = queue.current
      .catch(() => {})
      .then(() => desktop.workbenchDocumentSave(expectedPath, key, { version: 1, data: snapshot.value }));
    queue.current = write;
    try {
      await write;
      transition((latest) =>
        latest.path === snapshot.path && latest.value === snapshot.value
          ? { ...latest, dirty: false }
          : latest,
      );
      if (current.current.path === snapshot.path && current.current.value === snapshot.value)
        setStatus("saved");
    } catch (error) {
      if (current.current.path === snapshot.path) {
        setStatus("error");
        errorRef.current(message(error));
      }
      throw error;
    }
  }, [key, transition]);
  useEffect(() => registerProjectEditor(flush), [flush]);
  useEffect(() => {
    let live = true;
    transition((latest) =>
      latest.path === path
        ? { ...latest, ready: !desktop.isAvailable() }
        : { path, value: initialRef.current, ready: !desktop.isAvailable(), dirty: false },
    );
    if (!path || !desktop.isAvailable()) {
      setStatus("saved");
      return;
    }
    setStatus("loading");
    void desktop
      .workbenchDocumentGet(path, key)
      .then((saved) => {
        if (!live) return;
        let value = initialRef.current;
        if (saved !== null) {
          if (
            typeof saved !== "object" ||
            !("version" in saved) ||
            saved.version !== 1 ||
            !("data" in saved) ||
            !validateRef.current(saved.data)
          )
            throw new Error("Unsupported or invalid saved research document");
          value = saved.data;
        }
        transition((latest) =>
          latest.path === path
            ? { ...latest, value: latest.dirty ? latest.value : value, ready: true }
            : latest,
        );
        setStatus(current.current.dirty ? "saving" : "saved");
      })
      .catch((error) => {
        if (live) {
          setStatus("error");
          errorRef.current(message(error));
        }
      });
    return () => {
      live = false;
    };
  }, [path, key, transition]);
  const setValue = useCallback(
    (change: T | ((value: T) => T)) => {
      transition((latest) => {
        const previous = latest.path === path ? latest.value : initialRef.current;
        return {
          path,
          ready: latest.path === path && latest.ready,
          dirty: true,
          value: typeof change === "function" ? (change as (value: T) => T)(previous) : change,
        };
      });
    },
    [path, transition],
  );
  useEffect(() => {
    if (!entry.ready || !entry.dirty || entry.path !== path) return;
    const timer = setTimeout(() => void flush().catch(() => {}), 300);
    return () => clearTimeout(timer);
  }, [entry, path, flush]);
  return {
    value: entry.path === path ? entry.value : initial,
    setValue,
    loaded: entry.path === path && entry.ready,
    status,
    flush,
  };
}

export function useDocumentField<T, K extends keyof T>(
  document: T,
  setDocument: (change: (value: T) => T) => void,
  key: K,
): [T[K], (change: T[K] | ((value: T[K]) => T[K])) => void] {
  const setter = useCallback(
    (change: T[K] | ((value: T[K]) => T[K])) => {
      setDocument((value) => ({
        ...value,
        [key]: typeof change === "function" ? (change as (previous: T[K]) => T[K])(value[key]) : change,
      }));
    },
    [setDocument, key],
  );
  return [document[key], setter];
}
