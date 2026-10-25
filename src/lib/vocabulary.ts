import type { FilterVocabulary } from "../domain/types";
import { desktop } from "./desktop";

let pending: Promise<FilterVocabulary | null> | null = null;

/** The filter vocabulary, fetched once per session; null outside the desktop runtime. */
export function loadVocabulary(): Promise<FilterVocabulary | null> {
  if (!desktop.isAvailable()) return Promise.resolve(null);
  pending ??= desktop.filterVocabulary().catch(() => {
    pending = null;
    return null;
  });
  return pending;
}
