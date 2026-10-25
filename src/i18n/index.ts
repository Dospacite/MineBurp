import { en } from "./en";

export type Locale = "en";

export type MessageKey = keyof typeof en;

type Dictionary = Record<MessageKey, string>;

const catalogs: Record<Locale, Dictionary> = { en };

let active: Locale = "en";

/** Selects the catalog future lookups read from. */
export function setLocale(locale: Locale): void {
  active = locale;
}

/**
 * Looks up a UI string.
 *
 * A missing key returns the key itself rather than an empty node: a typo in a
 * catalog entry must be visible in review, not silently render nothing. At
 * runtime the English catalog is also the fallback for every other locale, so
 * a partially translated catalog degrades to English per string instead of
 * crashing on `undefined`.
 */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const text = catalogs[active][key] ?? en[key] ?? key;
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (_match: string, name: string) =>
    Object.hasOwn(params, name) ? String(params[name]) : `{${name}}`,
  );
}
