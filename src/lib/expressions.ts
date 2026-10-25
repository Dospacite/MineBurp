import type { FilterVocabulary, PacketSummary } from "../domain/types";

/** Quotes a filter value when the grammar would otherwise split it. */
export function quoteValue(value: string): string {
  if (/^[\w.:/-]+$/.test(value)) return value;
  return value.includes('"') ? `'${value}'` : `"${value}"`;
}

/**
 * An expression that selects packets like this one: same name (or id, for an
 * unnamed packet), phase, and direction.
 */
export function expressionForPacket(packet: PacketSummary): string {
  const parts: string[] = [];
  if (packet.name) parts.push(`name == ${quoteValue(packet.name)}`);
  else if (packet.packet_id !== null) parts.push(`id == ${packet.packet_id}`);
  parts.push(`state == ${packet.state}`, `direction == ${packet.direction}`);
  return parts.join(" && ");
}

/** Narrows an existing expression with another predicate. */
export function andExpression(existing: string, predicate: string): string {
  const current = existing.trim();
  if (!current) return predicate;
  // `||` binds loosest, so narrowing a disjunction needs every branch narrowed.
  if (current.includes("||")) {
    return current
      .split("||")
      .map((branch) => `${branch.trim()} && ${predicate}`)
      .join(" || ");
  }
  return `${current} && ${predicate}`;
}

export interface Completion {
  /** Text inserted in place of the partial token. */
  text: string;
  /** Where the partial token starts in the input. */
  from: number;
  /** Where it ends (the caret). */
  to: number;
}

const CONNECTORS = ["&&", "||"];

/**
 * Suggestions for the token under the caret, from the vocabulary the backend
 * accepts. The grammar is flat — `field op value` joined by `&&` and `||` — so
 * the position inside the current predicate says what can come next.
 */
export function completions(input: string, caret: number, vocabulary: FilterVocabulary | null): Completion[] {
  if (!vocabulary) return [];
  const before = input.slice(0, caret);
  const separator = Math.max(before.lastIndexOf("&&"), before.lastIndexOf("||"));
  const predicateStart = separator < 0 ? 0 : separator + 2;
  const predicate = before.slice(predicateStart);
  const partialMatch = /(\S*)$/.exec(predicate);
  const partial = partialMatch?.[1] ?? "";
  const from = caret - partial.length;
  const complete = predicate
    .slice(0, predicate.length - partial.length)
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  let candidates: string[];
  if (complete.length === 0) candidates = vocabulary.fields;
  else if (complete.length === 1) candidates = vocabulary.operators;
  else if (complete.length === 2) candidates = valuesFor(complete[0] ?? "", vocabulary);
  else candidates = CONNECTORS;

  const needle = partial.replace(/^["']/, "").toLowerCase();
  return candidates
    .filter((candidate) => candidate.toLowerCase().startsWith(needle) && candidate !== partial)
    .slice(0, 8)
    .map((text) => ({ text, from, to: caret }));
}

function valuesFor(field: string, vocabulary: FilterVocabulary): string[] {
  switch (field) {
    case "state":
    case "phase":
      return vocabulary.states;
    case "direction":
    case "dir":
      return vocabulary.directions;
    case "source":
      return vocabulary.sources;
    case "disposition":
    case "action":
      return vocabulary.dispositions;
    default:
      return [];
  }
}

/** Applies a completion and returns the new text and caret. */
export function applyCompletion(input: string, completion: Completion): { text: string; caret: number } {
  const insert = `${completion.text} `;
  const text = input.slice(0, completion.from) + insert + input.slice(completion.to).replace(/^\s+/, "");
  return { text, caret: completion.from + insert.length };
}
