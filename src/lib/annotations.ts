import { type CSSProperties, useSyncExternalStore } from "react";

import type { PacketAnnotation } from "../domain/types";
import { ANNOTATION_BATCH, desktop } from "./desktop";

/** The colour names offered in the UI; the backend also accepts `#rrggbb`. */
export const ANNOTATION_COLORS = ["red", "orange", "yellow", "green", "blue", "purple"] as const;

export interface AnnotationPatch {
  bookmarked?: boolean;
  color?: string | null;
  note?: string | null;
}

interface AnnotationApi {
  get: (ids: number[]) => Promise<PacketAnnotation[]>;
  set: (
    packetId: number,
    bookmarked: boolean,
    color: string | null,
    note: string | null,
  ) => Promise<PacketAnnotation | null>;
}

const EMPTY: ReadonlyMap<number, PacketAnnotation> = new Map();

/**
 * The annotations of the packets the operator has seen, fetched in batches.
 *
 * Shared by the table, the inspector, and the bookmark list so a bookmark set
 * in one place shows everywhere without a refetch. Ids that were fetched and
 * have no annotation are remembered too, so scrolling back over them costs
 * nothing.
 */
export class AnnotationStore {
  private readonly known = new Map<number, PacketAnnotation | null>();
  private readonly inFlight = new Set<number>();
  private readonly listeners = new Set<() => void>();
  /** Bumped by `reset`; a response from an older generation is dropped. */
  private generation = 0;
  private snapshot: ReadonlyMap<number, PacketAnnotation> = EMPTY;

  constructor(
    private readonly api: AnnotationApi = {
      get: (ids) => desktop.packetAnnotationsGet(ids),
      set: (id, bookmarked, color, note) => desktop.packetAnnotationSet(id, bookmarked, color, note),
    },
  ) {}

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  /** Annotated packets only. A new map whenever anything changed, so it can be a memo dependency. */
  getSnapshot = (): ReadonlyMap<number, PacketAnnotation> => this.snapshot;

  get(id: number): PacketAnnotation | undefined {
    return this.known.get(id) ?? undefined;
  }

  /** Whether the packet's annotation — possibly none — has been fetched. */
  has(id: number): boolean {
    return this.known.has(id);
  }

  /** Forgets everything: row ids belong to one project. */
  reset(): void {
    this.generation++;
    this.known.clear();
    this.inFlight.clear();
    this.publish();
  }

  /**
   * Fetches the annotations of whichever `ids` are not known or already being
   * fetched, in batches the backend accepts.
   */
  async ensure(ids: readonly number[]): Promise<void> {
    const missing = [...new Set(ids)].filter((id) => !this.known.has(id) && !this.inFlight.has(id));
    if (missing.length === 0) return;
    for (const id of missing) this.inFlight.add(id);
    const generation = this.generation;
    try {
      for (let start = 0; start < missing.length; start += ANNOTATION_BATCH) {
        const batch = missing.slice(start, start + ANNOTATION_BATCH);
        const rows = await this.api.get(batch);
        if (generation !== this.generation) return;
        for (const id of batch) {
          this.inFlight.delete(id);
          if (!this.known.has(id)) this.known.set(id, null);
        }
        for (const row of rows) this.known.set(row.packetId, row);
        if (rows.length > 0) this.publish();
      }
    } finally {
      if (generation === this.generation) for (const id of missing) this.inFlight.delete(id);
    }
  }

  /** Changes some of a packet's annotation, keeping the rest as it is. */
  async update(packetId: number, patch: AnnotationPatch): Promise<PacketAnnotation | null> {
    const current = this.get(packetId);
    const generation = this.generation;
    const saved = await this.api.set(
      packetId,
      patch.bookmarked ?? current?.bookmarked ?? false,
      patch.color !== undefined ? patch.color : (current?.color ?? null),
      patch.note !== undefined ? patch.note : (current?.note ?? null),
    );
    if (generation === this.generation) {
      this.known.set(packetId, saved);
      this.publish();
    }
    return saved;
  }

  toggleBookmark(packetId: number): Promise<PacketAnnotation | null> {
    return this.update(packetId, { bookmarked: !this.get(packetId)?.bookmarked });
  }

  private publish(): void {
    const next = new Map<number, PacketAnnotation>();
    for (const [id, annotation] of this.known) if (annotation) next.set(id, annotation);
    this.snapshot = next;
    for (const listener of this.listeners) listener();
  }
}

export const annotationStore = new AnnotationStore();

/** Every known annotation, re-rendering when one changes. */
export function useAnnotations(
  store: AnnotationStore = annotationStore,
): ReadonlyMap<number, PacketAnnotation> {
  return useSyncExternalStore(store.subscribe, store.getSnapshot);
}

/** A CSS class for a named colour, or an inline colour for `#rrggbb`. */
export function annotationColorStyle(color: string | null | undefined): {
  className: string;
  style?: CSSProperties;
} {
  if (!color) return { className: "" };
  if (color.startsWith("#")) return { className: "marked", style: { "--mark": color } as CSSProperties };
  return { className: `marked mark-${color}` };
}
