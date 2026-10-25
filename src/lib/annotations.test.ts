import { describe, expect, it, vi } from "vitest";

import type { PacketAnnotation } from "../domain/types";
import { AnnotationStore } from "./annotations";
import { ANNOTATION_BATCH } from "./desktop";

function annotation(packetId: number, patch: Partial<PacketAnnotation> = {}): PacketAnnotation {
  return { packetId, bookmarked: true, color: null, note: null, updatedAtMicros: 1, ...patch };
}

function fakeApi(annotated: (id: number) => boolean = (id) => id % 100 === 0) {
  return {
    get: vi.fn(async (ids: number[]) => ids.filter(annotated).map((id) => annotation(id))),
    set: vi.fn(async (id: number, bookmarked: boolean, color: string | null, note: string | null) =>
      bookmarked || color || note ? annotation(id, { bookmarked, color, note }) : null,
    ),
  };
}

describe("AnnotationStore", () => {
  it("fetches in batches the backend accepts", async () => {
    const api = fakeApi();
    const store = new AnnotationStore(api);
    const ids = Array.from({ length: 4_500 }, (_, index) => index + 1);
    await store.ensure(ids);
    expect(api.get).toHaveBeenCalledTimes(3);
    expect(api.get.mock.calls.map(([batch]) => batch.length)).toEqual([
      ANNOTATION_BATCH,
      ANNOTATION_BATCH,
      500,
    ]);
    expect(store.getSnapshot().size).toBe(45);
    expect(store.get(100)?.bookmarked).toBe(true);
    expect(store.has(101)).toBe(true);
    expect(store.get(101)).toBeUndefined();
  });

  it("asks only for ids it has not seen and is not already fetching", async () => {
    const api = fakeApi();
    const store = new AnnotationStore(api);
    const first = store.ensure([1, 2, 3]);
    const second = store.ensure([2, 3, 4, 4]);
    await Promise.all([first, second]);
    await store.ensure([1, 2, 3, 4]);
    expect(api.get.mock.calls.map(([batch]) => batch)).toEqual([[1, 2, 3], [4]]);
  });

  it("keeps the rest of an annotation when one part changes", async () => {
    const api = fakeApi(() => false);
    const store = new AnnotationStore(api);
    await store.update(7, { color: "red", note: "suspicious" });
    await store.toggleBookmark(7);
    expect(api.set).toHaveBeenLastCalledWith(7, true, "red", "suspicious");
    expect(store.get(7)).toMatchObject({ bookmarked: true, color: "red", note: "suspicious" });
  });

  it("forgets an annotation the backend cleared", async () => {
    const store = new AnnotationStore(fakeApi(() => false));
    await store.update(3, { bookmarked: true });
    await store.update(3, { bookmarked: false });
    expect(store.get(3)).toBeUndefined();
    expect(store.getSnapshot().has(3)).toBe(false);
  });

  it("drops a response that arrives after a reset", async () => {
    let release: (rows: PacketAnnotation[]) => void = () => undefined;
    const api = {
      get: vi.fn(
        () =>
          new Promise<PacketAnnotation[]>((resolve) => {
            release = resolve;
          }),
      ),
      set: vi.fn(),
    };
    const store = new AnnotationStore(api);
    const pending = store.ensure([5]);
    store.reset();
    release([annotation(5)]);
    await pending;
    expect(store.get(5)).toBeUndefined();
    expect(store.has(5)).toBe(false);
  });

  it("notifies subscribers with a new snapshot", async () => {
    const store = new AnnotationStore(fakeApi());
    const listener = vi.fn();
    store.subscribe(listener);
    const before = store.getSnapshot();
    await store.ensure([100]);
    expect(listener).toHaveBeenCalled();
    expect(store.getSnapshot()).not.toBe(before);
  });
});
