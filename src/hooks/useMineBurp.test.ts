import { describe, expect, it } from "vitest";

import { merge, same } from "./useMineBurp";

describe("same", () => {
  it("handles primitives and NaN", () => {
    expect(same(1, 1)).toBe(true);
    expect(same(1, 2)).toBe(false);
    expect(same(Number.NaN, Number.NaN)).toBe(true);
    expect(same(null, null)).toBe(true);
    expect(same(null, undefined)).toBe(false);
  });

  it("deep compares objects regardless of key order", () => {
    expect(same({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(true);
    expect(same({ a: { x: 1 } }, { a: { x: 1 } })).toBe(true);
    expect(same({ a: { x: 1 } }, { a: { x: 2 } })).toBe(false);
  });

  it("compares arrays", () => {
    expect(same([1, 2], [1, 2])).toBe(true);
    expect(same([1, 2], [2, 1])).toBe(false);
    expect(same([1], [1, 2])).toBe(false);
  });
});

describe("merge", () => {
  it("overlays live over stored and sorts by packet_count", () => {
    const stored = [
      { id: "a", packet_count: 10, target: { host: "1.1.1.1", port: 25565 } } as never,
      { id: "b", packet_count: 5, target: { host: "2.2.2.2", port: 25565 } } as never,
    ];
    const live = [{ id: "a", packet_count: 99, target: { host: "1.1.1.1", port: 25565 } } as never];
    const out = merge(stored, live);
    expect(out[0]!.id).toBe("a");
    expect(out[0]!.packet_count).toBe(99);
    expect(out).toHaveLength(2);
    // busiest first
    expect(out[0]!.packet_count).toBeGreaterThan(out[1]!.packet_count);
  });

  it("handles empty inputs", () => {
    expect(merge([], [])).toEqual([]);
  });
});
