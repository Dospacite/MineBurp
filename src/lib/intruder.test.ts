import { describe, expect, it, vi } from "vitest";
import { caseEdits, delay, payloadLists, validatePositions } from "./intruder";

describe("Intruder positions", () => {
  it("preserves empty payloads and selects the shared list for battering ram", () => {
    const positions = [
      { field: "a", payloads: "x\r\n" },
      { field: "b", payloads: "y" },
    ];
    const lists = payloadLists(positions);
    expect(lists).toEqual([["x", ""], ["y"]]);
    expect(caseEdits("battering_ram", positions, lists, [1, 1])).toEqual([
      { kind: "field", name: "a", value: "" },
      { kind: "field", name: "b", value: "" },
    ]);
    expect(caseEdits("sniper", positions, lists, [null, 0])).toEqual([
      { kind: "field", name: "b", value: "y" },
    ]);
  });
  it("orders raw replacements backwards and rejects ambiguous positions", () => {
    const positions = [
      { field: "@raw", offset: 1, length: 2, payloads: "ff" },
      { field: "@raw", offset: 4, length: 1, payloads: "00" },
    ];
    expect(validatePositions(positions)).toBe(true);
    expect(caseEdits("pitchfork", positions, payloadLists(positions), [0, 0])).toEqual([
      { kind: "range", offset: 4, length: 1, bytes: "00" },
      { kind: "range", offset: 1, length: 2, bytes: "ff" },
    ]);
    expect(validatePositions([{ ...positions[0]!, length: 4 }, positions[1]!])).toBe(false);
    expect(validatePositions([positions[0]!, { field: "a", payloads: "x" }])).toBe(false);
    expect(
      validatePositions([
        { field: "a", payloads: "x" },
        { field: "a", payloads: "y" },
      ]),
    ).toBe(false);
  });
  it("cancels pacing immediately", async () => {
    vi.useFakeTimers();
    const abort = new AbortController();
    const wait = delay(60000, abort.signal);
    abort.abort();
    await wait;
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });
});
