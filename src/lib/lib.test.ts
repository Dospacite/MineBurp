import { describe, expect, it } from "vitest";

import type { FilterVocabulary, PacketSummary } from "../domain/types";
import { DEFAULT_TABLE_SETTINGS, gridTemplate, moveColumn, normaliseColumns } from "./columns";
import { changedBytes, diffBytes, diffFields } from "./diff";
import { andExpression, applyCompletion, completions, expressionForPacket } from "./expressions";
import { newId } from "./ids";
import { formatPacketTime, formatSeconds } from "./time";

const vocabulary: FilterVocabulary = {
  fields: ["source", "direction", "state", "name", "size"],
  operators: ["==", "!=", ">", "~"],
  states: ["play", "login"],
  directions: ["client_to_server", "server_to_client"],
  sources: ["minecraft"],
  dispositions: ["forwarded"],
};

describe("diffBytes", () => {
  it("reports an insertion as one run, not a shifted tail", () => {
    const { runs, positional } = diffBytes(new Uint8Array([1, 2, 3, 4]), new Uint8Array([1, 2, 9, 3, 4]));
    expect(positional).toBe(false);
    expect(runs).toEqual([
      { kind: "equal", aOffset: 0, bOffset: 0, length: 2 },
      { kind: "insert", bOffset: 2, length: 1 },
      { kind: "equal", aOffset: 2, bOffset: 3, length: 2 },
    ]);
    expect(changedBytes(runs)).toBe(1);
  });

  it("handles empty and identical inputs", () => {
    expect(diffBytes(new Uint8Array(), new Uint8Array()).runs).toEqual([]);
    expect(changedBytes(diffBytes(new Uint8Array([7, 7]), new Uint8Array([7, 7])).runs)).toBe(0);
    expect(diffBytes(new Uint8Array(), new Uint8Array([1])).runs).toEqual([
      { kind: "insert", bOffset: 0, length: 1 },
    ]);
  });
});

describe("diffFields", () => {
  it("lines decoded fields up by path", () => {
    const rows = diffFields({ a: 1, nested: { b: "x" } }, { a: 2, nested: { b: "x" }, extra: true });
    expect(rows).toEqual([
      { path: "a", a: "1", b: "2", changed: true },
      { path: "nested.b", a: "x", b: "x", changed: false },
      { path: "extra", a: undefined, b: "true", changed: true },
    ]);
  });
});

describe("expressions", () => {
  const summary = {
    name: "chat",
    packet_id: 3,
    state: "play",
    direction: "client_to_server",
  } as PacketSummary;

  it("selects packets like one", () => {
    expect(expressionForPacket(summary)).toBe(
      "name == chat && state == play && direction == client_to_server",
    );
    expect(expressionForPacket({ ...summary, name: null })).toBe(
      "id == 3 && state == play && direction == client_to_server",
    );
  });

  it("narrows every branch of a disjunction", () => {
    expect(andExpression("", "size > 1")).toBe("size > 1");
    expect(andExpression("state == play || state == login", "size > 1")).toBe(
      "state == play && size > 1 || state == login && size > 1",
    );
  });

  it("completes fields, operators, and enumerated values", () => {
    expect(completions("st", 2, vocabulary).map((item) => item.text)).toEqual(["state"]);
    expect(completions("state ", 6, vocabulary).map((item) => item.text)).toEqual(["==", "!=", ">", "~"]);
    expect(completions("state == p", 10, vocabulary).map((item) => item.text)).toEqual(["play"]);
    expect(completions("state == play ", 14, vocabulary).map((item) => item.text)).toEqual(["&&", "||"]);
    expect(completions("size > 1 && dir", 15, vocabulary).map((item) => item.text)).toEqual(["direction"]);
  });

  it("applies a completion in place", () => {
    const [choice] = completions("state == p && size > 1", 10, vocabulary);
    expect(choice).toBeDefined();
    if (!choice) return;
    expect(applyCompletion("state == p && size > 1", choice)).toEqual({
      text: "state == play && size > 1",
      caret: 14,
    });
  });
});

describe("columns", () => {
  it("keeps known columns, drops unknown ones, and appends new ones", () => {
    const columns = normaliseColumns([
      { id: "bytes", visible: false },
      { id: "nonsense" },
      { id: "packet", visible: false },
    ]);
    expect(columns[0]).toEqual({ id: "bytes", visible: false });
    // The packet name cannot be hidden.
    expect(columns.find((column) => column.id === "packet")?.visible).toBe(true);
    expect(columns).toHaveLength(DEFAULT_TABLE_SETTINGS.columns.length);
  });

  it("builds a grid template from visible columns", () => {
    const moved = moveColumn(DEFAULT_TABLE_SETTINGS.columns, "sequence", 1);
    expect(moved[1]?.id).toBe("sequence");
    expect(
      gridTemplate([
        { id: "sequence", visible: true },
        { id: "packet", visible: true },
        { id: "id", visible: false },
      ]),
    ).toBe("56px minmax(130px, 1fr)");
  });
});

describe("time", () => {
  it("formats relative and delta times", () => {
    expect(formatSeconds(1_234_567)).toBe("1.234567");
    expect(formatSeconds(-5, true)).toBe("−0.000005");
    expect(formatPacketTime(3_000_000, "relative", 1_000_000, null)).toBe("2.000000");
    expect(formatPacketTime(3_000_000, "delta", null, 2_500_000)).toBe("+0.500000");
    expect(formatPacketTime(3_000_000, "relative", null, null)).toBe("—");
  });
});

describe("newId", () => {
  it("is a version-4 UUID", () => {
    expect(newId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});
