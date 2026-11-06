import { beforeEach, describe, expect, it, vi } from "vitest";
import { createDecodedColumnStore } from "./decodedColumns";
import { desktop } from "./desktop";
import { initialHistory, namedRevision, recordEdit, redoEdit, undoEdit } from "./editHistory";
import { TRAFFIC_PRESETS, trafficPreset } from "./trafficPresets";

beforeEach(() => vi.restoreAllMocks());
describe("edit history", () => {
  it("undoes, redoes, and discards redo on a new branch", () => {
    const history = recordEdit(initialHistory("00"), "00", "01");
    const undo = undoEdit(history, "01")!;
    expect(undo.hex).toBe("00");
    expect(redoEdit(undo.history, "00")?.hex).toBe("01");
    const branch = recordEdit(undo.history, "00", "02");
    expect(redoEdit(branch, "02")).toBeNull();
    expect(branch.original).toBe("00");
  });
  it("keeps bounded named revisions", () => {
    let history = initialHistory("00");
    for (let i = 0; i < 25; i++) history = namedRevision(history, `r${i}`, "01");
    expect(history.revisions).toHaveLength(20);
    history = namedRevision(history, "r24", "02");
    expect(history.revisions.filter((r) => r.name === "r24")).toEqual([{ name: "r24", hex: "02" }]);
  });
});
describe("decoded columns", () => {
  it("batches only requested packets and reuses their values", async () => {
    vi.useFakeTimers();
    const lookup = vi.spyOn(desktop, "packetFieldValues").mockResolvedValue({ "1": [7], "2": [8] });
    const store = createDecodedColumnStore("/one.mineburp", ["slot"]);
    store.ensure(1);
    store.ensure(2);
    store.ensure(1);
    await vi.advanceTimersByTimeAsync(20);
    expect(lookup).toHaveBeenCalledExactlyOnceWith("/one.mineburp", [1, 2], ["slot"]);
    expect(store.get(1)).toEqual([7]);
    store.ensure(1);
    await vi.advanceTimersByTimeAsync(20);
    expect(lookup).toHaveBeenCalledTimes(1);
    store.dispose();
    vi.useRealTimers();
  });
  it("can remount under StrictMode and never crosses project stores", async () => {
    vi.useFakeTimers();
    const lookup = vi.spyOn(desktop, "packetFieldValues").mockResolvedValue({ "1": ["one"] });
    const a = createDecodedColumnStore("/one.mineburp", ["slot"]);
    a.ensure(1);
    a.dispose();
    a.ensure(1);
    await vi.advanceTimersByTimeAsync(20);
    const b = createDecodedColumnStore("/two.mineburp", ["slot"]);
    b.ensure(1);
    await vi.advanceTimersByTimeAsync(20);
    expect(lookup).toHaveBeenNthCalledWith(2, "/two.mineburp", [1], ["slot"]);
    a.dispose();
    b.dispose();
    vi.useRealTimers();
  });
});
it("traffic presets are independent and explicit", () => {
  for (const p of TRAFFIC_PRESETS) expect(trafficPreset(p)).toBeDefined();
  expect(trafficPreset("login").states).toEqual(["handshake", "status", "login"]);
  expect(trafficPreset("dropped").dispositions).toEqual(["dropped"]);
  const quiet = trafficPreset("quiet");
  expect(quiet.expression).not.toContain("name ~ move ||");
  expect(trafficPreset("all").expression).toBe("");
});

it("coalesces typing until a pause without coalescing explicit edits", async () => {
  const { initialHistory, recordEdit, undoEdit } = await import("./editHistory");
  const now = vi.spyOn(Date, "now").mockReturnValue(1000);
  let history = recordEdit(initialHistory("00"), "00", "01", true);
  now.mockReturnValue(1100);
  history = recordEdit(history, "01", "02", true);
  expect(undoEdit(history, "02")?.hex).toBe("00");
  now.mockReturnValue(2000);
  history = recordEdit(history, "02", "03", true);
  expect(undoEdit(history, "03")?.hex).toBe("02");
  now.mockRestore();
});
