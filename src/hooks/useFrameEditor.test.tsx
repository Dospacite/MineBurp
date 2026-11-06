import { act, renderHook } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, expect, it, vi } from "vitest";
import { desktop } from "../lib/desktop";
import { useFrameEditor } from "./useFrameEditor";

const field = { name: "value", kind: "u8" as const, offset: 0, length: 1, value: 0 };
beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(desktop, "packetLayout").mockResolvedValue({ name: "test", complete: true, fields: [field] });
});
it("serializes commits against the latest bytes and waits before sending", async () => {
  const edit = vi
    .spyOn(desktop, "fieldEdit")
    .mockImplementation(async (bytes) => new Uint8Array([(bytes[0] ?? 0) + 1]));
  const { result } = renderHook(() => {
    const [hex, setHex] = useState("00");
    return useFrameEditor(hex, "play", "client_to_server", null, 1, setHex, vi.fn());
  });
  await act(async () => {
    void result.current.commitField(field, "1");
    void result.current.commitField(field, "2");
    await result.current.flush();
  });
  expect(Array.from(edit.mock.calls[1]?.[0] ?? [])).toEqual([1]);
  expect(result.current.latestHex().trim()).toBe("02");
});
it("rejects a commit whose frame was replaced while encoding", async () => {
  let finish!: (value: Uint8Array) => void;
  vi.spyOn(desktop, "fieldEdit").mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const apply = vi.fn();
  const { result, rerender } = renderHook(
    ({ id }) => useFrameEditor("00", "play", "client_to_server", null, id, apply, vi.fn()),
    { initialProps: { id: 1 } },
  );
  let pending!: Promise<void>;
  await act(async () => {
    pending = result.current.commitField(field, "1");
    await Promise.resolve();
    await Promise.resolve();
  });
  rerender({ id: 2 });
  await act(async () => {
    finish(new Uint8Array([1]));
    await expect(pending).rejects.toThrow("frame changed");
  });
  expect(apply).not.toHaveBeenCalled();
});
