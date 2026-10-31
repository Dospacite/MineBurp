import { act, renderHook, waitFor } from "@testing-library/react";
import { type ReactNode, StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { desktop } from "../lib/desktop";
import { flushProjectEditors } from "../lib/projectWrites";
import { useProjectDocument } from "./useProjectDocument";

const initial = { text: "" };
const valid = (v: unknown): v is typeof initial =>
  !!v && typeof v === "object" && "text" in v && typeof v.text === "string";
const wrapper = ({ children }: { children: ReactNode }) => <StrictMode>{children}</StrictMode>;
beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  vi.spyOn(desktop, "workbenchDocumentGet").mockResolvedValue({ version: 1, data: { text: "saved" } });
  vi.spyOn(desktop, "workbenchDocumentSave").mockResolvedValue();
});
afterEach(() => vi.restoreAllMocks());
describe("project research persistence", () => {
  it("restores before saving, autosaves edits, and flushes before a switch", async () => {
    const { result } = renderHook(
      () => useProjectDocument("/one.mineburp", "intruder", initial, valid, vi.fn()),
      { wrapper },
    );
    await waitFor(() => expect(result.current.loaded).toBe(true));
    expect(result.current.value.text).toBe("saved");
    expect(desktop.workbenchDocumentSave).not.toHaveBeenCalled();
    act(() => result.current.setValue({ text: "edited" }));
    await waitFor(() =>
      expect(desktop.workbenchDocumentSave).toHaveBeenCalledWith("/one.mineburp", "intruder", {
        version: 1,
        data: { text: "edited" },
      }),
    );
    act(() => result.current.setValue({ text: "latest" }));
    await act(async () => flushProjectEditors());
    expect(desktop.workbenchDocumentSave).toHaveBeenLastCalledWith("/one.mineburp", "intruder", {
      version: 1,
      data: { text: "latest" },
    });
  });
  it("keeps edits made during a late restore", async () => {
    let finish: (value: unknown) => void = () => {};
    vi.mocked(desktop.workbenchDocumentGet).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }),
    );
    const { result } = renderHook(() =>
      useProjectDocument("/one.mineburp", "sequencer", initial, valid, vi.fn()),
    );
    act(() => result.current.setValue({ text: "new work" }));
    await act(async () => {
      finish({ version: 1, data: { text: "old work" } });
    });
    expect(result.current.value.text).toBe("new work");
  });
  it("does not apply a previous project's late load to the next project", async () => {
    let finish: (value: unknown) => void = () => {};
    vi.mocked(desktop.workbenchDocumentGet).mockImplementation((path) =>
      path === "/one.mineburp"
        ? new Promise((resolve) => {
            finish = resolve;
          })
        : Promise.resolve({ version: 1, data: { text: "second" } }),
    );
    const { result, rerender } = renderHook(
      ({ path }) => useProjectDocument(path, "intruder", initial, valid, vi.fn()),
      { initialProps: { path: "/one.mineburp" } },
    );
    rerender({ path: "/two.mineburp" });
    await waitFor(() => expect(result.current.value.text).toBe("second"));
    await act(async () => {
      finish({ version: 1, data: { text: "first" } });
    });
    expect(result.current.value.text).toBe("second");
    expect(desktop.workbenchDocumentSave).not.toHaveBeenCalled();
  });
  it("preserves edits and reports write failure", async () => {
    vi.mocked(desktop.workbenchDocumentSave).mockRejectedValue(new Error("read-only project"));
    const onError = vi.fn();
    const { result } = renderHook(() =>
      useProjectDocument("/one.mineburp", "sequencer", initial, valid, onError),
    );
    await waitFor(() => expect(result.current.loaded).toBe(true));
    act(() => result.current.setValue({ text: "keep this" }));
    await act(async () => {
      await expect(flushProjectEditors()).rejects.toThrow("read-only");
    });
    expect(result.current.value.text).toBe("keep this");
    expect(result.current.status).toBe("error");
    expect(onError).toHaveBeenCalledWith("read-only project");
  });
});
