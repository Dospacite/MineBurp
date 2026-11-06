import { act, render, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { desktop } from "../lib/desktop";
import { ReplaceView } from "./ReplaceView";

it("reloads rules on MCP notification and on a project remount", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  const load = vi.spyOn(desktop, "replacementRules").mockResolvedValue([]);
  let change!: (topic: string) => void;
  vi.spyOn(desktop, "onMcpChange").mockImplementation(async (listener) => {
    change = listener;
    return () => undefined;
  });
  const error = vi.fn();
  const ui = render(<ReplaceView key="a" projectKey="a" seed={null} onError={error} />);
  await waitFor(() => expect(load).toHaveBeenCalledTimes(1));
  await act(async () => change("rules"));
  expect(load).toHaveBeenCalledTimes(2);
  ui.rerender(<ReplaceView key="b" projectKey="b" seed={null} onError={error} />);
  await waitFor(() => expect(load).toHaveBeenCalledTimes(3));
  vi.restoreAllMocks();
});
