import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { desktop } from "../lib/desktop";
import { LabListener } from "./LabListener";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it("creates a repeated loopback listener, exposes its address and stops it", async () => {
  const start = vi.spyOn(desktop, "labListenerStart").mockResolvedValue(["id", "127.0.0.1:12345"]);
  const stop = vi.spyOn(desktop, "labListenerStop").mockResolvedValue();
  const user = userEvent.setup();
  render(<LabListener onError={vi.fn()} />);
  await user.click(screen.getByText("Lab listener"));
  await user.click(screen.getByLabelText("Stay armed"));
  await user.click(screen.getByRole("button", { name: "Create listener" }));
  expect(start).toHaveBeenCalledWith("127.0.0.1", 25565, true);
  expect(screen.getByDisplayValue("127.0.0.1:12345")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Stop listener" }));
  expect(stop).toHaveBeenCalledWith("id");
  expect(screen.getByRole("button", { name: "Create listener" })).toBeInTheDocument();
});

it("keeps an armed listener across remounts and clears it after the backend idles it out", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.spyOn(desktop, "labListenerStart").mockResolvedValue(["lab", "127.0.0.1:23456"]);
  const active = vi.spyOn(desktop, "labListenerActive").mockResolvedValue(true);
  const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
  const { unmount } = render(<LabListener onError={vi.fn()} />);
  await user.click(screen.getByText("Lab listener"));
  await user.click(screen.getByRole("button", { name: "Create listener" }));
  unmount();
  render(<LabListener onError={vi.fn()} />);
  expect(screen.getByDisplayValue("127.0.0.1:23456")).toBeInTheDocument();
  active.mockResolvedValue(false);
  await act(() => vi.advanceTimersByTimeAsync(2100));
  expect(active).toHaveBeenCalledWith("lab");
  expect(screen.queryByDisplayValue("127.0.0.1:23456")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Create listener" })).toBeInTheDocument();
});

it("rejects an invalid port before calling the backend", async () => {
  const start = vi.spyOn(desktop, "labListenerStart");
  const user = userEvent.setup();
  render(<LabListener onError={vi.fn()} />);
  await user.click(screen.getByText("Lab listener"));
  const port = screen.getByLabelText("Target port");
  await user.clear(port);
  await user.type(port, "70000");
  expect(screen.getByRole("button", { name: "Create listener" })).toBeDisabled();
  expect(start).not.toHaveBeenCalled();
});
