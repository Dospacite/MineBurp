import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { desktop } from "../lib/desktop";
import { DecryptWarning } from "./DecryptWarning";
import { openSetup, SetupPanel } from "./SetupPanel";

afterEach(() => vi.restoreAllMocks());
it("shows required failures in the banner and exposes the fix", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  vi.spyOn(desktop, "setupCheck").mockResolvedValue([
    {
      id: "dumpcap",
      status: "fail",
      required: true,
      detail: "Missing dumpcap",
      hint: "Install wireshark-cli",
    },
  ]);
  render(<SetupPanel banner />);
  await userEvent.click(await screen.findByText(/Action required/));
  expect(screen.getByText("Install wireshark-cli")).toBeInTheDocument();
});
it("hides a healthy banner but opens from the palette event", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  const check = vi.spyOn(desktop, "setupCheck").mockResolvedValue([]);
  render(<SetupPanel banner />);
  await waitFor(() => expect(check).toHaveBeenCalled());
  expect(screen.queryByRole("region", { name: "Setup" })).not.toBeInTheDocument();
  openSetup();
  expect(await screen.findByRole("region", { name: "Setup" })).toBeInTheDocument();
});
it("warns when decryption has no connected agent", async () => {
  vi.spyOn(desktop, "clientAssistStatus").mockResolvedValue({ connected_agents: 0 } as Awaited<
    ReturnType<typeof desktop.clientAssistStatus>
  >);
  const listener = vi.fn();
  window.addEventListener("mineburp:setup", listener);
  render(<DecryptWarning enabled />);
  expect(screen.getByRole("status")).toHaveTextContent("without decryption");
  await userEvent.click(screen.getByRole("button", { name: "Open Setup" }));
  expect(listener).toHaveBeenCalled();
  window.removeEventListener("mineburp:setup", listener);
});
it("clears the warning when an agent is connected", async () => {
  vi.spyOn(desktop, "clientAssistStatus").mockResolvedValue({ connected_agents: 1 } as Awaited<
    ReturnType<typeof desktop.clientAssistStatus>
  >);
  render(<DecryptWarning enabled />);
  await waitFor(() => expect(screen.queryByRole("status")).not.toBeInTheDocument());
});
