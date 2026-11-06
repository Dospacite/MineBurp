import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { addToFinding, FindingPicker } from "../components/FindingPicker";
import { desktop } from "../lib/desktop";
import { emptyFinding, FindingsView } from "./FindingsView";

afterEach(() => vi.restoreAllMocks());
it("lists findings and filters severity", async () => {
  vi.spyOn(desktop, "findings").mockResolvedValue([
    { ...emptyFinding(), id: "one", title: "Unsafe channel", severity: "high" },
  ]);
  render(<FindingsView projectKey="/test.mineburp" onError={vi.fn()} onPacket={vi.fn()} />);
  expect(await screen.findByText(/Unsafe channel/)).toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Severity"), "low");
  expect(screen.queryByText(/Unsafe channel/)).not.toBeInTheDocument();
});
it("creates a finding with packet evidence through the picker", async () => {
  const call = vi.spyOn(desktop, "findings").mockResolvedValue([]);
  render(<FindingPicker projectKey="/test.mineburp" onError={vi.fn()} />);
  act(() => addToFinding([{ kind: "packet", id: 42 }]));
  await userEvent.type(screen.getByLabelText("Title"), "Channel issue");
  await userEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith(
      "/test.mineburp",
      "create",
      expect.objectContaining({
        finding: expect.objectContaining({ title: "Channel issue", evidence: [{ kind: "packet", id: 42 }] }),
      }),
    ),
  );
});
