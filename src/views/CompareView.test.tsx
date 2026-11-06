import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { ConnectionSnapshot, PacketSummary } from "../domain/types";
import { desktop } from "../lib/desktop";
import { CompareView } from "./CompareView";

afterEach(() => vi.restoreAllMocks());
it("switches modes, hides identical rows and navigates differences", async () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(true);
  vi.spyOn(desktop, "connections").mockResolvedValue([
    { id: "a", target: { host: "localhost", port: 25565 } },
    { id: "b", target: { host: "localhost", port: 25565 } },
  ] as ConnectionSnapshot[]);
  const packet = (id: number) =>
    ({ id, state: "login", name: `hello${id}`, direction: "client_to_server" }) as PacketSummary;
  vi.spyOn(desktop, "compareConnections").mockResolvedValue({
    rows: [
      { a: packet(1), b: packet(2), kind: "identical", size_delta: 0, first_difference: null },
      { a: packet(3), b: null, kind: "only_a", size_delta: -2, first_difference: null },
      { a: null, b: packet(4), kind: "only_b", size_delta: 2, first_difference: null },
    ],
    names: [],
  });
  render(<CompareView slots={{ a: null, b: null }} onSwap={vi.fn()} onClear={vi.fn()} onError={vi.fn()} />);
  await userEvent.click(screen.getByRole("button", { name: "Connections" }));
  await screen.findAllByRole("option", { name: /localhost.*a/ });
  await userEvent.click(screen.getByRole("button", { name: "Compare" }));
  await screen.findByText("= Identical");
  await userEvent.click(screen.getByRole("button", { name: /Next difference/ }));
  expect(screen.getByRole("button", { name: /− Only A/ })).toHaveAttribute("aria-pressed", "true");
  await userEvent.click(screen.getByRole("button", { name: /Next difference/ }));
  expect(screen.getByRole("button", { name: /\+ Only B/ })).toHaveAttribute("aria-pressed", "true");
  await userEvent.click(screen.getByRole("button", { name: /Previous difference/ }));
  expect(screen.getByRole("button", { name: /− Only A/ })).toHaveAttribute("aria-pressed", "true");
  await userEvent.click(screen.getByRole("checkbox", { name: "Hide identical" }));
  expect(screen.queryByText("= Identical")).not.toBeInTheDocument();
});
