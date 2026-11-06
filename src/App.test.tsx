import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { App } from "./App";
import { annotationStore } from "./lib/annotations";
import { desktop } from "./lib/desktop";

const state = vi.hoisted(() => ({ path: "a" }));
vi.mock("./hooks/useMineBurp", async (importOriginal) => {
  const original = await importOriginal<typeof import("./hooks/useMineBurp")>();
  return {
    ...original,
    useMineBurp: () => ({
      ...original.useMineBurp(),
      project: { path: state.path, name: "Test", temporary: false, encrypted: false, read_only: false },
    }),
  };
});
it("switches views with shortcuts and clears project-scoped caches on switching", () => {
  vi.spyOn(desktop, "isAvailable").mockReturnValue(false);
  const reset = vi.spyOn(annotationStore, "reset");
  localStorage.setItem("mineburp.theme", "light");
  const ui = render(<App />);
  fireEvent.keyDown(window, { key: "3", ctrlKey: true });
  expect(document.querySelector('.main-nav [aria-current="page"]')).toHaveTextContent("Repeater");
  fireEvent.keyDown(window, { key: "k", ctrlKey: true });
  expect(screen.getByRole("dialog")).toBeInTheDocument();
  state.path = "b";
  ui.rerender(<App />);
  expect(reset).toHaveBeenCalledTimes(2);
  vi.restoreAllMocks();
});
