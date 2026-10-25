import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Toast } from "./Toast";

describe("Toast", () => {
  afterEach(() => vi.useRealTimers());

  it("dismisses itself, but not while hovered", () => {
    vi.useFakeTimers();
    const onDismiss = vi.fn();
    render(<Toast tone="error" text="boom" onDismiss={onDismiss} />);

    fireEvent.pointerEnter(screen.getByRole("alert"));
    act(() => vi.advanceTimersByTime(30_000));
    expect(onDismiss).not.toHaveBeenCalled();

    fireEvent.pointerLeave(screen.getByRole("alert"));
    act(() => vi.advanceTimersByTime(10_000));
    expect(onDismiss).toHaveBeenCalledOnce();
  });
});
