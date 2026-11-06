import { act, renderHook } from "@testing-library/react";
import { expect, it } from "vitest";
import {
  notifyTrafficAppend,
  publishConnections,
  useTrafficAppend,
  useTrafficConnections,
} from "./trafficStore";

it("append notifications update only append subscribers", () => {
  let connectionRenders = 0;
  renderHook(() => {
    connectionRenders++;
    return useTrafficConnections();
  });
  const { result } = renderHook(() => useTrafficAppend());
  const before = result.current;
  act(() => notifyTrafficAppend());
  expect(result.current).toBe(before + 1);
  expect(connectionRenders).toBe(1);
});
it("preserves connection identity for an equal poll", () => {
  const { result } = renderHook(() => useTrafficConnections());
  act(() => publishConnections([]));
  const previous = result.current;
  act(() => publishConnections([]));
  expect(result.current).toBe(previous);
});
