import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { EMPTY_FILTER, type PacketFilter } from "../domain/types";
import { PacketFilterBar, splitList } from "./PacketFilterBar";

function Harness({ onChange }: { onChange: (filter: PacketFilter) => void }) {
  const [filter, setFilter] = useState<PacketFilter>({ ...EMPTY_FILTER });
  return (
    <PacketFilterBar
      filter={filter}
      onChange={(next) => {
        setFilter(next);
        onChange(next);
      }}
      loaded={0}
      onError={vi.fn()}
    />
  );
}

describe("PacketFilterBar", () => {
  it("accepts a typed comma between packet names", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<Harness onChange={onChange} />);
    await user.click(screen.getByRole("button", { name: /All packets/ }));
    const input = screen.getByPlaceholderText("chat, custom_payload");
    await user.type(input, "chat,");
    // The trailing comma survives the re-render that commits ["chat"].
    expect(input).toHaveValue("chat,");
    await user.type(input, " keep_alive");
    expect(input).toHaveValue("chat, keep_alive");
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ includeNames: ["chat", "keep_alive"] }),
    );
  });

  it("applies a payload search only when asked", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<Harness onChange={onChange} />);
    await user.click(screen.getByRole("button", { name: /All packets/ }));
    await user.type(screen.getByRole("textbox", { name: /payload bytes/ }), "brand");
    expect(onChange).not.toHaveBeenCalledWith(expect.objectContaining({ content: "brand" }));
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ content: "brand" }));
  });
});

describe("splitList", () => {
  it("drops empty entries and whitespace", () => {
    expect(splitList(" chat, ,keep_alive ,")).toEqual(["chat", "keep_alive"]);
  });
});
