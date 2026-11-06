import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { PacketLayout } from "../domain/types";
import { FieldEditor } from "./FieldEditor";

const layout: PacketLayout = {
  name: "set_container_slot",
  complete: true,
  fields: [{ name: "item.tag", kind: "nbt", offset: 1, length: 8, value: '{"count": 1}' }],
};

describe("FieldEditor", () => {
  it("edits NBT as JSON and commits with Ctrl+Enter", () => {
    const onCommit = vi.fn();
    render(<FieldEditor layout={layout} onCommit={onCommit} busy={false} />);
    const editor = screen.getByDisplayValue('{"count": 1}');
    expect(editor.tagName).toBe("TEXTAREA");

    fireEvent.change(editor, { target: { value: '{"count": 64}' } });
    fireEvent.keyDown(editor, { key: "Enter" });
    expect(onCommit).not.toHaveBeenCalled();
    fireEvent.keyDown(editor, { key: "Enter", ctrlKey: true });
    fireEvent.blur(editor);
    expect(onCommit).toHaveBeenCalledWith(layout.fields[0], '{"count": 64}');
  });

  it("keeps line breaks in short strings", () => {
    const onCommit = vi.fn();
    const field = { name: "message", kind: "string" as const, offset: 1, length: 6, value: "a\nb" };
    render(
      <FieldEditor
        layout={{ name: "system_chat", complete: true, fields: [field] }}
        onCommit={onCommit}
        busy={false}
      />,
    );
    const editor = screen.getByRole("textbox") as HTMLTextAreaElement;
    expect(editor.value).toBe("a\nb");
    // A single-line input would drop the newline.
    expect(editor.tagName).toBe("TEXTAREA");
    fireEvent.change(editor, { target: { value: "a\nc" } });
    fireEvent.blur(editor);
    expect(onCommit).toHaveBeenCalledWith(field, "a\nc");
  });
});

it.each(["short", "line\nbreak", "x".repeat(100)])(
  "Ctrl+Enter commits %s without bubbling a send",
  (value) => {
    const commit = vi.fn();
    const bubble = vi.fn();
    render(
      // biome-ignore lint/a11y/noStaticElementInteractions: observes bubbling in this regression test.
      <div role="presentation" onKeyDown={bubble}>
        <FieldEditor
          busy={false}
          layout={{
            name: "test",
            complete: true,
            fields: [{ name: "text", kind: "string", offset: 0, length: 1, value }],
          }}
          onCommit={commit}
        />
      </div>,
    );
    const input = screen.getByRole("textbox");
    input.focus();
    fireEvent.change(input, { target: { value: `${value}!` } });
    fireEvent.keyDown(input, { key: "Enter", ctrlKey: true });
    expect(commit).toHaveBeenCalled();
    expect(bubble).not.toHaveBeenCalled();
  },
);
