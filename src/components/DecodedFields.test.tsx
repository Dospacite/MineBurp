import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DecodedFields, visibleControls } from "./DecodedFields";

describe("visibleControls", () => {
  it("shows a Forge handshake marker's NUL", () => {
    expect(visibleControls("play.example.net\u0000FORGE")).toBe("play.example.net␀FORGE");
  });

  it("keeps line breaks and tabs", () => {
    expect(visibleControls("a\tb\nc\r\n")).toBe("a\tb\nc\r\n");
  });
});

describe("DecodedFields", () => {
  const insight = (fields: Record<string, unknown>) => ({ fields, stream: [] }) as never;

  it("lists each built-in field once", () => {
    render(<DecodedFields insight={insight({ server_port: 25565, next_state: 2 })} schema={null} />);
    expect(screen.getAllByText("server port")).toHaveLength(1);
    expect(screen.getAllByText("25565")).toHaveLength(1);
  });

  it("lets a schema field replace a built-in field of the same name", () => {
    render(
      <DecodedFields
        insight={insight({ channel: "mod:hello", data: "00ff" })}
        schema={{ data: "decoded" }}
      />,
    );
    expect(screen.getAllByText("data")).toHaveLength(1);
    expect(screen.getByText("decoded")).toBeInTheDocument();
    expect(screen.queryByText("00ff")).not.toBeInTheDocument();
    expect(screen.getByText("mod:hello")).toBeInTheDocument();
  });
});
