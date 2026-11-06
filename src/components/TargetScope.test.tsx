import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { OutOfScopeBadge, ScopeStatus } from "./TargetScope";

describe("target scope indicators", () => {
  it("badges only connections the scope excludes", () => {
    const { rerender } = render(<OutOfScopeBadge connection={{ in_scope: false }} />);
    expect(screen.getByText("Out of scope")).toBeInTheDocument();
    rerender(<OutOfScopeBadge connection={{ in_scope: true }} />);
    expect(screen.queryByText("Out of scope")).not.toBeInTheDocument();
    rerender(<OutOfScopeBadge connection={{}} />);
    expect(screen.queryByText("Out of scope")).not.toBeInTheDocument();
  });

  it("reports refused routes only while a scope is set", () => {
    const base = { enabled: true, route_adapter: "private", active_sessions: 0 };
    const { rerender } = render(<ScopeStatus status={{ ...base, scope_restricted: false }} />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    rerender(<ScopeStatus status={{ ...base, scope_restricted: true, out_of_scope_refusals: 0 }} />);
    expect(screen.getByRole("status")).toHaveTextContent(/^Target scope active$/);
    rerender(<ScopeStatus status={{ ...base, scope_restricted: true, out_of_scope_refusals: 3 }} />);
    expect(screen.getByRole("status")).toHaveTextContent("3 out-of-scope routes connected directly");
  });
});
