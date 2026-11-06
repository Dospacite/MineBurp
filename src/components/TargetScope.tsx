import type { ConnectionSnapshot, DecryptModeStatus } from "../domain/types";

/** Marks a connection whose target the project scope does not authorize. */
export function OutOfScopeBadge({ connection }: { connection: Pick<ConnectionSnapshot, "in_scope"> }) {
  if (connection.in_scope !== false) return null;
  return (
    <span className="project-tag" title="Repeater, Intercept and replacement rules skip this connection">
      Out of scope
    </span>
  );
}

/** Reports an active scope and how many agent routes it sent direct. */
export function ScopeStatus({ status }: { status: DecryptModeStatus | null }) {
  if (!status?.scope_restricted) return null;
  const refused = status.out_of_scope_refusals ?? 0;
  return (
    <p className="scope-status" role="status">
      Target scope active
      {refused > 0 &&
        ` · ${refused.toLocaleString()} out-of-scope ${refused === 1 ? "route" : "routes"} connected directly`}
    </p>
  );
}
