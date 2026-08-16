import type { ReactNode } from "react";

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <p className="empty-title">{title}</p>
      <p>{detail}</p>
      {action}
    </div>
  );
}
