import { X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { t } from "../i18n";

export type ToastTone = "error" | "info";

const DISMISS_AFTER_MS: Record<ToastTone, number> = { error: 10_000, info: 4_000 };

/**
 * The single transient message in the corner.
 *
 * Errors used to stay until dismissed by hand, so one stale failure sat over
 * the traffic table indefinitely. They now leave on their own, but not while
 * the pointer is over them — a message being read must not vanish.
 */
export function Toast({ text, tone, onDismiss }: { text: string; tone: ToastTone; onDismiss: () => void }) {
  const [hovered, setHovered] = useState(false);
  const dismiss = useRef(onDismiss);
  dismiss.current = onDismiss;

  useEffect(() => {
    if (hovered) return undefined;
    const timer = window.setTimeout(() => dismiss.current(), DISMISS_AFTER_MS[tone]);
    return () => window.clearTimeout(timer);
  }, [hovered, tone]);

  return (
    <div
      className={`toast ${tone}`}
      role={tone === "error" ? "alert" : "status"}
      onPointerEnter={() => setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      <span>{text}</span>
      <button type="button" className="icon-button" onClick={onDismiss} aria-label={t("app.toast.dismiss")}>
        <X size={15} aria-hidden="true" />
      </button>
    </div>
  );
}
