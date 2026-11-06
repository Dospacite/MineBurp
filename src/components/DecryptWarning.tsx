import { useEffect, useState } from "react";
import { desktop } from "../lib/desktop";
import { openSetup } from "./SetupPanel";
export function DecryptWarning({ enabled }: { enabled: boolean }) {
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const update = () =>
      void desktop
        .clientAssistStatus()
        .then((status) => {
          if (alive) setConnected(status.connected_agents > 0);
        })
        .catch(() => {
          if (alive) setConnected(false);
        });
    update();
    const timer = window.setInterval(update, 2000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [enabled]);
  return enabled && !connected ? (
    <p role="status">
      No client agent connected. Minecraft may connect directly without decryption.{" "}
      <button type="button" className="button" onClick={openSetup}>
        Open Setup
      </button>
    </p>
  ) : null;
}
