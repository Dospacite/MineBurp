import { Boxes, Braces, Moon, Radio, Repeat2, Sun, X } from "lucide-react";
import { useState } from "react";

import type { View } from "./domain/types";
import { Brand } from "./components/Brand";
import { ProjectControl } from "./components/ProjectControl";
import { useMineBurp } from "./hooks/useMineBurp";
import { useTheme } from "./hooks/useTheme";
import { InstancesView } from "./views/InstancesView";
import { RepeaterView } from "./views/RepeaterView";
import { SchemasView } from "./views/SchemasView";
import { TrafficView } from "./views/TrafficView";

const navigation: Array<{ id: View; label: string; icon: typeof Radio }> = [
  { id: "traffic", label: "Traffic", icon: Radio },
  { id: "repeater", label: "Repeater", icon: Repeat2 },
  { id: "schemas", label: "Schemas", icon: Braces },
  { id: "instances", label: "Instances", icon: Boxes },
];

export function App() {
  const workbench = useMineBurp();
  const { theme, toggleTheme } = useTheme();
  const [view, setView] = useState<View>("traffic");

  return (
    <div className="app-shell">
      <header className="topbar">
        <Brand />
        <nav className="main-nav" aria-label="Workbench views">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}>
              <Icon size={15} aria-hidden="true" />
              {label}
            </button>
          ))}
        </nav>
        <div className="topbar-actions">
          <span className="session-indicator"><span className={`status-dot ${workbench.captureStatus === "running" ? "active" : workbench.captureStatus === "failed" ? "failed" : "idle"}`} />{workbench.captureStatus === "running" ? "capturing" : workbench.captureStatus}</span>
          <button
            className="icon-button theme-toggle"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
            title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            {theme === "dark" ? <Sun size={15} aria-hidden="true" /> : <Moon size={15} aria-hidden="true" />}
          </button>
          <ProjectControl project={workbench.project} onChange={(project) => { workbench.setProject(project); void workbench.refresh(); }} onError={workbench.setError} />
        </div>
      </header>

      <div className="runtime-note" hidden={undefined} data-visible={!window.__TAURI_INTERNALS__}>
        Browser preview — automatic capture and project actions require the Tauri desktop runtime.
      </div>

      <div className="workspace">
        {view === "repeater" && <RepeaterView sessions={workbench.connections} seed={workbench.selectedPacket} onError={workbench.setError} />}
        {view === "traffic" && (
          <TrafficView
            capabilities={workbench.capabilities}
            project={workbench.project}
            connections={workbench.connections}
            selectedPacket={workbench.selectedPacket}
            selectedPacketId={workbench.selectedPacketId}
            decryptMode={workbench.decryptMode}
            captureStatus={workbench.captureStatus}
            appendSignal={workbench.appendSignal}
            onSelectPacket={workbench.selectPacket}
            onDecryptModeChange={workbench.setDecryptMode}
            onOpenRepeater={() => setView("repeater")}
            onError={workbench.setError}
          />
        )}
        {view === "schemas" && <SchemasView onError={workbench.setError} />}
        {view === "instances" && <InstancesView onError={workbench.setError} />}
      </div>

      {workbench.error && <div className="toast" role="alert"><span>{workbench.error}</span><button className="icon-button" onClick={() => workbench.setError(null)} aria-label="Dismiss error"><X size={15} /></button></div>}
    </div>
  );
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}
