import {
  BarChart3,
  Boxes,
  Braces,
  GitCompare,
  Hand,
  Moon,
  Radio,
  Repeat2,
  Replace,
  ScrollText,
  Sun,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Brand } from "./components/Brand";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ErrorLog } from "./components/ErrorLog";
import type { PacketActions } from "./components/PacketHistory";
import { ProjectControl } from "./components/ProjectControl";
import { Toast } from "./components/Toast";
import type { PacketView, View } from "./domain/types";
import { message, useMineBurp } from "./hooks/useMineBurp";
import { useTheme } from "./hooks/useTheme";
import { t } from "./i18n";
import { annotationStore } from "./lib/annotations";
import { desktop } from "./lib/desktop";
import { andExpression, quoteValue } from "./lib/expressions";
import { type CompareSlots, CompareView } from "./views/CompareView";
import { InstancesView } from "./views/InstancesView";
import { InterceptView } from "./views/InterceptView";
import { type RepeaterRequest, RepeaterView } from "./views/RepeaterView";
import { ReplaceView, type RuleRequest } from "./views/ReplaceView";
import { SchemasView } from "./views/SchemasView";
import { StatsView } from "./views/StatsView";
import { TrafficView } from "./views/TrafficView";

// Newer views go last so the existing Ctrl+number shortcuts keep their views.
const navigation: Array<{ id: View; labelKey: Parameters<typeof t>[0]; icon: typeof Radio }> = [
  { id: "traffic", labelKey: "app.view.traffic", icon: Radio },
  { id: "intercept", labelKey: "app.view.intercept", icon: Hand },
  { id: "repeater", labelKey: "app.view.repeater", icon: Repeat2 },
  { id: "replace", labelKey: "app.view.replace", icon: Replace },
  { id: "schemas", labelKey: "app.view.schemas", icon: Braces },
  { id: "instances", labelKey: "app.view.instances", icon: Boxes },
  { id: "compare", labelKey: "app.view.compare", icon: GitCompare },
  { id: "stats", labelKey: "app.view.stats", icon: BarChart3 },
];

export function App() {
  const workbench = useMineBurp();
  const { theme, toggleTheme } = useTheme();
  const [view, setView] = useState<View>("traffic");
  const [repeaterRequest, setRepeaterRequest] = useState<RepeaterRequest | null>(null);
  const [ruleRequest, setRuleRequest] = useState<RuleRequest | null>(null);
  const [compare, setCompare] = useState<CompareSlots>({ a: null, b: null });
  const [logOpen, setLogOpen] = useState(false);
  const nonce = useRef(0);
  const { setError, setNotice, markLogRead } = workbench;

  // Row ids belong to one project; a comparison cannot outlive it.
  const projectPath = workbench.project?.path ?? null;
  useEffect(() => {
    void projectPath;
    setCompare({ a: null, b: null });
    annotationStore.reset();
  }, [projectPath]);

  const { packetFilter, setPacketFilter, setConnectionId } = workbench;
  const applyName = useCallback(
    (name: string) => {
      setPacketFilter({
        ...packetFilter,
        expression: andExpression(packetFilter.expression, `name == ${quoteValue(name)}`),
      });
      setView("traffic");
    },
    [packetFilter, setPacketFilter],
  );
  const applyConnection = useCallback(
    (connectionId: string) => {
      setConnectionId(connectionId);
      setView("traffic");
    },
    [setConnectionId],
  );

  const openInRepeater = useCallback((packet: PacketView) => {
    setRepeaterRequest({ packet, nonce: ++nonce.current });
    setView("repeater");
  }, []);

  const actions = useMemo<PacketActions>(
    () => ({
      sendToRepeater: (id) => {
        void desktop
          .packet(id)
          .then((packet) => packet && openInRepeater(packet))
          .catch((reason) => setError(message(reason)));
      },
      compare: (id, slot) => {
        setCompare((current) => (slot === "a" ? { a: id, b: current.b } : { a: current.a, b: id }));
        if (slot === "b") setView("compare");
        else setNotice(t("compare.set-a", { id }));
      },
      hasCompareA: compare.a !== null,
      createRule: (expression) => {
        setRuleRequest({ expression, nonce: ++nonce.current });
        setView("replace");
      },
    }),
    [compare.a, openInRepeater, setError, setNotice],
  );

  const onRepeaterHandled = useCallback(
    (handled: number) => setRepeaterRequest((current) => (current?.nonce === handled ? null : current)),
    [],
  );
  const onRuleHandled = useCallback(
    (handled: number) => setRuleRequest((current) => (current?.nonce === handled ? null : current)),
    [],
  );

  // Ctrl/Cmd+number switches views, in navigation order.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
      const target = navigation[Number(event.key) - 1];
      if (!target) return;
      event.preventDefault();
      setView(target.id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="app-shell">
      <header className="topbar">
        <Brand />
        <nav className="main-nav" aria-label={t("app.nav.label")}>
          {navigation.map(({ id, labelKey, icon: Icon }, index) => (
            <button
              type="button"
              key={id}
              className={view === id ? "active" : ""}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
              title={t("app.shortcut.view", {
                view: t(labelKey),
                shortcut: `${shortcutModifier}+${index + 1}`,
              })}
            >
              <Icon size={15} aria-hidden="true" />
              {t(labelKey)}
              {id === "intercept" && workbench.interceptPending > 0 && (
                <span
                  className="nav-badge"
                  title={t("intercept.badge", { count: workbench.interceptPending })}
                >
                  {workbench.interceptPending}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="topbar-actions">
          <button
            type="button"
            className="icon-button log-button"
            aria-label={t("log.open", { count: workbench.unreadErrors })}
            title={t("log.title")}
            onClick={() => {
              setLogOpen(true);
              markLogRead();
            }}
          >
            <ScrollText size={15} aria-hidden="true" />
            {workbench.unreadErrors > 0 && <span className="nav-badge">{workbench.unreadErrors}</span>}
          </button>
          <span className="session-indicator" role="status">
            <span className={`status-dot ${statusDot[workbench.captureStatus]}`} aria-hidden="true" />
            {t(`app.capture.${workbench.captureStatus}`)}
          </span>
          <button
            type="button"
            className="icon-button theme-toggle"
            onClick={toggleTheme}
            aria-label={themeSwitchLabel(theme)}
            title={themeSwitchLabel(theme)}
          >
            {theme === "dark" ? <Sun size={15} aria-hidden="true" /> : <Moon size={15} aria-hidden="true" />}
          </button>
          <ProjectControl
            project={workbench.project}
            onChange={(project) => {
              workbench.setProject(project);
              void workbench.refresh();
            }}
            onError={workbench.setError}
          />
        </div>
      </header>

      <div className="workspace">
        {/* The Repeater stays mounted so unsaved tabs survive a trip to another view. */}
        <div className="view-host" hidden={view !== "repeater"}>
          <ErrorBoundary>
            <RepeaterView
              sessions={workbench.connections}
              request={repeaterRequest}
              onRequestHandled={onRepeaterHandled}
              visible={view === "repeater"}
              onError={workbench.setError}
            />
          </ErrorBoundary>
        </div>
        {view === "traffic" && (
          <ErrorBoundary>
            <TrafficView
              capabilities={workbench.capabilities}
              project={workbench.project}
              connections={workbench.connections}
              selectedPacket={workbench.selectedPacket}
              selectedPacketId={workbench.selectedPacketId}
              filter={workbench.packetFilter}
              onFilterChange={workbench.setPacketFilter}
              connectionId={workbench.connectionId}
              onConnectionChange={workbench.setConnectionId}
              decryptMode={workbench.decryptMode}
              captureStatus={workbench.captureStatus}
              appendSignal={workbench.appendSignal}
              onSelectPacket={workbench.selectPacket}
              onDecryptModeChange={workbench.setDecryptMode}
              onOpenRepeater={openInRepeater}
              actions={actions}
              onError={workbench.setError}
              onNotice={workbench.setNotice}
              onDataChanged={() => void workbench.refresh()}
            />
          </ErrorBoundary>
        )}
        {view === "stats" && (
          <ErrorBoundary>
            <StatsView
              project={workbench.project}
              filter={workbench.packetFilter}
              connectionId={workbench.connectionId}
              connections={workbench.connections}
              appendSignal={workbench.appendSignal}
              onApplyName={applyName}
              onApplyConnection={applyConnection}
              onError={workbench.setError}
            />
          </ErrorBoundary>
        )}
        {view === "intercept" && (
          <ErrorBoundary>
            <InterceptView
              settings={workbench.interceptSettings}
              onSettingsPatch={workbench.patchInterceptSettings}
              pendingSignal={workbench.interceptSignal}
              decryptEnabled={workbench.decryptMode?.enabled ?? false}
              onError={workbench.setError}
            />
          </ErrorBoundary>
        )}
        {view === "replace" && (
          <ErrorBoundary>
            <ReplaceView
              seed={workbench.selectedPacket}
              request={ruleRequest}
              onRequestHandled={onRuleHandled}
              onError={workbench.setError}
            />
          </ErrorBoundary>
        )}
        {view === "schemas" && (
          <ErrorBoundary>
            <SchemasView onError={workbench.setError} />
          </ErrorBoundary>
        )}
        {view === "instances" && (
          <ErrorBoundary>
            <InstancesView onError={workbench.setError} />
          </ErrorBoundary>
        )}
        {view === "compare" && (
          <ErrorBoundary>
            <CompareView
              slots={compare}
              onSwap={() => setCompare(({ a, b }) => ({ a: b, b: a }))}
              onClear={() => setCompare({ a: null, b: null })}
              onError={workbench.setError}
            />
          </ErrorBoundary>
        )}
      </div>

      {logOpen && (
        <ErrorLog
          entries={workbench.log}
          onClear={workbench.clearLog}
          onClose={() => setLogOpen(false)}
          onError={workbench.setError}
        />
      )}

      {workbench.error ? (
        <Toast
          key={workbench.error}
          tone="error"
          text={workbench.error}
          onDismiss={() => workbench.setError(null)}
        />
      ) : (
        workbench.notice && (
          <Toast
            key={workbench.notice}
            tone="info"
            text={workbench.notice}
            onDismiss={() => workbench.setNotice(null)}
          />
        )
      )}
    </div>
  );
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}
const statusDot = { starting: "starting", running: "active", unavailable: "idle", failed: "failed" } as const;

const shortcutModifier = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl";

function themeSwitchLabel(theme: "dark" | "light"): string {
  const mode = theme === "dark" ? t("app.theme.light") : t("app.theme.dark");
  return t("app.theme.switch", { mode });
}
