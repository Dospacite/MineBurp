import {
  BarChart3,
  Binary,
  Boxes,
  Braces,
  Crosshair,
  Fingerprint,
  GitCompare,
  Hand,
  Moon,
  Network,
  Radio,
  Repeat2,
  Replace,
  ScrollText,
  Search,
  Sun,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Brand } from "./components/Brand";
import { CommandPalette, type PaletteCommand } from "./components/CommandPalette";
import { type DecoderRequest, DecoderSidebar } from "./components/DecoderSidebar";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ErrorLog } from "./components/ErrorLog";
import { FindingPicker } from "./components/FindingPicker";
import type { PacketActions } from "./components/PacketHistory";
import { ProjectControl } from "./components/ProjectControl";
import { openSetup, SetupPanel } from "./components/SetupPanel";
import { Toast } from "./components/Toast";
import type { PacketView, SavedFilter, View } from "./domain/types";
import { message, useMineBurp } from "./hooks/useMineBurp";
import { useTheme } from "./hooks/useTheme";
import { t } from "./i18n";
import { annotationStore } from "./lib/annotations";
import { addDecodedColumn } from "./lib/columns";
import { desktop, formatRawHex, readPayload } from "./lib/desktop";
import { andExpression, quoteValue } from "./lib/expressions";
import { flushProjectEditors } from "./lib/projectWrites";
import { type SelectionActions, SelectionActionsContext } from "./lib/selectionActions";
import { TRAFFIC_PRESETS, trafficPreset } from "./lib/trafficPresets";
import { ChannelExplorerView } from "./views/ChannelExplorerView";
import { type CompareSlots, CompareView } from "./views/CompareView";
import { FindingsView } from "./views/FindingsView";
import { InstancesView } from "./views/InstancesView";
import { InterceptView } from "./views/InterceptView";
import { IntruderView, type ResearchRequest } from "./views/IntruderView";
import { type RepeaterRequest, RepeaterView } from "./views/RepeaterView";
import { ReplaceView, type RuleRequest } from "./views/ReplaceView";
import { SchemasView } from "./views/SchemasView";
import { SequencerView } from "./views/SequencerView";
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
  { id: "intruder", labelKey: "app.view.intruder", icon: Crosshair },
  { id: "sequencer", labelKey: "app.view.sequencer", icon: Fingerprint },
  { id: "findings", labelKey: "app.view.findings", icon: ScrollText },
  { id: "channels", labelKey: "app.view.channels", icon: Network },
];

export function App() {
  const workbench = useMineBurp();
  const { theme, toggleTheme } = useTheme();
  const [view, setView] = useState<View>("traffic");
  const [repeaterRequest, setRepeaterRequest] = useState<RepeaterRequest | null>(null);
  const [intruderRequest, setIntruderRequest] = useState<ResearchRequest | null>(null);
  const [sequencerRequest, setSequencerRequest] = useState<ResearchRequest | null>(null);
  const [ruleRequest, setRuleRequest] = useState<RuleRequest | null>(null);
  const [compare, setCompare] = useState<CompareSlots>({ a: null, b: null });
  const [decoderOpen, setDecoderOpen] = useState(false);
  const [decoderRequest, setDecoderRequest] = useState<DecoderRequest | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteFilters, setPaletteFilters] = useState<SavedFilter[]>([]);
  const [logOpen, setLogOpen] = useState(false);
  const nonce = useRef(0);
  const { setError, setNotice, markLogRead } = workbench;

  // Row ids belong to one project; a comparison cannot outlive it.
  const projectPath = workbench.project?.path ?? null;
  const projectRef = useRef(projectPath);
  projectRef.current = projectPath;
  useEffect(() => {
    void projectPath;
    setCompare({ a: null, b: null });
    setRepeaterRequest(null);
    setRuleRequest(null);
    setIntruderRequest(null);
    setSequencerRequest(null);
    annotationStore.reset();
  }, [projectPath]);

  useEffect(() => {
    const open = (event: Event) => {
      setView("repeater");
      window.dispatchEvent(
        new CustomEvent("finding-repeater", { detail: (event as CustomEvent<string>).detail }),
      );
    };
    window.addEventListener("finding-open-repeater", open);
    return () => window.removeEventListener("finding-open-repeater", open);
  }, []);
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
      sendToIntruder: (id) => {
        const sourceProject = projectRef.current;
        void desktop
          .packet(id)
          .then((packet) => {
            if (packet && projectRef.current === sourceProject) {
              setIntruderRequest({ packet, nonce: ++nonce.current });
              setView("intruder");
            }
          })
          .catch((reason) => setError(message(reason)));
      },
      sendToSequencer: (id) => {
        const sourceProject = projectRef.current;
        void desktop
          .packet(id)
          .then((packet) => {
            if (packet && projectRef.current === sourceProject) {
              setSequencerRequest({ packet, nonce: ++nonce.current });
              setView("sequencer");
            }
          })
          .catch((reason) => setError(message(reason)));
      },
      sendToRepeater: (id) => {
        const sourceProject = projectRef.current;
        void desktop
          .packet(id)
          .then((packet) => packet && projectRef.current === sourceProject && openInRepeater(packet))
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

  const selectionActions = useMemo<SelectionActions>(
    () => ({
      intruder: (packet, range, field) => {
        setIntruderRequest({
          packet,
          nonce: ++nonce.current,
          selection: { ...range, field: field?.name, value: field?.value },
        });
        setView("intruder");
      },
      sequencer: (packet, field) => {
        setSequencerRequest({
          packet,
          nonce: ++nonce.current,
          selection: { offset: field.offset, length: field.length, field: field.name, value: field.value },
        });
        setView("sequencer");
      },
      decoder: (packet, range) => {
        const sourceProject = projectRef.current;
        void (async () => {
          if (range.length > 1024 * 1024) throw new Error(t("decoder.selection-limit"));
          const window = await desktop.packetBytes(
            packet.summary.id,
            range.offset,
            Math.min(range.length, 256 * 1024),
          );
          if (!window) throw new Error(t("decoder.missing"));
          // Large selections are loaded with the bounded payload reader.
          let bytes: Uint8Array;
          if (range.length > 256 * 1024) {
            const full = await readPayload(packet.summary.id, range.offset + range.length);
            if (!full.complete && full.bytes.length < range.offset + range.length)
              throw new Error(t("decoder.missing"));
            bytes = full.bytes.slice(range.offset, range.offset + range.length);
          } else {
            bytes = Uint8Array.from(atob(window.base64), (c) => c.charCodeAt(0));
            if (bytes.length !== range.length) throw new Error(t("decoder.missing"));
          }
          if (projectRef.current !== sourceProject) return;
          setDecoderRequest({ input: formatRawHex(bytes), nonce: ++nonce.current });
          setDecoderOpen(true);
        })().catch((error) => setError(message(error)));
      },
      column: (path) => {
        try {
          addDecodedColumn(path);
          setNotice(t("columns.added", { path }));
        } catch (error) {
          setError(message(error));
        }
      },
      find: (value) => {
        setPacketFilter({
          ...packetFilter,
          content: value,
          contentMode: "text",
          contentScope: "contains",
          contentNegate: false,
        });
        setView("traffic");
      },
    }),
    [packetFilter, setPacketFilter, setError, setNotice],
  );

  useEffect(() => {
    if (!paletteOpen || !desktop.isAvailable()) return;
    let live = true;
    void desktop
      .savedFilters()
      .then((filters) => {
        if (live) setPaletteFilters(filters);
      })
      .catch((error) => setError(message(error)));
    return () => {
      live = false;
    };
  }, [paletteOpen, setError]);
  const paletteCommands: PaletteCommand[] = [
    { id: "setup", label: "Open Setup", keywords: "capture dumpcap agent assistance", run: openSetup },
    ...navigation.map((item) => ({
      id: `view-${item.id}`,
      label: t(item.labelKey),
      keywords: "view tool",
      run: () => setView(item.id),
    })),
    {
      id: "decoder",
      label: t("decoder.title"),
      keywords: "sidebar transform encode decode",
      run: () => setDecoderOpen(true),
    },
    { id: "theme", label: t("palette.theme"), run: toggleTheme },
    ...TRAFFIC_PRESETS.map((p) => ({
      id: `preset-${p}`,
      label: `${t("preset.title")}: ${t(`preset.${p}`)}`,
      run: () => {
        setPacketFilter(trafficPreset(p));
        setView("traffic");
      },
    })),
    ...paletteFilters.map((f) => ({
      id: `filter-${f.id}`,
      label: `${t("palette.filter")}: ${f.name}`,
      run: () => {
        setPacketFilter({ ...trafficPreset("all"), ...f.filter });
        setView("traffic");
      },
    })),
    {
      id: "selected-repeater",
      label: t("menu.repeater"),
      disabled: !workbench.selectedPacket,
      run: () => {
        if (workbench.selectedPacket) openInRepeater(workbench.selectedPacket);
      },
    },
    {
      id: "selected-intruder",
      label: t("menu.intruder"),
      disabled: !workbench.selectedPacket,
      run: () => {
        if (workbench.selectedPacket) actions.sendToIntruder?.(workbench.selectedPacket.summary.id);
      },
    },
    {
      id: "selected-sequencer",
      label: t("menu.sequencer"),
      disabled: !workbench.selectedPacket,
      run: () => {
        if (workbench.selectedPacket) actions.sendToSequencer?.(workbench.selectedPacket.summary.id);
      },
    },
    {
      id: "selected-decoder",
      label: t("selection.decoder"),
      disabled: !workbench.selectedPacket,
      run: () => {
        const packet = workbench.selectedPacket;
        if (packet)
          selectionActions.decoder(packet, { offset: 0, length: Math.min(packet.total_bytes, 1024 * 1024) });
      },
    },
  ];

  useEffect(() => {
    if (!desktop.isAvailable()) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void import("@tauri-apps/api/window")
      .then(async ({ getCurrentWindow }) => {
        const window = getCurrentWindow();
        let closing = false;
        const unsubscribe = await window.onCloseRequested((event) => {
          event.preventDefault();
          if (closing) return;
          closing = true;
          void flushProjectEditors()
            .then(() => window.destroy())
            .catch((error) => {
              closing = false;
              setError(message(error));
              if (
                globalThis.confirm(`Could not save project edits: ${message(error)}. Close and discard them?`)
              )
                void window.destroy();
            });
        });
        if (disposed) unsubscribe();
        else unlisten = unsubscribe;
      })
      .catch((error) => setError(message(error)));
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [setError]);

  useEffect(() => {
    void view;
    document
      .querySelector<HTMLElement>('.main-nav [aria-current="page"]')
      ?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [view]);

  // Ctrl/Cmd+number switches views, in navigation order.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
      if (event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
        return;
      }
      if (paletteOpen) return;
      const digit = Number(event.key);
      if (!/^[0-9]$/.test(event.key)) return;
      const target = navigation[digit === 0 ? 9 : digit - 1];
      if (!target) return;
      event.preventDefault();
      setView(target.id);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [paletteOpen]);

  return (
    <SelectionActionsContext.Provider value={selectionActions}>
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
                  shortcut: index < 10 ? `${shortcutModifier}+${(index + 1) % 10}` : `${shortcutModifier}+K`,
                })}
              >
                <Icon size={15} aria-hidden="true" />
                <span className="nav-label">{t(labelKey)}</span>
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
              className="icon-button"
              title={t("palette.shortcut")}
              aria-label={t("palette.title")}
              onClick={() => setPaletteOpen(true)}
            >
              <Search size={15} />
            </button>
            <button
              type="button"
              className={`icon-button ${decoderOpen ? "on" : ""}`}
              title={t("decoder.title")}
              aria-label={t("decoder.title")}
              aria-expanded={decoderOpen}
              onClick={() => setDecoderOpen((open) => !open)}
            >
              <Binary size={15} />
            </button>
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
            <span
              className="session-indicator"
              role="status"
              title={t(`app.capture.${workbench.captureStatus}`)}
            >
              <span className={`status-dot ${statusDot[workbench.captureStatus]}`} aria-hidden="true" />
              <span className="session-label">{t(`app.capture.${workbench.captureStatus}`)}</span>
            </span>
            <button
              type="button"
              className="icon-button theme-toggle"
              onClick={toggleTheme}
              aria-label={themeSwitchLabel(theme)}
              title={themeSwitchLabel(theme)}
            >
              {theme === "dark" ? (
                <Sun size={15} aria-hidden="true" />
              ) : (
                <Moon size={15} aria-hidden="true" />
              )}
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

        <div className={`workbench-body ${decoderOpen ? "decoder-open" : ""}`}>
          <div className="workspace">
            <FindingPicker key={projectPath} projectKey={projectPath} onError={setError} />
            {view === "findings" && (
              <FindingsView
                key={projectPath}
                projectKey={projectPath}
                onError={setError}
                onPacket={(id) => {
                  setView("traffic");
                  setTimeout(
                    () => window.dispatchEvent(new CustomEvent("finding-packet", { detail: id })),
                    0,
                  );
                }}
              />
            )}
            <div className="view-host" hidden={view !== "intruder"}>
              <ErrorBoundary>
                <IntruderView
                  key={projectPath}
                  request={intruderRequest}
                  projectKey={projectPath}
                  onError={workbench.setError}
                />
              </ErrorBoundary>
            </div>
            <div className="view-host" hidden={view !== "sequencer"}>
              <ErrorBoundary>
                <SequencerView
                  key={projectPath}
                  request={sequencerRequest}
                  projectKey={projectPath}
                  onError={workbench.setError}
                />
              </ErrorBoundary>
            </div>
            {/* The Repeater stays mounted so unsaved tabs survive a trip to another view. */}
            <div className="view-host" hidden={view !== "repeater"}>
              <ErrorBoundary>
                <RepeaterView
                  key={projectPath}
                  projectKey={projectPath}
                  request={repeaterRequest}
                  onRequestHandled={onRepeaterHandled}
                  visible={view === "repeater" && !paletteOpen}
                  onError={workbench.setError}
                />
              </ErrorBoundary>
            </div>
            {view === "traffic" && (
              <ErrorBoundary>
                <TrafficView
                  key={projectPath}
                  capabilities={workbench.capabilities}
                  project={workbench.project}
                  selectedPacket={workbench.selectedPacket}
                  selectedPacketId={workbench.selectedPacketId}
                  filter={workbench.packetFilter}
                  onFilterChange={workbench.setPacketFilter}
                  connectionId={workbench.connectionId}
                  onConnectionChange={workbench.setConnectionId}
                  decryptMode={workbench.decryptMode}
                  captureStatus={workbench.captureStatus}
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
            {view === "channels" && (
              <ErrorBoundary>
                <ChannelExplorerView
                  key={projectPath}
                  filter={workbench.packetFilter}
                  connectionId={workbench.connectionId}
                  projectKey={projectPath}
                  onTraffic={(filter) => {
                    setPacketFilter(filter);
                    setView("traffic");
                  }}
                  onRepeater={openInRepeater}
                  onError={setError}
                />
              </ErrorBoundary>
            )}
            {view === "stats" && (
              <ErrorBoundary>
                <StatsView
                  key={projectPath}
                  project={workbench.project}
                  filter={workbench.packetFilter}
                  connectionId={workbench.connectionId}
                  onApplyName={applyName}
                  onApplyConnection={applyConnection}
                  onError={workbench.setError}
                />
              </ErrorBoundary>
            )}
            {view === "intercept" && (
              <ErrorBoundary>
                <InterceptView
                  key={projectPath}
                  onRepeater={openInRepeater}
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
                  key={projectPath}
                  projectKey={projectPath}
                  seed={workbench.selectedPacket}
                  request={ruleRequest}
                  onRequestHandled={onRuleHandled}
                  onError={workbench.setError}
                />
              </ErrorBoundary>
            )}
            {view === "schemas" && (
              <ErrorBoundary>
                <SchemasView key={projectPath} onError={workbench.setError} />
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

          <DecoderSidebar
            request={decoderRequest}
            open={decoderOpen}
            onClose={() => setDecoderOpen(false)}
            onError={setError}
          />
        </div>
        <SetupPanel banner />
        {paletteOpen && <CommandPalette commands={paletteCommands} onClose={() => setPaletteOpen(false)} />}
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
    </SelectionActionsContext.Provider>
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
