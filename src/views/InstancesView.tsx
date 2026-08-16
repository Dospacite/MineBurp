import {
  CheckCircle2,
  Copy,
  ExternalLink,
  Loader2,
  LogIn,
  LogOut,
  Play,
  Plug,
  RefreshCw,
  Settings2,
} from "lucide-react";
import { useEffect, useState } from "react";

import type { ClientAssistStatus, InstanceDescriptor } from "../domain/types";
import { desktop } from "../lib/desktop";
import { message } from "../hooks/useMineBurp";
import { EmptyState } from "../components/EmptyState";

const launcherLabels: Record<InstanceDescriptor["launcher"], string> = {
  official: "Minecraft Launcher",
  prism: "Prism Launcher",
  multi_mc: "MultiMC",
  modrinth: "Modrinth",
  curse_forge: "CurseForge",
};

export function InstancesView({ onError }: { onError: (error: string) => void }) {
  const [instances, setInstances] = useState<InstanceDescriptor[]>([]);
  const [account, setAccount] = useState<{ profile: { id: string; name: string } } | null>(null);
  const [authStart, setAuthStart] = useState<{ url: string } | null>(null);
  const [callbackUrl, setCallbackUrl] = useState("");
  const [clientAssist, setClientAssist] = useState<ClientAssistStatus | null>(null);
  const [busyInstance, setBusyInstance] = useState<string | null>(null);
  const [launchingInstance, setLaunchingInstance] = useState<string | null>(null);
  const [setupNotice, setSetupNotice] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState(false);

  async function refresh() {
    try { setInstances(await desktop.instances()); } catch (reason) { onError(message(reason)); }
  }

  useEffect(() => {
    void refresh();
    void desktop.authSession().then(setAccount).catch(() => undefined);
    let mounted = true;
    const updateClientAssist = () => {
      void desktop.clientAssistStatus()
        .then((status) => { if (mounted) setClientAssist(status); })
        .catch(() => undefined);
    };
    updateClientAssist();
    const interval = window.setInterval(updateClientAssist, 2_000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  async function copyText(value: string) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.append(input);
    input.select();
    const copiedSuccessfully = document.execCommand("copy");
    input.remove();
    if (!copiedSuccessfully) throw new Error("Could not copy the JVM argument.");
  }

  async function copyJvmArgument() {
    if (!clientAssist) return;
    try {
      await copyText(clientAssist.jvm_argument);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function beginSignIn() {
    try {
      const next = await desktop.authBegin();
      setAuthStart(next);
      window.open(next.url, "_blank", "noopener,noreferrer");
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function completeSignIn() {
    if (!authStart) return;
    try {
      setAccount(await desktop.authComplete(callbackUrl));
      setAuthStart(null);
      setCallbackUrl("");
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function signOut() {
    await desktop.authSignOut();
    setAccount(null);
  }

  async function launch(instance: InstanceDescriptor) {
    const instanceKey = `${instance.launcher}-${instance.id}`;
    setLaunchingInstance(instanceKey);
    try { await desktop.launch(instance); } catch (reason) { onError(message(reason)); }
    finally { setLaunchingInstance(null); }
  }

  async function configureClientAssist(instance: InstanceDescriptor, enabled: boolean) {
    const instanceKey = `${instance.launcher}-${instance.id}`;
    setBusyInstance(instanceKey);
    try {
      const outcome = await desktop.configureClientAssist(instance, enabled);
      let notice = outcome.message;
      if (outcome.kind === "manual" && enabled) {
        await copyText(outcome.jvm_argument);
        notice = `${notice} The argument was copied to the clipboard.`;
      }
      setSetupNotice((current) => ({ ...current, [instanceKey]: notice }));
      if (outcome.kind === "managed") await refresh();
    } catch (reason) {
      onError(message(reason));
    } finally {
      setBusyInstance(null);
    }
  }

  return (
    <div className="page-view">
      <div className="page-heading page-heading-row"><div><span className="eyebrow">Launch adapters</span><h1>Minecraft instances</h1><p>Launch vanilla, Fabric, Forge, NeoForge, Quilt, and modpack clients normally. System capture observes their network traffic automatically.</p></div><button className="button" onClick={refresh}><RefreshCw size={14} /> Refresh</button></div>
      <section className="client-assist-card" aria-labelledby="client-assist-title">
        <div className="client-assist-heading">
          <div className="client-assist-title"><span className={`status-dot ${clientAssist?.connected_agents ? "active" : "idle"}`} /><span><h2 id="client-assist-title">Advanced session assistance</h2><p>{account ? `Direct OAuth session active for ${account.profile.name}.` : clientAssist?.ready_sessions ? `${clientAssist.ready_sessions} authenticated Minecraft session${clientAssist.ready_sessions === 1 ? " is" : "s are"} ready.` : clientAssist?.connected_agents ? "Minecraft is connected; waiting for its signed-in session." : "Optional for active protocol extensions. Automatic traffic capture does not require this setup."}</p></span></div>
          <span className="assist-count" aria-live="polite"><Plug size={14} /> {clientAssist?.connected_agents ?? 0} connected · {clientAssist?.ready_sessions ?? 0} ready</span>
        </div>
        <div className="jvm-argument-row">
          <label>Manual JVM argument<input readOnly value={clientAssist?.jvm_argument ?? "Loading client-assistance configuration…"} /></label>
          <button className="button" disabled={!clientAssist} onClick={() => void copyJvmArgument()}><Copy size={14} /> {copied ? "Copied" : "Copy"}</button>
        </div>
        <p className="assist-privacy">{account ? "Direct OAuth credentials are held only in MineBurp memory for this process." : "Credentials remain inside the Minecraft process. MineBurp receives only a one-use request to join the selected upstream server."}</p>
        {clientAssist?.direct_oauth_available && <details className="direct-auth">
          <summary><Settings2 size={14} /> Advanced: direct Microsoft sign-in</summary>
          <div className="account-card">
            {account ? (
              <><div><CheckCircle2 size={16} /><span><strong>{account.profile.name}</strong><small>Direct OAuth session overrides launcher assistance</small></span></div><button className="button" onClick={() => void signOut()}><LogOut size={14} /> Sign out</button></>
            ) : (
              <div className="auth-form">
                <div><strong>Build-provided app registration</strong><p>Use this only when your MineBurp build was configured with a Microsoft public-client application.</p></div>
                {!authStart ? (
                  <button className="button" onClick={() => void beginSignIn()}><LogIn size={14} /> Sign in with Microsoft</button>
                ) : (
                  <div className="auth-complete">
                    <a className="button" href={authStart.url} target="_blank" rel="noreferrer"><ExternalLink size={14} /> Open sign-in</a>
                    <label>Callback URL<input value={callbackUrl} onChange={(event) => setCallbackUrl(event.target.value)} placeholder="Paste the full localhost callback URL" /></label>
                    <button className="button primary" disabled={!callbackUrl} onClick={() => void completeSignIn()}>Complete sign-in</button>
                  </div>
                )}
              </div>
            )}
          </div>
        </details>}
      </section>
      {instances.length ? <div className="instance-grid">{instances.map((instance) => {
        const instanceKey = `${instance.launcher}-${instance.id}`;
        const configuring = busyInstance === instanceKey;
        const launching = launchingInstance === instanceKey;
        return <article className="instance-card" key={instanceKey}>
          <div>
            <div className="instance-badges"><span className="loader-badge">{instance.loader}</span>{instance.client_assist_configured && <span className="configured-badge"><CheckCircle2 size={12} /> Client assistance configured</span>}</div>
            <h2>{instance.name}</h2>
            <p>{instance.minecraft_version ?? "Unknown version"} · {launcherLabels[instance.launcher]}</p>
            {setupNotice[instanceKey] && <p className="instance-setup-note" aria-live="polite">{setupNotice[instanceKey]}</p>}
          </div>
          <div className="instance-actions">
            {instance.supports_agent_configuration ? <button className="button" onClick={() => void configureClientAssist(instance, !instance.client_assist_configured)} disabled={configuring}>{configuring ? <Loader2 className="spin" size={14} /> : instance.client_assist_configured ? null : <Settings2 size={14} />} {instance.client_assist_configured ? "Remove assistance" : "Configure assistance"}</button> : <button className="button" onClick={() => void configureClientAssist(instance, true)} disabled={configuring}>{configuring ? <Loader2 className="spin" size={14} /> : <Copy size={14} />} Copy setup argument</button>}
            <button className="button primary" onClick={() => void launch(instance)} disabled={launching}>{launching ? <Loader2 className="spin" size={14} /> : <Play size={14} />} {launching ? "Launching…" : "Launch"}</button>
          </div>
        </article>;
      })}</div> : <EmptyState title="No instances found" detail="Install a supported launcher in its default location, or configure adapter roots in the desktop backend." />}
    </div>
  );
}
