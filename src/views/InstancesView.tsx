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
import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { openSetup } from "../components/SetupPanel";
import type { ClientAssistStatus, InstanceDescriptor } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";

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

  const refresh = useCallback(async () => {
    try {
      setInstances(await desktop.instances());
    } catch (reason) {
      onError(message(reason));
    }
  }, [onError]);

  useEffect(() => {
    void refresh();
    // A failed session lookup is reported once rather than swallowed: the
    // backend may be degraded, and silence reads as "signed out".
    desktop
      .authSession()
      .then(setAccount)
      .catch((reason) => onError(message(reason)));
    let mounted = true;
    let assistFailures = 0;
    const updateClientAssist = () => {
      void desktop
        .clientAssistStatus()
        .then((status) => {
          if (mounted) setClientAssist(status);
        })
        .catch((reason) => {
          if (!mounted) return;
          assistFailures += 1;
          if (assistFailures === 1) onError(message(reason));
        });
    };
    updateClientAssist();
    const interval = window.setInterval(updateClientAssist, 2_000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [onError, refresh]);

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
    try {
      await desktop.authSignOut();
      setAccount(null);
    } catch (reason) {
      onError(message(reason));
    }
  }

  async function launch(instance: InstanceDescriptor) {
    const instanceKey = `${instance.launcher}-${instance.id}`;
    setLaunchingInstance(instanceKey);
    try {
      await desktop.launch(instance);
    } catch (reason) {
      onError(message(reason));
    } finally {
      setLaunchingInstance(null);
    }
  }

  async function configureClientAssist(instance: InstanceDescriptor, enabled: boolean) {
    const instanceKey = `${instance.launcher}-${instance.id}`;
    setBusyInstance(instanceKey);
    try {
      const outcome = await desktop.configureClientAssist(instance, enabled);
      let notice = outcome.message;
      if (outcome.kind === "manual" && enabled) {
        await copyText(outcome.jvm_argument);
        notice = `${notice} ${t("instances.setup.copied-suffix")}`;
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
      <div className="page-heading page-heading-row">
        <h1>{t("instances.title")}</h1>
        <button type="button" className="button" onClick={openSetup}>
          Setup
        </button>
        <button type="button" className="button" onClick={refresh}>
          <RefreshCw size={14} /> {t("instances.refresh")}
        </button>
      </div>
      <section className="client-assist-card" aria-labelledby="client-assist-title">
        <div className="client-assist-heading">
          <div className="client-assist-title">
            <span className={`status-dot ${clientAssist?.connected_agents ? "active" : "idle"}`} />
            <h2 id="client-assist-title">{t("instances.assistance.title")}</h2>
          </div>
          <span className="assist-count" aria-live="polite">
            <Plug size={14} />{" "}
            {t("instances.connected-count", {
              connected: clientAssist?.connected_agents ?? 0,
              ready: clientAssist?.ready_sessions ?? 0,
            })}
          </span>
        </div>
        <div className="jvm-argument-row">
          <label>
            {t("instances.jvm-argument")}
            <input readOnly value={clientAssist?.jvm_argument ?? "…"} />
          </label>
          <button
            type="button"
            className="button"
            disabled={!clientAssist}
            onClick={() => void copyJvmArgument()}
          >
            <Copy size={14} /> {copied ? t("instances.copied") : t("instances.copy")}
          </button>
        </div>
        {clientAssist?.direct_oauth_available && (
          <details className="direct-auth">
            <summary>
              <Settings2 size={14} /> {t("instances.direct-signin")}
            </summary>
            <div className="account-card">
              {account ? (
                <>
                  <div>
                    <CheckCircle2 size={16} />
                    <strong>{account.profile.name}</strong>
                  </div>
                  <button type="button" className="button" onClick={() => void signOut()}>
                    <LogOut size={14} /> {t("instances.sign-out")}
                  </button>
                </>
              ) : (
                <div className="auth-form">
                  {!authStart ? (
                    <button type="button" className="button" onClick={() => void beginSignIn()}>
                      <LogIn size={14} /> {t("instances.sign-in-microsoft")}
                    </button>
                  ) : (
                    <div className="auth-complete">
                      <a className="button" href={authStart.url} target="_blank" rel="noreferrer">
                        <ExternalLink size={14} /> {t("instances.open-signin")}
                      </a>
                      <label>
                        {t("instances.callback-url")}
                        <input
                          value={callbackUrl}
                          onChange={(event) => setCallbackUrl(event.target.value)}
                          placeholder={t("instances.callback-placeholder")}
                        />
                      </label>
                      <button
                        type="button"
                        className="button primary"
                        disabled={!callbackUrl}
                        onClick={() => void completeSignIn()}
                      >
                        {t("instances.complete-signin")}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </details>
        )}
      </section>
      {instances.length ? (
        <div className="instance-grid">
          {instances.map((instance) => {
            const instanceKey = `${instance.launcher}-${instance.id}`;
            const configuring = busyInstance === instanceKey;
            const launching = launchingInstance === instanceKey;
            return (
              <article className="instance-card" key={instanceKey}>
                <div>
                  <div className="instance-badges">
                    <span className="loader-badge">{instance.loader}</span>
                    {instance.client_assist_configured && (
                      <span className="configured-badge">
                        <CheckCircle2 size={12} /> {t("instances.assisted")}
                      </span>
                    )}
                  </div>
                  <h2>{instance.name}</h2>
                  <p>
                    {instance.minecraft_version ?? t("instances.unknown-version")} ·{" "}
                    {launcherLabels[instance.launcher]}
                  </p>
                  {setupNotice[instanceKey] && (
                    <p className="instance-setup-note" aria-live="polite">
                      {setupNotice[instanceKey]}
                    </p>
                  )}
                </div>
                <div className="instance-actions">
                  {instance.client_assist_stale && (
                    <>
                      <span>Assistance is stale</span>
                      <button
                        type="button"
                        className="button"
                        disabled={configuring}
                        onClick={() => void configureClientAssist(instance, true)}
                      >
                        Reconfigure
                      </button>
                    </>
                  )}
                  {instance.supports_agent_configuration ? (
                    <button
                      type="button"
                      className="button"
                      onClick={() => void configureClientAssist(instance, !instance.client_assist_configured)}
                      disabled={configuring}
                    >
                      {configuring ? (
                        <Loader2 className="spin" size={14} />
                      ) : instance.client_assist_configured ? null : (
                        <Settings2 size={14} />
                      )}{" "}
                      {instance.client_assist_configured
                        ? t("instances.remove-assistance")
                        : t("instances.configure-assistance")}
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="button"
                      onClick={() => void configureClientAssist(instance, true)}
                      disabled={configuring}
                    >
                      {configuring ? <Loader2 className="spin" size={14} /> : <Copy size={14} />}{" "}
                      {t("instances.copy-setup-argument")}
                    </button>
                  )}
                  <button
                    type="button"
                    className="button primary"
                    onClick={() => void launch(instance)}
                    disabled={launching}
                  >
                    {launching ? <Loader2 className="spin" size={14} /> : <Play size={14} />}{" "}
                    {launching ? t("instances.launching") : t("instances.launch")}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      ) : (
        <EmptyState title={t("instances.none.title")} detail={t("instances.none.detail")} />
      )}
    </div>
  );
}
