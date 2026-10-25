import { Gauge, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import type { LinkConditions, NetworkConditions } from "../domain/types";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { Modal } from "./Modal";

export const NEUTRAL_LINK: LinkConditions = { delay_ms: 0, jitter_ms: 0, bandwidth_bytes_per_second: null };
export const NEUTRAL_CONDITIONS: NetworkConditions = {
  client_to_server: NEUTRAL_LINK,
  server_to_client: NEUTRAL_LINK,
};

/** The backend's ceiling for delay and jitter. Mirrors `MAX_LINK_DELAY_MS`. */
const MAX_DELAY_MS = 120_000;

/** One direction as the operator types it: strings, so a field can be empty mid-edit. */
interface LinkDraft {
  delay: string;
  jitter: string;
  /** KiB per second; empty is unlimited. */
  bandwidth: string;
}

export function isNeutral(conditions: NetworkConditions | null): boolean {
  if (!conditions) return true;
  return [conditions.client_to_server, conditions.server_to_client].every(
    (link) => link.delay_ms === 0 && link.jitter_ms === 0 && link.bandwidth_bytes_per_second === null,
  );
}

function toDraft(link: LinkConditions): LinkDraft {
  return {
    delay: String(link.delay_ms),
    jitter: String(link.jitter_ms),
    bandwidth: link.bandwidth_bytes_per_second === null ? "" : String(link.bandwidth_bytes_per_second / 1024),
  };
}

/** Reads a draft back, or null when a field is out of range. */
export function parseLink(draft: LinkDraft): LinkConditions | null {
  const millis = (text: string) => {
    const value = text.trim() === "" ? 0 : Number(text);
    return Number.isInteger(value) && value >= 0 && value <= MAX_DELAY_MS ? value : null;
  };
  const delay = millis(draft.delay);
  const jitter = millis(draft.jitter);
  let bandwidth: number | null = null;
  if (draft.bandwidth.trim() !== "") {
    const kib = Number(draft.bandwidth);
    if (!Number.isFinite(kib) || kib <= 0) return null;
    bandwidth = Math.max(1, Math.round(kib * 1024));
  }
  if (delay === null || jitter === null) return null;
  return { delay_ms: delay, jitter_ms: jitter, bandwidth_bytes_per_second: bandwidth };
}

/** Edits the delay, jitter and bandwidth applied to proxied traffic. */
export function NetworkConditionsDialog({
  onApplied,
  onClose,
  onError,
}: {
  onApplied: (conditions: NetworkConditions) => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [drafts, setDrafts] = useState<{ c2s: LinkDraft; s2c: LinkDraft } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let current = true;
    void desktop
      .networkConditions()
      .then((conditions) => {
        if (current)
          setDrafts({ c2s: toDraft(conditions.client_to_server), s2c: toDraft(conditions.server_to_client) });
      })
      .catch((reason) => onError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      current = false;
    };
  }, [onError]);

  const c2s = drafts ? parseLink(drafts.c2s) : null;
  const s2c = drafts ? parseLink(drafts.s2c) : null;
  const valid = c2s !== null && s2c !== null;

  async function apply(conditions: NetworkConditions) {
    setBusy(true);
    try {
      const applied = await desktop.setNetworkConditions(conditions);
      onApplied(applied);
      onClose();
    } catch (reason) {
      onError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={t("network.title")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="button" onClick={onClose}>
            {t("network.cancel")}
          </button>
          <button
            type="button"
            className="button"
            disabled={busy}
            onClick={() => void apply(NEUTRAL_CONDITIONS)}
          >
            {t("network.reset")}
          </button>
          <button
            type="button"
            className="button primary"
            disabled={!valid || busy}
            onClick={() => {
              if (c2s && s2c) void apply({ client_to_server: c2s, server_to_client: s2c });
            }}
          >
            {busy ? (
              <Loader2 className="spin" size={13} aria-hidden="true" />
            ) : (
              <Gauge size={13} aria-hidden="true" />
            )}{" "}
            {t("network.apply")}
          </button>
        </>
      }
    >
      <p className="filter-hint">{t("network.detail")}</p>
      {drafts ? (
        <div className="network-conditions">
          <LinkFields
            legend={t("network.direction.c2s")}
            draft={drafts.c2s}
            invalid={c2s === null}
            onChange={(next) => setDrafts({ ...drafts, c2s: next })}
          />
          <LinkFields
            legend={t("network.direction.s2c")}
            draft={drafts.s2c}
            invalid={s2c === null}
            onChange={(next) => setDrafts({ ...drafts, s2c: next })}
          />
        </div>
      ) : (
        <Loader2 className="spin" size={16} aria-hidden="true" />
      )}
    </Modal>
  );
}

function LinkFields({
  legend,
  draft,
  invalid,
  onChange,
}: {
  legend: string;
  draft: LinkDraft;
  invalid: boolean;
  onChange: (draft: LinkDraft) => void;
}) {
  return (
    <fieldset className="network-link" aria-invalid={invalid || undefined}>
      <legend>{legend}</legend>
      <label className="filter-field">
        {t("network.delay")}
        <input
          inputMode="numeric"
          value={draft.delay}
          onChange={(event) => onChange({ ...draft, delay: event.target.value })}
        />
      </label>
      <label className="filter-field">
        {t("network.jitter")}
        <input
          inputMode="numeric"
          value={draft.jitter}
          onChange={(event) => onChange({ ...draft, jitter: event.target.value })}
        />
      </label>
      <label className="filter-field">
        {t("network.bandwidth")}
        <input
          inputMode="decimal"
          value={draft.bandwidth}
          placeholder={t("network.bandwidth.placeholder")}
          onChange={(event) => onChange({ ...draft, bandwidth: event.target.value })}
        />
      </label>
    </fieldset>
  );
}
