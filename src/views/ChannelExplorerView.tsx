import { useCallback, useEffect, useRef, useState } from "react";
import { PacketInspector } from "../components/PacketInspector";
import { Split } from "../components/Split";
import type { ChannelStat, PacketFilter, PacketSummary, PacketView } from "../domain/types";
import { message } from "../hooks/useMineBurp";
import { t } from "../i18n";
import { desktop } from "../lib/desktop";
import { andExpression, quoteValue } from "../lib/expressions";

export function ChannelExplorerView({
  filter,
  connectionId,
  projectKey,
  onTraffic,
  onRepeater,
  onError,
}: {
  filter: PacketFilter;
  connectionId: string | null;
  projectKey: string | null;
  onTraffic: (filter: PacketFilter) => void;
  onRepeater: (packet: PacketView) => void;
  onError: (error: string) => void;
}) {
  const [channels, setChannels] = useState<ChannelStat[]>([]);
  const [selected, setSelected] = useState<ChannelStat | null>(null);
  const [samples, setSamples] = useState<PacketSummary[]>([]);
  const [packet, setPacket] = useState<PacketView | null>(null);
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const packetGeneration = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++generation.current;
    setBusy(true);
    try {
      const rows = await desktop.channelStats({ ...filter, connectionId });
      if (version === generation.current) setChannels(rows);
    } catch (error) {
      if (version === generation.current) onError(message(error));
    } finally {
      if (version === generation.current) setBusy(false);
    }
  }, [filter, connectionId, onError]);
  useEffect(() => {
    void projectKey;
    const version = ++generation.current;
    let live = true;
    setSelected(null);
    setSamples([]);
    setPacket(null);
    setBusy(true);
    void desktop
      .channelStats({ ...filter, connectionId })
      .then((rows) => {
        if (live && version === generation.current) setChannels(rows);
      })
      .catch((error) => {
        if (live && version === generation.current) onError(message(error));
      })
      .finally(() => {
        if (live && version === generation.current) setBusy(false);
      });
    return () => {
      live = false;
    };
  }, [filter, connectionId, projectKey, onError]);
  const selectedExpression = selected
    ? `channel == ${quoteValue(selected.channel)} && direction == ${selected.direction} && state == ${selected.state}${selected.protocolVersion === null ? " && !(protocol >= -2147483648)" : ` && protocol == ${selected.protocolVersion}`}`
    : "";
  useEffect(() => {
    let live = true;
    setPacket(null);
    setSamples([]);
    if (selected)
      void desktop
        .packets({
          ...filter,
          connectionId,
          expression: andExpression(filter.expression, selectedExpression),
          limit: 40,
        })
        .then((rows) => {
          if (live) setSamples(rows);
        })
        .catch((error) => {
          if (live) onError(message(error));
        });
    return () => {
      live = false;
    };
  }, [selected, selectedExpression, filter, connectionId, onError]);
  useEffect(() => {
    let live = true;
    const version = ++packetGeneration.current;
    if (selected)
      void desktop
        .packet(selected.samplePacketId)
        .then((value) => {
          if (live && version === packetGeneration.current) setPacket(value);
        })
        .catch((error) => {
          if (live) onError(message(error));
        });
    return () => {
      live = false;
    };
  }, [selected, onError]);
  const visible = channels
    .slice(0, 500)
    .filter((c) => c.channel.toLowerCase().includes(search.toLowerCase()));
  return (
    <Split
      orientation="columns"
      storageKey="channels"
      initial={[0.6, 0.4]}
      minimum={260}
      className="channel-explorer"
    >
      <section className="channel-main">
        <header className="research-toolbar">
          <h2>{t("app.view.channels")}</h2>
          <button type="button" className="button" disabled={busy} onClick={() => void refresh()}>
            {t("channels.refresh")}
          </button>
        </header>
        <p>{t("channels.description")}</p>
        <label>
          {t("channels.search")}
          <input value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        {channels.length > 500 && <p role="status">{t("channels.limit")}</p>}
        <div className="research-results">
          <table>
            <thead>
              <tr>
                {["channel", "direction", "state", "version", "packets", "bytes", "connections"].map((k) => (
                  <th key={k}>{t(`channels.${k}` as Parameters<typeof t>[0])}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((c) => (
                <tr
                  key={`${c.channel}:${c.direction}:${c.state}:${c.protocolVersion}`}
                  className={c === selected ? "selected" : ""}
                >
                  <td>
                    <button type="button" className="link-button" onClick={() => setSelected(c)}>
                      {c.channel}
                    </button>
                  </td>
                  <td>{c.direction}</td>
                  <td>{c.state}</td>
                  <td>{c.protocolVersion ?? "—"}</td>
                  <td>{c.packets}</td>
                  <td>{c.bytes}</td>
                  <td>{c.connections}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!busy && !channels.length && <p>{t("channels.empty")}</p>}
        {selected && (
          <>
            <div className="research-toolbar">
              <button
                type="button"
                className="button"
                onClick={() =>
                  onTraffic({ ...filter, expression: andExpression(filter.expression, selectedExpression) })
                }
              >
                {t("channels.traffic")}
              </button>
              <span>{t("channels.examples")}</span>
            </div>
            <div className="channel-examples">
              {samples.map((p) => (
                <button
                  type="button"
                  className={`button ${packet?.summary.id === p.id ? "active" : ""}`}
                  key={p.id}
                  onClick={() => {
                    const version = ++packetGeneration.current;
                    void desktop
                      .packet(p.id)
                      .then((value) => {
                        if (version === packetGeneration.current) setPacket(value);
                      })
                      .catch((error) => {
                        if (version === packetGeneration.current) onError(message(error));
                      });
                  }}
                >
                  #{p.id} · {p.size} B
                </button>
              ))}
            </div>
          </>
        )}
      </section>
      <PacketInspector packet={packet} onRepeater={onRepeater} onError={onError} />
    </Split>
  );
}
