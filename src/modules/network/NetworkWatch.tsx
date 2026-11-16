import { useEffect, useMemo, useState } from "react";
import type uPlot from "uplot";
import { Plot, Sev } from "../../design/components";
import { ago, clock, rate, stamp } from "../../design/format";
import { api } from "../../ipc/api";
import type { ConnHistoryRow, ConnectionInfo, GeoStatus } from "../../ipc/types";
import { useGhost } from "../../state/store";
import { contactsOf, Sonar } from "../../viz/Sonar";
import "./network.css";

type Tab = "live" | "listen" | "all" | "history";

const TABS: { id: Tab; label: string }[] = [
  { id: "live", label: "Kurulu bağlantılar" },
  { id: "listen", label: "Dinleyen portlar" },
  { id: "all", label: "Tüm soketler" },
  { id: "history", label: "Geçmiş" },
];

const STATE_TR: Record<string, string> = {
  ESTABLISHED: "kurulu",
  LISTEN: "dinliyor",
  TIME_WAIT: "kapanıyor",
  CLOSE_WAIT: "kapanış bekliyor",
  SYN_SENT: "bağlanıyor",
  BOUND: "bağlı (udp)",
  FIN_WAIT1: "kapanıyor",
  FIN_WAIT2: "kapanıyor",
  LAST_ACK: "kapanıyor",
};

function addr(a: string, port: number | null) {
  return a.includes(":") ? `[${a}]:${port ?? ""}` : `${a}:${port ?? ""}`;
}

function bindLabel(c: ConnectionInfo) {
  if (c.localAddr === "0.0.0.0" || c.localAddr === "::") return "tüm arabirimler";
  if (c.scope === "loopback") return "yalnızca bu bilgisayar";
  return c.localAddr;
}

function GeoNote({ status, onChange }: { status: GeoStatus | null; onChange: (s: GeoStatus) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!status) return null;
  if (status.countryDb && status.asnDb)
    return (
      <span className="nw-geo mono">
        ülke/ASN: DB-IP Lite {status.built} · db-ip.com (CC BY 4.0)
      </span>
    );
  return (
    <div className="nw-geo nw-geo--missing">
      <span>Ülke ve ASN bilgisi için çevrimdışı veritabanı gerekli (DB-IP Lite, ücretsiz, ~60 MB).</span>
      <button
        className="btn"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setErr(null);
          try {
            onChange(await api.downloadGeo());
          } catch (e) {
            setErr(String(e));
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "İndiriliyor…" : "Veritabanını indir"}
      </button>
      {err && <span className="nw-err">{err}</span>}
    </div>
  );
}

export default function NetworkWatch() {
  const connections = useGhost((s) => s.connections);
  const series = useGhost((s) => s.series);
  const metrics = useGhost((s) => s.metrics);
  const focusProcess = useGhost((s) => s.focusProcess);
  const [tab, setTab] = useState<Tab>("live");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [geo, setGeo] = useState<GeoStatus | null>(null);
  const [history, setHistory] = useState<ConnHistoryRow[]>([]);

  useEffect(() => {
    api.geoStatus().then(setGeo).catch(() => {});
  }, []);

  useEffect(() => {
    if (tab !== "history") return;
    const t = window.setTimeout(() => api.connHistory(q, 800).then(setHistory).catch(() => {}), 200);
    return () => window.clearTimeout(t);
  }, [tab, q]);

  const contacts = useMemo(() => contactsOf(connections), [connections]);
  const live = connections.filter((c) => c.remoteAddr && c.scope !== "loopback" && c.state === "ESTABLISHED");
  const listen = connections.filter((c) => c.protocol === "tcp" && c.state === "LISTEN");
  const countries = new Set(live.map((c) => c.country).filter(Boolean));

  const ql = q.trim().toLocaleLowerCase("tr-TR");
  const match = (c: ConnectionInfo) =>
    (!selected || c.remoteAddr === selected) &&
    (!ql ||
      [c.processName, c.remoteAddr, c.hostname, c.localAddr, String(c.localPort), String(c.remotePort ?? ""), c.country, c.asn]
        .filter(Boolean)
        .some((v) => String(v).toLocaleLowerCase("tr-TR").includes(ql)));

  const rows =
    tab === "live"
      ? live.filter(match).sort((a, b) => b.started - a.started)
      : tab === "listen"
        ? listen.filter(match).sort((a, b) => a.localPort - b.localPort)
        : connections
            .filter(match)
            .sort((a, b) => (a.processName ?? "").localeCompare(b.processName ?? "") || a.localPort - b.localPort);

  const traffic = useMemo<uPlot.AlignedData>(() => [series.t, series.rx, series.tx], [series]);

  return (
    <div className="nw">
      <section className="nw-left">
        <div className="nw-stats">
          <div>
            <b className="mono">{live.length}</b>
            <span>kurulu bağlantı</span>
          </div>
          <div>
            <b className="mono">{contacts.filter((c) => c.pub).length}</b>
            <span>internet sunucusu</span>
          </div>
          <div>
            <b className="mono">{listen.filter((l) => l.scope !== "loopback").length}</b>
            <span>dışa açık port</span>
          </div>
          <div>
            <b className="mono">{geo?.countryDb ? countries.size : "—"}</b>
            <span>ülke</span>
          </div>
        </div>
        <div className="nw-sonar">
          <Sonar contacts={contacts} selected={selected} onSelect={setSelected} />
          {selected && (
            <button className="nw-clear btn" onClick={() => setSelected(null)}>
              {selected} filtresini kaldır
            </button>
          )}
        </div>
        <div className="nw-traffic">
          <div className="nw-traffic__head mono">
            <span>
              <i className="rx" />↓ {metrics ? rate(metrics.netRxRate) : "—"}
            </span>
            <span>
              <i className="tx" />↑ {metrics ? rate(metrics.netTxRate) : "—"}
            </span>
            <em>tüm arabirimler, son 3 dk</em>
          </div>
          {series.t.length > 1 && (
            <Plot
              data={traffic}
              height={70}
              axes={false}
              scales={{ y: { range: (_u, _a, max) => [0, Math.max(65536, max * 1.2)] } }}
              series={[
                { scale: "y", stroke: "#22b8ff", width: 1.2, fill: "rgba(34,184,255,0.08)" },
                { scale: "y", stroke: "#3dff9a", width: 1 },
              ]}
            />
          )}
        </div>
        <GeoNote status={geo} onChange={setGeo} />
      </section>

      <section className="nw-right">
        <div className="nw-bar">
          <div className="seg">
            {TABS.map((t) => (
              <button key={t.id} className={tab === t.id ? "is-on" : ""} onClick={() => setTab(t.id)}>
                {t.label}
                {t.id !== "history" && (
                  <i className="mono">{t.id === "live" ? live.length : t.id === "listen" ? listen.length : connections.length}</i>
                )}
              </button>
            ))}
          </div>
          <input
            className="field"
            placeholder="işlem, IP, ana bilgisayar, port, ülke"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="nw-table-wrap">
          {tab === "history" ? (
            <table className="nw-table">
              <thead>
                <tr>
                  <th>Zaman</th>
                  <th>İşlem</th>
                  <th>Uzak adres</th>
                  <th>Port</th>
                  <th>Ülke / ASN</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i}>
                    <td className="mono dim">{stamp(h.ts)}</td>
                    <td>{h.process ?? `PID ${h.pid}`}</td>
                    <td>
                      <span className="mono">{h.remote}</span>
                      {h.hostname && <small>{h.hostname}</small>}
                    </td>
                    <td className="mono">{h.port}</td>
                    <td className="dim">{[h.country, h.asn].filter(Boolean).join(" · ") || "—"}</td>
                  </tr>
                ))}
                {history.length === 0 && (
                  <tr>
                    <td colSpan={5} className="nw-empty">
                      Geçmiş kaydı yok. Ghost Monitor internete açılan her yeni bağlantıyı buraya kaydeder.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          ) : tab === "listen" ? (
            <table className="nw-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Erişim</th>
                  <th>İşlem</th>
                  <th>Yerel adres</th>
                  <th>Açılış</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.id} className={c.scope !== "loopback" ? "is-exposed" : ""}>
                    <td className="mono">
                      <b>{c.localPort}</b> <span className="dim">{c.ipv6 ? "v6" : "v4"}</span>
                    </td>
                    <td>{bindLabel(c)}</td>
                    <td>
                      <button className="link" onClick={() => focusProcess(c.pid)}>
                        {c.processName ?? `PID ${c.pid}`}
                      </button>
                    </td>
                    <td className="mono dim">{c.localAddr}</td>
                    <td className="dim">{ago(c.started)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="nw-table">
              <thead>
                <tr>
                  <th>İşlem</th>
                  <th>Uzak adres</th>
                  <th>Port</th>
                  <th>Pr.</th>
                  <th>Durum</th>
                  <th>Ülke / ASN</th>
                  <th>Başlangıç</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 1500).map((c) => (
                  <tr key={c.id} className={c.risk && c.risk !== "INFO" ? `risk-${c.risk} is-risk` : ""}>
                    <td>
                      <button className="link" onClick={() => focusProcess(c.pid)}>
                        {c.processName ?? `PID ${c.pid}`}
                      </button>
                      {c.risk && c.risk !== "INFO" && <Sev level={c.risk} label={false} />}
                    </td>
                    <td>
                      {c.remoteAddr ? (
                        <>
                          <span className="mono">{c.remoteAddr}</span>
                          {c.hostname && <small>{c.hostname}</small>}
                        </>
                      ) : (
                        <span className="mono dim">{addr(c.localAddr, c.localPort)}</span>
                      )}
                    </td>
                    <td className="mono">{c.remotePort ?? c.localPort}</td>
                    <td className="mono dim">{c.protocol}</td>
                    <td className={`st st--${c.state}`}>{STATE_TR[c.state] ?? c.state.toLowerCase()}</td>
                    <td className="dim">
                      {c.scope === "public"
                        ? [c.country, c.asn].filter(Boolean).join(" · ") || (geo?.countryDb ? "bilinmiyor" : "—")
                        : c.scope === "private"
                          ? "yerel ağ"
                          : "—"}
                    </td>
                    <td className="mono dim" title={stamp(c.started)}>
                      {clock(c.started)}
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="nw-empty">
                      {q || selected ? "Filtreyle eşleşen soket yok." : "Şu an kurulu dış bağlantı yok."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}
