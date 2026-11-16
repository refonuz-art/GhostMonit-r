import { save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { SEV_COLOR, SEV_LABEL, Sev } from "../../design/components";
import { stamp } from "../../design/format";
import { Icon } from "../../design/icons";
import { api } from "../../ipc/api";
import { intel, type ReportData } from "../../ipc/intel";
import { SEVERITIES, type Severity } from "../../ipc/types";
import { useGhost } from "../../state/store";
import "./report.css";

type Kind = "daily" | "weekly";

const KIND_LABEL: Record<string, string> = {
  "process.start": "işlem başlatma",
  "process.exit": "işlem sonlanma",
  "network.new_remote": "yeni uzak adres",
  "threat.finding": "tehdit bulgusu",
  "startup.new": "yeni açılış girdisi",
  "startup.changed": "değişen açılış girdisi",
  "startup.removed": "kaldırılan açılış girdisi",
  "user.kill": "kullanıcı: işlem sonlandırma",
  "user.trust": "kullanıcı: güven",
  "user.hashdb": "kullanıcı: hash veritabanı",
  "file.new": "yeni indirilen dosya",
  "usb.inserted": "takılan sürücü",
  "usb.removed": "çıkarılan sürücü",
  "intel.feed": "liste güncellemesi",
  "report.auto": "otomatik rapor",
};

function fileStamp(ms: number) {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function Days({ r }: { r: ReportData }) {
  const max = Math.max(1, ...r.days.map((d) => d.events));
  return (
    <div className="rp-days">
      {r.days.map((d) => (
        <div key={d.day} className="rp-day" title={`${d.events} olay · ${d.threats} tehdit · ${d.newRemotes} yeni uzak adres`}>
          <div className="rp-day__bar">
            <i style={{ height: `${(d.events / max) * 100}%` }} />
            {d.threats > 0 && <b style={{ height: `${Math.max(4, (d.threats / max) * 100)}%` }} />}
          </div>
          <span className="mono">{d.day.slice(5).replace("-", ".")}</span>
        </div>
      ))}
    </div>
  );
}

function Preview({ r }: { r: ReportData }) {
  const threats = r.findings.filter((f) => f.severity !== "INFO");
  const sevCounts = SEVERITIES.slice(1)
    .reverse()
    .map((s) => [s, r.bySeverity.find(([k]) => k === s)?.[1] ?? 0] as [Severity, number]);
  return (
    <article className="rp-doc">
      <header className="rp-doc__head">
        <div>
          <h1>{r.title}</h1>
          <p className="dim">
            {r.host.hostname} — {stamp(r.since)} ile {stamp(r.until)} arası
          </p>
        </div>
        <div className={`rp-verdict ${r.topSeverity ? `risk-${r.topSeverity}` : "is-clean"}`}>
          <b>{r.topSeverity ? SEV_LABEL[r.topSeverity] : "temiz"}</b>
          <span>en yüksek bulgu seviyesi</span>
        </div>
      </header>

      <div className="rp-figures">
        <div>
          <b className="mono">{r.totalEvents.toLocaleString("tr-TR")}</b>
          <span>kayıtlı olay</span>
        </div>
        <div>
          <b className="mono">{threats.length}</b>
          <span>şüpheli bulgu</span>
        </div>
        <div>
          <b className="mono">{r.newRemoteHosts}</b>
          <span>ilk kez görülen uzak adres</span>
        </div>
        <div>
          <b className="mono">{r.openPorts.length}</b>
          <span>ağa açık port (şu an)</span>
        </div>
      </div>

      {r.days.length > 1 && (
        <section>
          <h2>Günlere göre olaylar</h2>
          <Days r={r} />
        </section>
      )}

      <section>
        <h2>Şüpheli bulgular</h2>
        {threats.length === 0 ? (
          <p className="dim">Bu dönemde bulgu yok.</p>
        ) : (
          <table className="rp-table">
            <tbody>
              {threats.slice(0, 40).map((f) => (
                <tr key={f.key}>
                  <td>
                    <Sev level={f.severity} />
                  </td>
                  <td>
                    <b>{f.title}</b>
                    <div className="mono dim">{f.entity}</div>
                  </td>
                  <td className="mono r">{f.score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="rp-sevs">
          {sevCounts.map(([s, n]) => (
            <span key={s} style={{ color: n ? SEV_COLOR[s] : undefined }} className={n ? "" : "dim"}>
              {n} {SEV_LABEL[s]} olay
            </span>
          ))}
        </div>
      </section>

      <div className="rp-two">
        <section>
          <h2>En çok bağlanılan uzak adresler</h2>
          {r.topRemotes.length === 0 ? (
            <p className="dim">Kayıtlı internet bağlantısı yok.</p>
          ) : (
            <table className="rp-table">
              <tbody>
                {r.topRemotes.slice(0, 12).map((x) => (
                  <tr key={x.remote}>
                    <td className="mono">{x.remote}</td>
                    <td>
                      {x.hostname ?? <span className="dim">—</span>}
                      <div className="dim">{[x.country, x.asn].filter(Boolean).join(" · ")}</div>
                    </td>
                    <td className="mono r">{x.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
        <section>
          <h2>Ağa açık portlar</h2>
          {r.openPorts.length === 0 ? (
            <p className="dim">Ağa açık dinleyen port yok.</p>
          ) : (
            <table className="rp-table">
              <tbody>
                {r.openPorts.map((p) => (
                  <tr key={`${p.protocol}${p.port}`}>
                    <td className="mono">{p.port}</td>
                    <td className="mono dim">{p.bind}</td>
                    <td>{p.process}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      <div className="rp-two">
        <section>
          <h2>Başlangıç değişiklikleri</h2>
          {r.startupEvents.length === 0 ? (
            <p className="dim">Değişiklik yok.</p>
          ) : (
            <ul className="rp-list">
              {r.startupEvents.slice(0, 20).map((e) => (
                <li key={e.id}>
                  <span className="dim mono">{stamp(e.ts)}</span> {e.title}
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h2>Olay türleri</h2>
          <ul className="rp-list">
            {r.byKind.map(([k, n]) => (
              <li key={k}>
                <span className="mono">{n.toLocaleString("tr-TR")}</span> {KIND_LABEL[k] ?? k}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section>
        <h2>En sık başlatılan işlemler</h2>
        <p className="rp-procs">
          {r.topProcesses.length ? r.topProcesses.map(([n, c]) => `${n} (${c})`).join(", ") : <span className="dim">Kayıt yok.</span>}
        </p>
      </section>

      <footer className="rp-foot dim">
        {r.host.osName} {r.host.osVersion} · Ghost Monitor {r.host.appVersion} · oluşturuldu {stamp(r.generatedAt)}. Bu rapor
        yalnızca yerel veritabanındaki kayıtlardan üretilir; kayıtlar 30 gün saklanır.
      </footer>
    </article>
  );
}

export default function Reports() {
  const notify = useGhost((s) => s.notify);
  const [kind, setKind] = useState<Kind>("daily");
  const [data, setData] = useState<ReportData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"pdf" | "json" | null>(null);
  const [last, setLast] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    setErr(null);
    intel.buildReport(kind).then(setData).catch((e) => setErr(String(e)));
  }, [kind]);

  async function exportAs(format: "pdf" | "json") {
    if (!data) return;
    const path = await save({
      defaultPath: `ghost-monitor-${kind === "weekly" ? "haftalik" : "gunluk"}-${fileStamp(data.until)}.${format}`,
      filters: [{ name: format.toUpperCase(), extensions: [format] }],
    });
    if (!path) return;
    setBusy(format);
    try {
      const p = await intel.exportReport(kind, format, path, data.since, data.until);
      setLast(p);
      notify(`Rapor kaydedildi: ${p}`);
    } catch (e) {
      notify(String(e), "bad");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="rp">
      <aside className="rp-side">
        <h3>Dönem</h3>
        <div className="rp-kinds">
          <button className={kind === "daily" ? "is-on" : ""} onClick={() => setKind("daily")}>
            <b>Günlük</b>
            <span>son 24 saat</span>
          </button>
          <button className={kind === "weekly" ? "is-on" : ""} onClick={() => setKind("weekly")}>
            <b>Haftalık</b>
            <span>son 7 gün, günlere bölünmüş</span>
          </button>
        </div>
        <h3>Dışa aktar</h3>
        <button className="btn" disabled={!data || !!busy} onClick={() => exportAs("pdf")}>
          <Icon.report /> {busy === "pdf" ? "PDF hazırlanıyor…" : "PDF olarak kaydet"}
        </button>
        <button className="btn" disabled={!data || !!busy} onClick={() => exportAs("json")}>
          {busy === "json" ? "Yazılıyor…" : "JSON olarak kaydet"}
        </button>
        <p className="rp-hint">
          JSON dosyası tüm ham alanları içerir; başka araçlara aktarmak için uygundur. PDF yazdırılabilir özet sürümüdür.
        </p>
        {last && (
          <button className="btn btn--quiet" onClick={() => api.reveal(last)}>
            <Icon.folder /> Son raporu klasörde göster
          </button>
        )}
      </aside>
      <section className="rp-main">
        {err && <div className="confirm confirm--critical">{err}</div>}
        {!data && !err && <div className="rp-loading mono">rapor derleniyor…</div>}
        {data && <Preview r={data} />}
      </section>
    </div>
  );
}
