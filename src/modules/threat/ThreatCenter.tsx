import { useEffect, useMemo, useState } from "react";
import { SEV_LABEL, Sev } from "../../design/components";
import { ago, basename, stamp } from "../../design/format";
import { Icon } from "../../design/icons";
import { api } from "../../ipc/api";
import { guard } from "../../ipc/guard";
import type { Finding, Severity } from "../../ipc/types";
import { SEVERITIES } from "../../ipc/types";
import { securityLevel } from "../../state/derive";
import { useGhost } from "../../state/store";
import { distinct, EvidenceBar } from "./EvidenceBar";
import { Explain } from "./Explain";
import "./threat.css";

type Tab = "active" | "history";

/** What the engine actually evaluates today — shown so users know the coverage. */
const RULES: { area: string; checks: string; live: boolean }[] = [
  { area: "Kimlik taklidi", checks: "Sistem dosyası adı yanlış konumda, sistem işlemine benzeyen adlar", live: true },
  { area: "İmza ve konum", checks: "Geçersiz imza, geçici/kullanıcı klasöründen imzasız çalıştırma", live: true },
  { area: "Soy anomalisi", checks: "Ofis/PDF uygulamasının betik yorumlayıcısı başlatması", live: true },
  { area: "PowerShell", checks: "Kodlanmış komut, gizli pencere, indirme, Invoke-Expression, AMSI atlatma", live: true },
  { area: "Sistem araçları", checks: "mshta, rundll32, regsvr32, certutil ile uzak içerik", live: true },
  { area: "Ağ", checks: "İmzasız işlemin internet bağlantısı, bilinen arka kapı portları", live: true },
  { area: "Portlar", checks: "Öğrenme süresinden sonra açılan yeni dış port", live: true },
  { area: "Kaynak", checks: "2 dakikadan uzun yüksek CPU", live: true },
  { area: "Zararlı hash", checks: "Çalışan dosyaların SHA-256’sı yerel hash veritabanında (içe aktarılmışsa)", live: true },
  {
    area: "Başlangıç kayıtları",
    checks: "Run/Winlogon/Başlangıç klasörü/görev/hizmet: aynı kurallar + Winlogon sapması, eksik hedef, yeni kayıt",
    live: true,
  },
  { area: "Dosya analizi", checks: "Çift uzantı, içerik-uzantı uyuşmazlığı, RTLO, internetten inen imzasız dosya", live: true },
  { area: "Dosya izleme", checks: "İndirilenler ve Masaüstü'ne gelen yeni program/betik/kısayol otomatik analiz edilir (Ayarlar'dan açılıp kapatılır)", live: true },
  { area: "Fidye yazılımı", checks: "Tuzak dosyalara dokunulması, belgelerin topluca yeniden adlandırılması veya yazılması", live: true },
  { area: "Koruma ayarları", checks: "Defender kapatılması, geniş dışlamalar, güvenlik duvarı, hosts/DNS/proxy yönlendirmesi", live: true },
  { area: "Tarayıcı uzantıları", checks: "Tüm sitelere erişim, çerez, hata ayıklayıcı, proxy izinleri; mağaza dışı kurulum", live: true },
  { area: "Olay günlüğü", checks: "Şifre deneme saldırısı, yeni hesap, yönetici grubu, günlük temizleme (Security günlüğü yönetici ister)", live: true },
  { area: "Yerel ağ", checks: "Modemin donanım adresinin değişmesi (ARP zehirleme), ağa yeni cihaz katılması", live: true },
  { area: "Sürücüler", checks: "Takılan USB, harici disk ve bağlanan ISO: autorun.inf, kökteki kısayol ve programlar", live: true },
];

function CaseRow({ f, active, onClick }: { f: Finding; active: boolean; onClick: () => void }) {
  return (
    <button className={`case${active ? " is-on" : ""} risk-${f.severity}`} onClick={onClick}>
      <Sev level={f.severity} label={false} />
      <span className="case__t">{f.title}</span>
      <span className="case__e mono">{basename(f.entity)}</span>
      <span className="case__m mono">
        {f.pids.length > 1 ? `${f.pids.length} işlem · ` : ""}
        {ago(f.firstSeen)}
      </span>
    </button>
  );
}

function CaseDetail({ f, live }: { f: Finding; live: boolean }) {
  const processes = useGhost((s) => s.processes);
  const focusProcess = useGhost((s) => s.focusProcess);
  const notify = useGhost((s) => s.notify);
  const procs = processes.filter((p) => f.pids.includes(p.pid));
  const sigs = distinct(f.signals);
  const path = f.entity.includes("\\") ? f.entity : null;
  const [qBusy, setQBusy] = useState(false);
  // Files (downloads, drive roots) and process images can be quarantined once nothing runs them.
  const canQuarantine = !!path && (f.entityKind === "file" || f.entityKind === "process") && procs.length === 0;

  return (
    <article className={`dossier-case risk-${f.severity}`}>
      <header>
        <Sev level={f.severity} />
        <h2>{f.title}</h2>
        <div className="mono dim selectable">{f.entity}</div>
      </header>

      <EvidenceBar signals={f.signals} />

      <section>
        <h3>Kanıtlar</h3>
        <ol className="evidence">
          {sigs.map((s) => (
            <li key={s.rule}>
              <b className="mono">+{s.weight}</b>
              <div>
                <span>{s.label}</span>
                <code className="mono selectable">{s.evidence}</code>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <Explain signals={f.signals} severity={f.severity} />

      <section>
        <h3>Etkilenen işlemler</h3>
        {live && procs.length > 0 ? (
          <ul className="affected">
            {procs.map((p) => (
              <li key={p.pid}>
                <button className="link" onClick={() => focusProcess(p.pid)}>
                  {p.name} <span className="mono dim">PID {p.pid}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="dim">Şu anda çalışan eşleşen işlem yok.</p>
        )}
      </section>

      <section className="case-times mono dim">
        ilk görülme {stamp(f.firstSeen)} · son görülme {stamp(f.lastSeen)} · durum {f.status}
      </section>

      <div className="case-actions">
        {live && procs[0] && (
          <button className="btn" onClick={() => focusProcess(procs[0].pid)}>
            <Icon.lineage /> İşlem dosyasını aç
          </button>
        )}
        {path && (
          <button className="btn" onClick={() => api.reveal(path).catch((e) => notify(String(e), "bad"))}>
            <Icon.folder /> Konumu aç
          </button>
        )}
        {f.entityKind === "ransomware" && procs.length > 0 && (
          <button
            className="btn btn--danger"
            onClick={async () => {
              for (const p of procs) {
                await guard.suspend(p.pid, true).then(
                  (m) => notify(m),
                  (e) => notify(String(e), "bad"),
                );
              }
            }}
          >
            Şüphelileri dondur
          </button>
        )}
        {canQuarantine && (
          <button
            className="btn"
            disabled={qBusy}
            title="Dosyayı yerinden kaldırıp şifreli olarak saklar; Sağlık → Karantina'dan geri yüklenebilir"
            onClick={async () => {
              setQBusy(true);
              await guard.quarantineAdd(path!, f.title).then(
                () => notify("Dosya karantinaya alındı"),
                (e) => notify(String(e), "bad"),
              );
              setQBusy(false);
            }}
          >
            {qBusy ? "Karantinaya alınıyor…" : "Karantinaya al"}
          </button>
        )}
        <button
          className="btn"
          onClick={async () => {
            await api.setTrust(f.key, true);
            notify("Güvenilir olarak işaretlendi; bu öğe artık değerlendirilmeyecek");
          }}
        >
          <Icon.trust /> Güvenilir işaretle
        </button>
        {f.status !== "dismissed" && (
          <button
            className="btn btn--quiet"
            onClick={async () => {
              await api.setFindingStatus(f.key, "dismissed");
              notify("Bulgu yok sayıldı");
            }}
          >
            <Icon.dismiss /> Yok say
          </button>
        )}
      </div>
    </article>
  );
}

export default function ThreatCenter() {
  const findings = useGhost((s) => s.findings);
  const [tab, setTab] = useState<Tab>("active");
  const [history, setHistory] = useState<Finding[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [minSev, setMinSev] = useState<Severity>("LOW");

  useEffect(() => {
    if (tab === "history") api.findingHistory(500).then(setHistory).catch(() => {});
  }, [tab]);

  const level = securityLevel(findings);
  const list = useMemo(() => {
    const src = tab === "active" ? findings : history;
    return src.filter((f) => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf(minSev));
  }, [tab, findings, history, minSev]);
  const current = list.find((f) => f.key === sel) ?? list[0] ?? null;

  const dist = SEVERITIES.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));
  const maxN = Math.max(1, ...dist.map((d) => d.n));

  return (
    <div className="tc">
      <section className="tc-head">
        <div className={`tc-level cc-level--${level.tone}`}>
          <span className="dim">genel durum</span>
          <b>{level.word}</b>
          <span>{level.note}</span>
        </div>
        <div className="tc-dist" aria-label="Seviye dağılımı">
          {dist.map(({ s, n }) => (
            <button key={s} className={`tc-dist__col risk-${s}${minSev === s ? " is-min" : ""}`} onClick={() => setMinSev(s)} title={`${SEV_LABEL[s]} ve üstünü göster`}>
              <i style={{ height: `${(n / maxN) * 100}%` }} />
              <b className="mono">{n}</b>
              <span>{SEV_LABEL[s]}</span>
            </button>
          ))}
        </div>
        <p className="tc-policy">
          Hiçbir kural tek başına “zararlı” kararı vermez. Her kural ağırlıklı bir sinyal üretir. Tek sinyal en fazla
          <em> orta</em> seviyeye çıkabilir; <em>kritik</em> için en az iki bağımsız sinyal ya da bilinen zararlı hash gerekir.
        </p>
      </section>

      <section className="tc-list">
        <div className="tc-bar">
          <div className="seg">
            <button className={tab === "active" ? "is-on" : ""} onClick={() => setTab("active")}>
              Etkin <i className="mono">{findings.length}</i>
            </button>
            <button className={tab === "history" ? "is-on" : ""} onClick={() => setTab("history")}>
              Geçmiş
            </button>
          </div>
          <span className="dim mono">{SEV_LABEL[minSev]}+</span>
        </div>
        <div className="tc-cases">
          {list.length === 0 && (
            <div className="empty">
              <strong>{tab === "active" ? "Etkin bulgu yok" : "Kayıtlı bulgu yok"}</strong>
              <span>Etkin kurallar şu an bu seviyede şüpheli davranış görmüyor.</span>
            </div>
          )}
          {list.map((f) => (
            <CaseRow key={f.key} f={f} active={current?.key === f.key} onClick={() => setSel(f.key)} />
          ))}
        </div>
      </section>

      <section className="tc-detail">
        {current ? (
          <CaseDetail key={current.key} f={current} live={tab === "active"} />
        ) : (
          <div className="tc-rules">
            <h3>Etkin algılama kuralları</h3>
            <table>
              <tbody>
                {RULES.map((r) => (
                  <tr key={r.area} className={r.live ? "" : "is-off"}>
                    <td>{r.area}</td>
                    <td>{r.checks}</td>
                    <td className="mono">{r.live ? "etkin" : "henüz yok"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
