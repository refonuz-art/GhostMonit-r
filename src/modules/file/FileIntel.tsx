import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { Sev, SigMark } from "../../design/components";
import { basename, bytes, stamp } from "../../design/format";
import { Icon } from "../../design/icons";
import { api, on } from "../../ipc/api";
import type { SecurityEvent } from "../../ipc/types";
import { intel, type AutoScan, type DriveInfo, type FileReport, type HashDbStats, type Reputation } from "../../ipc/intel";
import { useGhost } from "../../state/store";
import { distinct, EvidenceBar } from "../threat/EvidenceBar";
import { Explain } from "../threat/Explain";
import "./file.css";

function Copy({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      className="fi-copy"
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setOk(true);
          window.setTimeout(() => setOk(false), 1200);
        });
      }}
    >
      {ok ? "kopyalandı" : "kopyala"}
    </button>
  );
}

function VerdictWord({ r }: { r: FileReport }) {
  if (r.knownBad) return <b className="fi-verdict is-bad">Bilinen zararlı</b>;
  switch (r.severity) {
    case "CRITICAL":
    case "HIGH":
      return <b className="fi-verdict is-bad">Yüksek risk</b>;
    case "MEDIUM":
      return <b className="fi-verdict is-warn">Şüpheli</b>;
    case "LOW":
      return <b className="fi-verdict is-low">Zayıf sinyaller</b>;
    default:
      return <b className="fi-verdict is-ok">Yerel analizde sorun yok</b>;
  }
}

function VirusTotalBox({ sha256 }: { sha256: string }) {
  const [hasKey, setHasKey] = useState<boolean | null>(null);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [rep, setRep] = useState<Reputation | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    intel.vtHasKey().then(setHasKey).catch(() => setHasKey(false));
  }, []);

  if (hasKey === null) return null;
  if (!hasKey)
    return (
      <div className="fi-vt">
        <p>
          İsteğe bağlı: VirusTotal API anahtarı eklerseniz yalnızca bu dosyanın <b>SHA-256</b> değeri sorgulanır; dosyanın
          kendisi gönderilmez. Anahtar Windows DPAPI ile şifrelenip saklanır.
        </p>
        <div className="fi-vt__row">
          <input
            className="field"
            type="password"
            placeholder="VirusTotal API anahtarı"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
          <button
            className="btn"
            disabled={!key.trim()}
            onClick={async () => {
              try {
                await intel.vtSetKey(key);
                setKey("");
                setHasKey(true);
                setErr(null);
              } catch (e) {
                setErr(String(e));
              }
            }}
          >
            Anahtarı kaydet
          </button>
        </div>
        {err && <p className="fi-err">{err}</p>}
      </div>
    );

  return (
    <div className="fi-vt">
      {!rep && (
        <div className="fi-vt__row">
          <button
            className="btn"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setErr(null);
              try {
                setRep(await intel.vtLookup(sha256));
              } catch (e) {
                setErr(String(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? "Sorgulanıyor…" : "VirusTotal’da hash’i sorgula"}
          </button>
          <button
            className="btn btn--quiet"
            onClick={async () => {
              await intel.vtSetKey(null);
              setHasKey(false);
            }}
          >
            Anahtarı sil
          </button>
        </div>
      )}
      {rep && !rep.found && <p>VirusTotal bu hash’i daha önce görmemiş. Bu tek başına iyi ya da kötü bir işaret değildir.</p>}
      {rep && rep.found && (
        <div className="fi-vt__res">
          <b className={`mono ${rep.malicious > 0 ? "is-bad" : "is-ok"}`}>
            {rep.malicious}/{rep.malicious + rep.suspicious + rep.harmless + rep.undetected}
          </b>
          <span>
            motor zararlı dedi{rep.suspicious ? `, ${rep.suspicious} şüpheli` : ""}
            {rep.label ? ` · ${rep.label}` : ""}
          </span>
          <span className="mono dim selectable">{rep.link}</span>
        </div>
      )}
      {err && <p className="fi-err">{err}</p>}
    </div>
  );
}

function Specimen({ r }: { r: FileReport }) {
  const notify = useGhost((s) => s.notify);
  const sigs = distinct(r.signals);
  return (
    <article className={`specimen risk-${r.severity}`}>
      <header className="specimen__head">
        <div>
          <h2 className="selectable">{r.name}</h2>
          <div className="mono dim selectable">{r.path}</div>
        </div>
        <div className="specimen__verdict">
          <VerdictWord r={r} />
          {r.signals.length > 0 && <Sev level={r.severity} />}
        </div>
      </header>

      {r.signals.length > 0 ? (
        <>
          <EvidenceBar signals={r.signals} />
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
          <Explain signals={r.signals} severity={r.severity} />
        </>
      ) : (
        <p className="specimen__clean">
          Yerel kurallar bu dosyada şüpheli bir işaret bulmadı. Bu, dosyanın kesinlikle güvenli olduğu anlamına gelmez;
          yalnızca bilinen kalıplarla eşleşmediğini gösterir.
        </p>
      )}

      <section className="specimen__grid">
        <div>
          <h3>Özellikler</h3>
          <dl className="facts">
            <dt>Tür (içerikten)</dt>
            <dd>{r.kind}</dd>
            {r.detail && (
              <>
                <dt>Ayrıntı</dt>
                <dd className="mono">{r.detail}</dd>
              </>
            )}
            <dt>Uzantı</dt>
            <dd className="mono">{r.extension ? `.${r.extension}` : "—"}</dd>
            <dt>Boyut</dt>
            <dd className="mono">
              {bytes(r.size)} <span className="dim">({r.size.toLocaleString("tr-TR")} bayt)</span>
            </dd>
            <dt>Oluşturulma</dt>
            <dd>{r.created ? stamp(r.created) : "—"}</dd>
            <dt>Değiştirilme</dt>
            <dd>{r.modified ? stamp(r.modified) : "—"}</dd>
            <dt>Dijital imza</dt>
            <dd>
              <SigMark sig={r.signature} />
            </dd>
          </dl>
        </div>
        <div>
          <h3>Köken</h3>
          {r.motw ? (
            <dl className="facts">
              <dt>Bölge</dt>
              <dd className={r.motw.zone >= 3 ? "fi-net" : ""}>{r.motw.zoneName}</dd>
              {r.motw.hostUrl && (
                <>
                  <dt>İndirildiği adres</dt>
                  <dd className="mono selectable">{r.motw.hostUrl}</dd>
                </>
              )}
              {r.motw.referrerUrl && (
                <>
                  <dt>Yönlendiren</dt>
                  <dd className="mono selectable">{r.motw.referrerUrl}</dd>
                </>
              )}
            </dl>
          ) : (
            <p className="dim">İndirme işareti (Zone.Identifier) yok — dosya yerelde oluşmuş ya da işaret silinmiş.</p>
          )}
          <h3>Zararlı hash veritabanı</h3>
          <p className={r.knownBad ? "fi-err" : "dim"}>{r.knownBad ? `Eşleşme: ${r.knownBad}` : "Eşleşme yok."}</p>
        </div>
      </section>

      <section>
        <h3>Hash değerleri</h3>
        <table className="fi-hashes mono selectable">
          <tbody>
            {(
              [
                ["SHA-256", r.sha256],
                ["SHA-1", r.sha1],
                ["MD5", r.md5],
              ] as const
            ).map(([k, v]) => (
              <tr key={k}>
                <td className="dim">{k}</td>
                <td>{v}</td>
                <td>
                  <Copy text={v} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h3>Çevrimiçi itibar</h3>
        <VirusTotalBox key={r.sha256} sha256={r.sha256} />
      </section>

      <div className="case-actions">
        <button className="btn" onClick={() => api.reveal(r.path).catch((e) => notify(String(e), "bad"))}>
          <Icon.folder /> Konumu aç
        </button>
      </div>
    </article>
  );
}

function HashDbPanel() {
  const [stats, setStats] = useState<HashDbStats | null>(null);
  const [busy, setBusy] = useState(false);
  const notify = useGhost((s) => s.notify);
  const load = () => intel.hashdbStats().then(setStats).catch(() => {});
  useEffect(() => {
    load();
  }, []);
  return (
    <section className="fi-db">
      <h3>Yerel zararlı hash veritabanı</h3>
      <div className="fi-db__n mono">{stats ? stats.total.toLocaleString("tr-TR") : "—"}</div>
      <p className="dim">
        kayıtlı SHA-256. Çalışan işlemler ve analiz edilen dosyalar bu listeyle karşılaştırılır; eşleşme tek başına
        <b> kritik</b> bulgu üretir.
      </p>
      {stats?.sources.map(([s, n]) => (
        <div key={s} className="fi-db__src mono">
          <span>{s}</span>
          <span>{n.toLocaleString("tr-TR")}</span>
        </div>
      ))}
      <div className="fi-db__actions">
        <button
          className="btn"
          disabled={busy}
          onClick={async () => {
            const path = await open({ multiple: false, filters: [{ name: "Hash listesi", extensions: ["txt", "csv"] }] });
            if (!path) return;
            setBusy(true);
            try {
              const r = await intel.hashdbImport(path);
              notify(`${r.added.toLocaleString("tr-TR")} yeni hash eklendi (${r.seen.toLocaleString("tr-TR")} okundu)`);
              load();
            } catch (e) {
              notify(String(e), "bad");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "İçe aktarılıyor…" : "Liste içe aktar (.txt/.csv)"}
        </button>
        {!!stats?.total && (
          <button
            className="btn btn--quiet"
            onClick={async () => {
              await intel.hashdbClear();
              load();
            }}
          >
            Temizle
          </button>
        )}
      </div>
      <p className="fi-db__hint">
        Her satırdaki 64 karakterlik onaltılık değerler SHA-256 olarak alınır. Örneğin abuse.ch MalwareBazaar dışa aktarımları
        doğrudan kullanılabilir.
      </p>
    </section>
  );
}

const WATCH_KINDS = new Set(["file.new", "usb.inserted", "usb.removed"]);

/** What the background watchers analysed on their own (Downloads, Desktop, new drives). */
function WatchPanel({ onOpen, current }: { onOpen: (r: FileReport) => void; current: string | null }) {
  const [scans, setScans] = useState<AutoScan[]>([]);
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  useEffect(() => {
    const load = () => {
      intel.autoScans().then(setScans, () => {});
      intel.drives().then(setDrives, () => {});
    };
    load();
    const un = on<SecurityEvent>("event", (e) => WATCH_KINDS.has(e.kind) && load());
    return () => {
      un.then((f) => f());
    };
  }, []);
  return (
    <>
      {drives.length > 0 && (
        <>
          <h3>Takılı sürücüler</h3>
          <ol className="fi-hist">
            {drives.map((d) => (
              <li key={d.letter} className="fi-drive">
                {d.severity !== "INFO" ? <Sev level={d.severity} label={false} /> : <span className="fi-okdot" />}
                <span>
                  {d.letter} {d.label}
                  <em>
                    {d.kind} · {d.rootExecutables.length ? `${d.rootExecutables.length} çalıştırılabilir` : "kökte program yok"}
                  </em>
                </span>
              </li>
            ))}
          </ol>
        </>
      )}
      <h3>Otomatik analizler</h3>
      {scans.length === 0 ? (
        <p className="fi-note">İndirilenler veya Masaüstü klasörüne yeni bir program, betik ya da kısayol geldiğinde burada görünür.</p>
      ) : (
        <ol className="fi-hist">
          {scans.map((s) => (
            <li key={s.report.path}>
              <button className={current === s.report.path ? "is-on" : ""} onClick={() => onOpen(s.report)}>
                {s.report.signals.length > 0 ? <Sev level={s.report.severity} label={false} /> : <span className="fi-okdot" />}
                <span>
                  {basename(s.report.path)}
                  <em>
                    {s.origin} · {new Date(s.ts).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" })}
                  </em>
                </span>
              </button>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}

export default function FileIntel() {
  const [history, setHistory] = useState<FileReport[]>([]);
  const [current, setCurrent] = useState<FileReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [hover, setHover] = useState(false);

  async function analyze(path: string) {
    setBusy(path);
    setErr(null);
    try {
      const r = await intel.analyzeFile(path);
      setCurrent(r);
      setHistory((h) => [r, ...h.filter((x) => x.path !== r.path)].slice(0, 30));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    let un: (() => void) | undefined;
    getCurrentWebview()
      .onDragDropEvent((e) => {
        if (e.payload.type === "over" || e.payload.type === "enter") setHover(true);
        else if (e.payload.type === "leave") setHover(false);
        else if (e.payload.type === "drop") {
          setHover(false);
          const p = e.payload.paths[0];
          if (p) analyze(p);
        }
      })
      .then((u) => (un = u));
    return () => un?.();
  }, []);

  async function pick() {
    const path = await open({ multiple: false, directory: false });
    if (path) analyze(path);
  }

  return (
    <div className={`fi${hover ? " is-drop" : ""}`}>
      <aside className="fi-side">
        <button className="fi-drop" onClick={pick}>
          <Icon.file width={28} height={28} />
          <b>Dosyayı buraya bırakın</b>
          <span>veya tıklayıp seçin</span>
        </button>
        {history.length > 0 && <h3>Bu oturumda incelenenler</h3>}
        <ol className="fi-hist">
          {history.map((h) => (
            <li key={h.path}>
              <button className={current?.path === h.path ? "is-on" : ""} onClick={() => setCurrent(h)}>
                {h.signals.length > 0 ? <Sev level={h.severity} label={false} /> : <span className="fi-okdot" />}
                <span>{basename(h.path)}</span>
              </button>
            </li>
          ))}
        </ol>
        <WatchPanel onOpen={setCurrent} current={current?.path ?? null} />
        <HashDbPanel />
      </aside>

      <section className="fi-main">
        {busy && (
          <div className="fi-busy mono">
            <i />
            hash hesaplanıyor ve imza doğrulanıyor — {basename(busy)}
          </div>
        )}
        {err && <div className="confirm confirm--critical">{err}</div>}
        {current ? (
          <Specimen key={current.path + current.sha256} r={current} />
        ) : (
          !busy && (
            <div className="empty fi-empty">
              <strong>İncelenecek bir dosya seçin</strong>
              <span>
                SHA-256/SHA-1/MD5, gerçek dosya türü, dijital imza, internetten indirilme kökeni ve gizlenmiş uzantılar yerel
                olarak denetlenir. Hiçbir veri dışarı gönderilmez.
              </span>
            </div>
          )
        )}
      </section>
      {hover && <div className="fi-overlay">Bırakın — analiz başlayacak</div>}
    </div>
  );
}
