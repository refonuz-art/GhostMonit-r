import { useEffect, useMemo, useState } from "react";
import { Sev, SigMark } from "../../design/components";
import { ago, stamp } from "../../design/format";
import { Icon } from "../../design/icons";
import { api, on } from "../../ipc/api";
import { intel, type StartupItem } from "../../ipc/intel";
import type { SecurityEvent, Severity } from "../../ipc/types";
import { useGhost } from "../../state/store";
import "./startup.css";

type Kind = StartupItem["kind"];
const KIND_LABEL: Record<Kind, string> = {
  registry: "Kayıt defteri (Run)",
  winlogon: "Winlogon",
  folder: "Başlangıç klasörü",
  service: "Hizmetler",
  task: "Zamanlanmış görevler",
};
const KIND_HINT: Record<Kind, string> = {
  registry: "Oturum açılınca çalışan Run / RunOnce değerleri",
  winlogon: "Windows varsayılanından sapan Shell / Userinit",
  folder: "Başlat menüsü Başlangıç klasöründeki kısayollar",
  service: "Hizmet Denetimi Yöneticisi’ndeki Win32 hizmetleri",
  task: "Görev Zamanlayıcı’daki komut çalıştıran görevler",
};
const ORDER: Kind[] = ["registry", "winlogon", "folder", "task", "service"];
const SEV_RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

type Filter = "all" | "risky" | "unsigned" | "recent";

function isMicrosoft(i: StartupItem) {
  return (i.signature?.publisher ?? "").toLowerCase().startsWith("microsoft");
}

function Row({ it, open, onToggle }: { it: StartupItem; open: boolean; onToggle: () => void }) {
  const notify = useGhost((s) => s.notify);
  const findings = useGhost((s) => s.findings);
  const f = findings.find((x) => x.key === `startup:${it.id}`);
  return (
    <li className={`su-row${open ? " is-open" : ""}${it.enabled ? "" : " is-off"}${it.risk ? ` risk-${it.risk}` : ""}`}>
      <button className="su-row__main" onClick={onToggle}>
        <span className="su-row__risk">{it.risk ? <Sev level={it.risk} label={false} /> : null}</span>
        <span className="su-row__name">{it.name}</span>
        <span className="su-row__cmd mono">{it.command || "—"}</span>
        <span className="su-row__sig">
          {it.signature ? <SigMark sig={it.signature} /> : <span className="dim">{it.imageExists ? "—" : "dosya yok"}</span>}
        </span>
        <span className="su-row__state">
          {it.kind === "service" ? (
            <>
              <i className={it.state === "çalışıyor" ? "on" : ""} />
              {it.start}
            </>
          ) : it.enabled ? (
            <>
              <i className="on" />
              etkin
            </>
          ) : (
            <>
              <i />
              devre dışı
            </>
          )}
        </span>
      </button>
      {open && (
        <div className="su-detail">
          {f && (
            <div className="su-detail__finding">
              <b>{f.title}</b>
              <ul>
                {f.signals.map((s) => (
                  <li key={s.rule}>
                    <span className="mono">+{s.weight}</span> {s.label}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <dl className="facts">
            <dt>Komut</dt>
            <dd className="mono selectable">{it.command || "—"}</dd>
            <dt>Çözümlenen dosya</dt>
            <dd className="mono selectable">
              {it.image ?? "—"} {it.image && !it.imageExists && <span className="su-missing">diskte yok</span>}
            </dd>
            <dt>Konum</dt>
            <dd className="mono selectable">{it.location}</dd>
            {it.account && (
              <>
                <dt>Hesap</dt>
                <dd>{it.account}</dd>
              </>
            )}
            {it.author && (
              <>
                <dt>Yazar</dt>
                <dd>{it.author}</dd>
              </>
            )}
            <dt>İlk görülme</dt>
            <dd>{it.firstSeen ? stamp(it.firstSeen) : "—"}</dd>
          </dl>
          <div className="case-actions">
            {it.image && it.imageExists && (
              <button className="btn" onClick={() => api.reveal(it.image!).catch((e) => notify(String(e), "bad"))}>
                <Icon.folder /> Konumu aç
              </button>
            )}
            {it.risk && (
              <button
                className="btn btn--quiet"
                onClick={async () => {
                  await api.setTrust(`startup:${it.id}`, true);
                  notify("Girdi güvenilir olarak işaretlendi; sonraki taramada bulgu üretmeyecek");
                  intel.rescanStartup();
                }}
              >
                <Icon.trust /> Güvenilir say
              </button>
            )}
          </div>
          <p className="su-note">
            Ghost Monitor başlangıç girdilerini değiştirmez veya silmez. Kaldırmak için ilgili uygulamanın ayarlarını, Görev
            Zamanlayıcı’yı ya da Hizmetler konsolunu kullanın.
          </p>
        </div>
      )}
    </li>
  );
}

export default function StartupMonitor() {
  const [items, setItems] = useState<StartupItem[] | null>(null);
  const [scannedAt, setScannedAt] = useState<number | null>(null);
  const [changes, setChanges] = useState<SecurityEvent[]>([]);
  const [kind, setKind] = useState<Kind | "all">("all");
  const [filter, setFilter] = useState<Filter>("all");
  const [hideMs, setHideMs] = useState(true);
  const [q, setQ] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const loadChanges = () =>
    api
      .events({ kinds: ["startup.new", "startup.changed", "startup.removed"], limit: 200 })
      .then(setChanges)
      .catch(() => {});

  useEffect(() => {
    intel.startupItems().then((s) => {
      setItems(s.scannedAt ? s.items : null);
      setScannedAt(s.scannedAt);
    });
    loadChanges();
    const un = on<StartupItem[]>("startup", (list) => {
      setItems(list);
      setScannedAt(Date.now());
      setScanning(false);
      loadChanges();
    });
    return () => {
      un.then((u) => u());
    };
  }, []);

  const counts = useMemo(() => {
    const m = new Map<Kind, { n: number; risky: number }>();
    for (const i of items ?? []) {
      const c = m.get(i.kind) ?? { n: 0, risky: 0 };
      c.n++;
      if (i.risk && i.risk !== "INFO") c.risky++;
      m.set(i.kind, c);
    }
    return m;
  }, [items]);

  const shown = useMemo(() => {
    const needle = q.trim().toLocaleLowerCase("tr-TR");
    const weekAgo = Date.now() - 7 * 86_400_000;
    return (items ?? [])
      .filter((i) => kind === "all" || i.kind === kind)
      .filter((i) => !(hideMs && i.kind !== "registry" && i.kind !== "folder" && i.kind !== "winlogon" && isMicrosoft(i) && !i.risk))
      .filter((i) => {
        switch (filter) {
          case "risky":
            return !!i.risk;
          case "unsigned":
            return i.signature?.state === "unsigned" || i.signature?.state === "invalid";
          case "recent":
            return i.firstSeen > weekAgo;
          default:
            return true;
        }
      })
      .filter(
        (i) =>
          !needle ||
          i.name.toLocaleLowerCase("tr-TR").includes(needle) ||
          i.command.toLocaleLowerCase("tr-TR").includes(needle) ||
          (i.signature?.publisher ?? "").toLocaleLowerCase("tr-TR").includes(needle),
      )
      .sort(
        (a, b) =>
          (SEV_RANK[b.risk ?? "INFO"] - SEV_RANK[a.risk ?? "INFO"]) * 10 +
          (ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind)) ||
          a.name.localeCompare(b.name, "tr"),
      );
  }, [items, kind, filter, hideMs, q]);

  const grouped = useMemo(() => {
    const g = new Map<Kind, StartupItem[]>();
    for (const i of shown) g.set(i.kind, [...(g.get(i.kind) ?? []), i]);
    return ORDER.filter((k) => g.has(k)).map((k) => [k, g.get(k)!] as const);
  }, [shown]);

  const risky = (items ?? []).filter((i) => i.risk).length;

  return (
    <div className="su">
      <aside className="su-side">
        <div className="su-total">
          <b className="mono">{items ? items.length : "—"}</b>
          <span>otomatik başlatma noktası</span>
          <span className={risky ? "su-total__risk" : "dim"}>
            {items ? (risky ? `${risky} girdi şüpheli sinyal taşıyor` : "şüpheli sinyal yok") : "ilk tarama sürüyor…"}
          </span>
        </div>
        <nav className="su-kinds">
          <button className={kind === "all" ? "is-on" : ""} onClick={() => setKind("all")}>
            <span>Tüm kaynaklar</span>
            <span className="mono">{items?.length ?? 0}</span>
          </button>
          {ORDER.map((k) => {
            const c = counts.get(k);
            return (
              <button key={k} className={kind === k ? "is-on" : ""} onClick={() => setKind(k)} title={KIND_HINT[k]}>
                <span>{KIND_LABEL[k]}</span>
                <span className="mono">
                  {c?.risky ? <em>{c.risky}</em> : null}
                  {c?.n ?? 0}
                </span>
              </button>
            );
          })}
        </nav>
        <div className="su-scan">
          <span className="dim">{scannedAt ? `son tarama ${ago(scannedAt)}` : "taranıyor…"}</span>
          <button
            className="btn"
            disabled={scanning}
            onClick={() => {
              setScanning(true);
              intel.rescanStartup();
            }}
          >
            {scanning ? "Taranıyor…" : "Yeniden tara"}
          </button>
          <span className="su-scan__hint">Otomatik tarama her 10 dakikada bir çalışır.</span>
        </div>
      </aside>

      <section className="su-main">
        <div className="su-tools">
          <div className="seg">
            {(
              [
                ["all", "Tümü"],
                ["risky", "Şüpheli"],
                ["unsigned", "İmzasız"],
                ["recent", "Son 7 gün"],
              ] as const
            ).map(([k, l]) => (
              <button key={k} className={filter === k ? "is-on" : ""} onClick={() => setFilter(k)}>
                {l}
              </button>
            ))}
          </div>
          <input className="field" placeholder="Ad, komut veya yayıncı ara" value={q} onChange={(e) => setQ(e.target.value)} />
          <label className="su-check">
            <input type="checkbox" checked={hideMs} onChange={(e) => setHideMs(e.target.checked)} />
            Microsoft imzalı hizmet ve görevleri gizle
          </label>
        </div>

        {!items ? (
          <div className="empty">
            <strong>Başlangıç noktaları taranıyor</strong>
            <span>Kayıt defteri, Başlangıç klasörleri, hizmetler ve zamanlanmış görevler okunuyor; imzalar doğrulanıyor.</span>
          </div>
        ) : grouped.length === 0 ? (
          <div className="empty">
            <strong>Bu filtreyle eşleşen girdi yok</strong>
            <span>Filtreyi “Tümü” yapın veya Microsoft girdilerini gösterin.</span>
          </div>
        ) : (
          grouped.map(([k, list]) => (
            <section key={k} className="su-group">
              <h3>
                {KIND_LABEL[k]} <span className="mono dim">{list.length}</span>
              </h3>
              <ul className="su-list">
                {list.map((it) => (
                  <Row key={it.id} it={it} open={openId === it.id} onToggle={() => setOpenId(openId === it.id ? null : it.id)} />
                ))}
              </ul>
            </section>
          ))
        )}
      </section>

      <aside className="su-ledger">
        <h3>Değişiklik geçmişi</h3>
        {changes.length === 0 ? (
          <p className="dim">
            İlk taramadan bu yana eklenen, değişen veya kaldırılan girdi yok. İlk tarama temel durum olarak kaydedilir.
          </p>
        ) : (
          <ol>
            {changes.map((e) => (
              <li key={e.id} className={`su-ch su-ch--${e.kind.split(".")[1]}`}>
                <span className="su-ch__mark" />
                <div>
                  <b>{e.title}</b>
                  <span className="dim">{stamp(e.ts)}</span>
                  {e.detail && <code className="mono selectable">{e.detail}</code>}
                </div>
              </li>
            ))}
          </ol>
        )}
      </aside>
    </div>
  );
}
