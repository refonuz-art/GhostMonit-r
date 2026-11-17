import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Sev } from "../../design/components";
import { ago, bytes, rate, stamp } from "../../design/format";
import { api, on } from "../../ipc/api";
import {
  guard,
  type BlockRule,
  type CheckStatus,
  type GuardCheck,
  type GuardState,
  type HealthCheck,
  type NetUsage,
  type QItem,
} from "../../ipc/guard";
import { useGhost } from "../../state/store";
import "./health.css";

type Tab = "checks" | "defense" | "ext" | "net" | "block" | "quarantine";
const TABS: [Tab, string][] = [
  ["checks", "Kontrol listesi"],
  ["defense", "Koruma"],
  ["ext", "Tarayıcı uzantıları"],
  ["net", "Ağ"],
  ["block", "Engellenenler"],
  ["quarantine", "Karantina"],
];

const STATUS_TEXT: Record<CheckStatus, string> = { ok: "tamam", warn: "dikkat", bad: "sorun", unknown: "bilinmiyor" };

function useAsync() {
  const notify = useGhost((s) => s.notify);
  const [busy, setBusy] = useState<string | null>(null);
  const run = useCallback(
    async <T,>(id: string, fn: () => Promise<T>, ok?: (v: T) => string): Promise<T | undefined> => {
      setBusy(id);
      try {
        const v = await fn();
        if (ok) notify(ok(v));
        return v;
      } catch (e) {
        notify(String(e), "bad");
        return undefined;
      } finally {
        setBusy(null);
      }
    },
    [notify],
  );
  return { busy, run };
}

/** The score as a strip: every check is a segment as wide as the points it is worth. */
function Strip({ checks }: { checks: HealthCheck[] }) {
  const total = checks.reduce((a, c) => a + c.weight, 0) || 1;
  return (
    <div className="hl-strip" role="img" aria-label="Kontrollerin dağılımı">
      {checks.map((c) => (
        <i key={c.id} className={`is-${c.status}`} style={{ flexGrow: c.weight / total }} title={`${c.label}: ${STATUS_TEXT[c.status]}`} />
      ))}
    </div>
  );
}

function Checks({ g }: { g: GuardState }) {
  const h = g.health;
  if (!h) return <div className="empty"><strong>İlk kontroller sürüyor</strong><span>Birkaç dakika içinde burada sonuç görünecek.</span></div>;
  const order: CheckStatus[] = ["bad", "warn", "unknown", "ok"];
  const list = [...h.checks].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || b.weight - a.weight);
  return (
    <ul className="hl-checks">
      {list.map((c) => (
        <li key={c.id} className={`is-${c.status}`}>
          <span className="hl-checks__mark">{STATUS_TEXT[c.status]}</span>
          <div>
            <b>{c.label}</b>
            <span className="selectable">{c.detail}</span>
            {c.fix && c.status !== "ok" && <em>{c.fix}</em>}
          </div>
          <span className="hl-checks__pts mono">{c.status === "bad" ? `−${c.weight}` : c.status === "warn" ? `−${Math.floor(c.weight / 2)}` : ""}</span>
        </li>
      ))}
    </ul>
  );
}

function yes(v: boolean | null | undefined, on = "açık", off = "kapalı") {
  if (v === null || v === undefined) return <span className="dim">bilinmiyor</span>;
  return <span className={v ? "hl-on" : "hl-off"}>{v ? on : off}</span>;
}

function Defense({ g }: { g: GuardState }) {
  const d = g.defender;
  const host = useGhost((s) => s.host);
  return (
    <div className="hl-cols">
      <section>
        <h3>Microsoft Defender</h3>
        {!d ? (
          <p className="dim">İlk kontrol henüz tamamlanmadı.</p>
        ) : !d.defenderAvailable ? (
          <p className="dim">{d.error ?? "Defender sorgulanamadı (başka bir antivirüs kullanılıyor olabilir)."}</p>
        ) : (
          <dl className="facts">
            <dt>Gerçek zamanlı koruma</dt>
            <dd>{yes(d.realtime)}</dd>
            <dt>Davranış izleme</dt>
            <dd>{yes(d.behavior)}</dd>
            <dt>Kurcalama koruması</dt>
            <dd>{yes(d.tamper)}</dd>
            <dt>Virüs tanımları</dt>
            <dd>{d.signatureAgeDays === null ? "—" : d.signatureAgeDays === 0 ? "bugün güncellendi" : `${d.signatureAgeDays} gün önce`}</dd>
            <dt>Son hızlı tarama</dt>
            <dd>{d.quickScanAgeDays === null ? "—" : d.quickScanAgeDays === 0 ? "bugün" : `${d.quickScanAgeDays} gün önce`}</dd>
            <dt>Dışlamalar</dt>
            <dd>
              {d.exclusions === null ? (
                <span className="dim">yalnızca yönetici görebilir</span>
              ) : d.exclusions.length === 0 ? (
                "yok"
              ) : (
                <span className="selectable mono">{d.exclusions.join(", ")}</span>
              )}
            </dd>
          </dl>
        )}
        {d && d.products.length > 0 && (
          <>
            <h4>Kayıtlı antivirüs ürünleri</h4>
            <ul className="hl-plain">
              {d.products.map((p) => (
                <li key={p.name}>
                  {p.name} — {yes(p.enabled, "etkin", "devre dışı")}
                  {!p.upToDate && <span className="hl-off"> · tanımlar eski</span>}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
      <section>
        <h3>Güvenlik duvarı ve güncellemeler</h3>
        {d && d.firewall.length > 0 ? (
          <dl className="facts">
            {d.firewall.map((f) => (
              <span key={f.name} style={{ display: "contents" }}>
                <dt>{f.name} profil</dt>
                <dd>{yes(f.enabled)}</dd>
              </span>
            ))}
            <dt>Son Windows güncellemesi</dt>
            <dd>{d.lastUpdate ? `${d.lastUpdate} (${d.lastUpdateId})` : "—"}</dd>
          </dl>
        ) : (
          <p className="dim">Henüz okunmadı.</p>
        )}
        <h3>Fidye yazılımı kalkanı</h3>
        {g.canary.enabled ? (
          <>
            <p>
              <span className="hl-on">açık</span> — {g.canary.files.length} tuzak dosya, {g.canary.watchedFolders.length} klasör izleniyor.
            </p>
            {g.canary.tripped && (
              <p className="hl-off">
                Son alarm {ago(g.canary.tripped)}: {g.canary.lastAlert}
              </p>
            )}
          </>
        ) : (
          <p className="dim">Kapalı. Ayarlar → Koruma bölümünden açabilirsiniz.</p>
        )}
        <h3>Olay günlüğü</h3>
        {g.eventlog.channels.length === 0 ? (
          <p className="dim">Henüz okunmadı (Ayarlar'da kapalı olabilir).</p>
        ) : (
          <ul className="hl-plain">
            {g.eventlog.channels.map((c) => (
              <li key={c.name}>
                {c.label}: {c.readable ? <span className="hl-on">izleniyor</span> : c.needsAdmin ? <span className="hl-warn">yönetici gerekli</span> : <span className="dim">okunamıyor</span>}
              </li>
            ))}
          </ul>
        )}
        {!host?.elevated && g.eventlog.channels.some((c) => c.needsAdmin) && (
          <button className="btn" onClick={() => api.relaunchAdmin()}>
            Yönetici olarak yeniden başlat
          </button>
        )}
      </section>
    </div>
  );
}

function Extensions({ g }: { g: GuardState }) {
  const [open_, setOpen] = useState<string | null>(null);
  if (!g.extensionsScanned) return <div className="empty"><strong>Uzantılar henüz taranmadı</strong></div>;
  if (g.extensions.length === 0) return <div className="empty"><strong>Yüklü tarayıcı uzantısı bulunamadı</strong><span>Chrome, Edge, Brave, Opera, Vivaldi ve Firefox profillerine bakıldı.</span></div>;
  return (
    <ul className="hl-ext">
      {g.extensions.map((e) => (
        <li key={e.key} className={e.enabled ? "" : "is-off"}>
          <button className="hl-ext__main" onClick={() => setOpen(open_ === e.key ? null : e.key)}>
            <Sev level={e.severity} label={false} />
            <b>{e.name}</b>
            <span className="dim">
              {e.browser} · {e.profile}
              {e.version && ` · ${e.version}`}
            </span>
            <span className="hl-ext__state">{e.enabled ? (e.fromStore ? "mağazadan" : "mağaza dışı") : "devre dışı"}</span>
          </button>
          {open_ === e.key && (
            <div className="hl-ext__detail">
              {e.signals.length > 0 ? (
                <ul>
                  {e.signals.map((s) => (
                    <li key={s.rule}>
                      {s.label} <span className="mono dim">{s.evidence}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="dim">Belirgin riskli izin yok.</p>
              )}
              <p className="mono dim selectable">
                {e.id} · {e.permissions.length} izin
              </p>
              <p className="dim">Kaldırmak için tarayıcının uzantılar sayfasını açın. Ghost Monitor tarayıcı dosyalarını değiştirmez.</p>
              <button className="btn btn--quiet" onClick={() => api.reveal(e.path)}>
                Klasörü göster
              </button>
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

function Network({ g }: { g: GuardState }) {
  const { busy, run } = useAsync();
  const [usage, setUsage] = useState<NetUsage | null>(null);
  useEffect(() => {
    let live = true;
    const tick = () => guard.netUsage().then((u) => live && setUsage(u), () => {});
    tick();
    const t = window.setInterval(tick, 3000);
    return () => {
      live = false;
      window.clearInterval(t);
    };
  }, []);
  const n = g.netconf;
  return (
    <div className="hl-cols">
      <section>
        <div className="hl-head">
          <h3>Ev ağındaki cihazlar</h3>
          <button
            className="btn"
            disabled={busy === "sweep"}
            onClick={() => run("sweep", guard.lanSweep, (k) => `${k} adres yanıt verdi`)}
            title="Yerel ağdaki 254 adrese birer ARP isteği gönderir"
          >
            {busy === "sweep" ? "Taranıyor…" : "Ağı tara"}
          </button>
        </div>
        {g.lan.length === 0 ? (
          <p className="dim">Henüz cihaz görülmedi.</p>
        ) : (
          <table className="hl-table">
            <tbody>
              {g.lan.map((d) => (
                <tr key={d.mac} className={d.online ? "" : "is-off"}>
                  <td className="mono">{d.ip}</td>
                  <td className="mono dim">{d.mac}</td>
                  <td>{d.gateway ? "modem / yönlendirici" : d.vendor ?? <span className="dim">bilinmiyor</span>}</td>
                  <td className="dim">{d.online ? "çevrimiçi" : `son ${ago(d.lastSeen)}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <h3>İsim çözümleme ve proxy</h3>
        {n ? (
          <dl className="facts">
            <dt>DNS sunucuları</dt>
            <dd>
              {n.dns.map((d) => (
                <div key={d.adapter + d.server}>
                  <span className="mono">{d.server}</span> <span className="dim">({d.provider ?? "tanınmıyor"} · {d.adapter})</span>
                </div>
              ))}
            </dd>
            <dt>Proxy</dt>
            <dd>{n.proxy.enabled ? <span className="hl-warn mono">{n.proxy.server}</span> : "kullanılmıyor"}</dd>
            {n.proxy.pacUrl && (
              <>
                <dt>PAC betiği</dt>
                <dd className="mono hl-warn">{n.proxy.pacUrl}</dd>
              </>
            )}
            <dt>hosts dosyası</dt>
            <dd>
              {n.hosts.length} kayıt
              {n.hosts.filter((h) => h.risk).map((h) => (
                <div key={h.host} className="hl-off mono">
                  {h.host} → {h.ip} ({h.risk})
                </div>
              ))}
            </dd>
          </dl>
        ) : (
          <p className="dim">Henüz okunmadı.</p>
        )}
      </section>
      <section>
        <h3>Program başına veri kullanımı</h3>
        {!usage ? (
          <p className="dim">Ölçülüyor…</p>
        ) : !usage.available ? (
          <>
            <p className="dim">{usage.reason}</p>
            <button className="btn" onClick={() => api.relaunchAdmin()}>
              Yönetici olarak yeniden başlat
            </button>
          </>
        ) : (
          <>
            <p className="dim">
              Yalnızca TCP; {usage.since ? `${ago(usage.since)} başladı` : ""}. UDP (ör. QUIC, DNS) trafiği dahil değil.
            </p>
            <table className="hl-table">
              <thead>
                <tr>
                  <th>Program</th>
                  <th>İndirilen</th>
                  <th>Gönderilen</th>
                  <th>Şu an</th>
                </tr>
              </thead>
              <tbody>
                {usage.processes.map((p) => (
                  <tr key={p.pid}>
                    <td title={p.exe ?? ""}>
                      {p.name} <span className="dim mono">{p.pid}</span>
                    </td>
                    <td className="mono">{bytes(p.bytesIn)}</td>
                    <td className="mono">{bytes(p.bytesOut)}</td>
                    <td className="mono dim">
                      ↓{rate(p.rateIn)} ↑{rate(p.rateOut)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </div>
  );
}

function Blocks() {
  const { busy, run } = useAsync();
  const [rules, setRules] = useState<BlockRule[]>([]);
  const [ip, setIp] = useState("");
  const load = useCallback(() => guard.fwRules().then(setRules, () => {}), []);
  useEffect(() => {
    load();
  }, [load]);
  const pick = async () => {
    const f = await open({ title: "Engellenecek program", filters: [{ name: "Program", extensions: ["exe"] }] });
    if (typeof f === "string") await run("add", () => guard.block("program", f), (r) => `${r.target} engellendi`);
    load();
  };
  return (
    <div className="hl-block">
      <p className="dim">
        Windows Güvenlik Duvarı'na "Ghost Monitor - …" adlı engelleme kuralları eklenir. Her ekleme ve kaldırmada Windows sizden yönetici onayı ister. Yönetici olarak
        çalışmıyorsanız yalnızca giden bağlantılar engellenir.
      </p>
      <div className="hl-block__add">
        <button className="btn" disabled={busy !== null} onClick={pick}>
          Program seç ve engelle
        </button>
        <form
          className="st-key"
          onSubmit={async (e) => {
            e.preventDefault();
            const ok = await run("add", () => guard.block("ip", ip.trim()), (r) => `${r.target} engellendi`);
            if (ok) setIp("");
            load();
          }}
        >
          <input className="field mono" placeholder="IP adresi" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button className="btn" disabled={busy !== null || !ip.trim()}>
            IP'yi engelle
          </button>
        </form>
      </div>
      {rules.length === 0 ? (
        <p className="dim">Ghost Monitor ile eklenmiş engelleme kuralı yok.</p>
      ) : (
        <table className="hl-table">
          <tbody>
            {rules.map((r) => (
              <tr key={r.name}>
                <td>{r.kind === "ip" ? "IP" : "Program"}</td>
                <td className="mono selectable">{r.target}</td>
                <td className="dim">{stamp(r.created)}</td>
                <td>
                  <button
                    className="btn btn--quiet"
                    disabled={busy !== null}
                    onClick={async () => {
                      await run("del", () => guard.unblock(r.name), () => "Engelleme kaldırıldı");
                      load();
                    }}
                  >
                    Kaldır
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Quarantine() {
  const { busy, run } = useAsync();
  const [items, setItems] = useState<QItem[]>([]);
  const [confirm, setConfirm] = useState<number | null>(null);
  const load = useCallback(() => guard.quarantine().then(setItems, () => {}), []);
  useEffect(() => {
    load();
  }, [load]);
  const pick = async () => {
    const f = await open({ title: "Karantinaya alınacak dosya" });
    if (typeof f === "string") await run("add", () => guard.quarantineAdd(f, "Kullanıcı seçti"), () => "Dosya karantinaya alındı");
    load();
  };
  return (
    <div className="hl-block">
      <p className="dim">
        Karantinadaki dosya bulunduğu yerden kaldırılır ve şifrelenmiş olarak uygulama veri klasöründe saklanır; çalıştırılamaz ve açılamaz. İstediğiniz zaman
        aynı yere geri yükleyebilir veya kalıcı olarak silebilirsiniz.
      </p>
      <div className="hl-block__add">
        <button className="btn" disabled={busy !== null} onClick={pick}>
          Dosya seç ve karantinaya al
        </button>
      </div>
      {items.length === 0 ? (
        <p className="dim">Karantinada dosya yok.</p>
      ) : (
        <table className="hl-table">
          <tbody>
            {items.map((q) => (
              <tr key={q.id}>
                <td className="mono selectable" title={q.sha256}>
                  {q.original}
                  {q.reason && <div className="dim">{q.reason}</div>}
                </td>
                <td className="mono dim">{bytes(q.size)}</td>
                <td className="dim">{stamp(q.createdAt)}</td>
                <td className="hl-row-actions">
                  <button
                    className="btn btn--quiet"
                    disabled={busy !== null}
                    onClick={async () => {
                      await run("restore", () => guard.quarantineRestore(q.id), (p) => `Geri yüklendi: ${p}`);
                      load();
                    }}
                  >
                    Geri yükle
                  </button>
                  {confirm === q.id ? (
                    <button
                      className="btn btn--danger"
                      onClick={async () => {
                        setConfirm(null);
                        await run("del", () => guard.quarantineDelete(q.id), () => "Kalıcı olarak silindi");
                        load();
                      }}
                    >
                      Eminim, sil
                    </button>
                  ) : (
                    <button className="btn btn--quiet" onClick={() => setConfirm(q.id)}>
                      Sil
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const REFRESH_OF: Partial<Record<Tab, GuardCheck>> = { checks: "defender", defense: "defender", ext: "browser", net: "netconf" };

export default function Health() {
  const [g, setG] = useState<GuardState | null>(null);
  const [tab, setTab] = useState<Tab>(() => {
    const t = useGhost.getState().healthTab;
    useGhost.setState({ healthTab: null });
    return TABS.some(([id]) => id === t) ? (t as Tab) : "checks";
  });
  const { busy, run } = useAsync();
  useEffect(() => {
    guard.state().then(setG, () => {});
    const u = on<GuardState>("guard", setG);
    return () => {
      u.then((f) => f());
    };
  }, []);
  if (!g) return <div className="module-loading" />;
  const h = g.health;
  const refresh = REFRESH_OF[tab];
  const counts = { bad: 0, warn: 0, unknown: 0, ok: 0 } as Record<CheckStatus, number>;
  h?.checks.forEach((c) => counts[c.status]++);
  return (
    <div className="hl">
      <aside className="hl-side">
        <h2>Güvenlik sağlığı</h2>
        {h ? (
          <>
            <div className={`hl-score is-${h.score >= 90 ? "ok" : h.score >= 70 ? "warn" : "bad"}`}>
              <b>{h.score}</b>
              <span>/ 100 · {h.grade}</span>
            </div>
            <Strip checks={h.checks} />
            <dl className="facts">
              <dt>Sorun</dt>
              <dd className={counts.bad ? "hl-off" : ""}>{counts.bad}</dd>
              <dt>Dikkat</dt>
              <dd className={counts.warn ? "hl-warn" : ""}>{counts.warn}</dd>
              <dt>Ölçülemedi</dt>
              <dd>{counts.unknown}</dd>
              <dt>Tamam</dt>
              <dd>{counts.ok}</dd>
              <dt>Hesaplandı</dt>
              <dd>{ago(h.computed)}</dd>
            </dl>
            <p className="hl-side__note">Ölçülemeyen kontroller puanı düşürmez. Puan, kontrol listesindeki her maddenin ağırlığına göre hesaplanır.</p>
          </>
        ) : (
          <p className="dim">İlk kontroller sürüyor…</p>
        )}
        <nav className="hl-tabs">
          {TABS.map(([id, label]) => (
            <button key={id} className={tab === id ? "is-on" : ""} onClick={() => setTab(id)}>
              {label}
              {id === "ext" && g.extensions.length > 0 && <span className="dim">{g.extensions.length}</span>}
              {id === "net" && g.lan.length > 0 && <span className="dim">{g.lan.filter((d) => d.online).length}</span>}
            </button>
          ))}
        </nav>
      </aside>
      <div className="hl-main">
        {refresh && (
          <div className="hl-main__bar">
            <button className="btn btn--quiet" disabled={busy !== null} onClick={() => run("refresh", () => guard.refresh(refresh)).then((s) => s && setG(s))}>
              {busy === "refresh" ? "Kontrol ediliyor…" : "Şimdi yeniden kontrol et"}
            </button>
          </div>
        )}
        {tab === "checks" && <Checks g={g} />}
        {tab === "defense" && <Defense g={g} />}
        {tab === "ext" && <Extensions g={g} />}
        {tab === "net" && <Network g={g} />}
        {tab === "block" && <Blocks />}
        {tab === "quarantine" && <Quarantine />}
      </div>
    </div>
  );
}
