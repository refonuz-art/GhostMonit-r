import { useCallback, useEffect, useState } from "react";
import { ago, basename, stamp } from "../../design/format";
import { api } from "../../ipc/api";
import { guard } from "../../ipc/guard";
import type { Finding } from "../../ipc/types";
import { v5, type IncidentContext } from "../../ipc/v5";
import { useGhost } from "../../state/store";
import { talkThrough } from "../../assistant/agent";
import { useAyla } from "../../assistant/store";

type StepState = "done" | "todo" | "na";

function Step({ n, title, state, children }: { n: number; title: string; state: StepState; children: React.ReactNode }) {
  return (
    <li className={`ir-step is-${state}`}>
      <span className="ir-step__n mono">{state === "done" ? "✓" : n}</span>
      <div className="ir-step__body">
        <h4>
          {title}
          <em>{state === "done" ? "yapıldı" : state === "na" ? "gerekmiyor" : "bekliyor"}</em>
        </h4>
        {children}
      </div>
    </li>
  );
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One-screen response plan for a finding: contain → cut network → persistence → remove → trace. */
export function Incident({ f, live }: { f: Finding; live: boolean }) {
  const notify = useGhost((s) => s.notify);
  const setModule = useGhost((s) => s.setModule);
  const [ctx, setCtx] = useState<IncidentContext | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [frozen, setFrozen] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const [armed, setArmed] = useState(false);

  const load = useCallback(() => v5.incident(f.key).then(setCtx, (e) => setErr(String(e))), [f.key]);
  useEffect(() => {
    load();
  }, [load]);

  if (err) return <p className="dim">Müdahale bilgisi alınamadı: {err}</p>;
  if (!ctx) return <p className="dim">Müdahale planı hazırlanıyor…</p>;

  const running = live ? ctx.running : [];
  const freezable = running.filter((p) => !p.critical);
  const allFrozen = freezable.length > 0 && freezable.every((p) => frozen.has(p.pid));
  const canBlock = !!ctx.path && ctx.fileExists && /\.(exe|com|scr)$/i.test(ctx.path);
  const anyCritical = running.some((p) => p.critical);

  const run = async (id: string, fn: () => Promise<void>) => {
    setBusy(id);
    try {
      await fn();
    } catch (e) {
      notify(String(e), "bad");
    } finally {
      setBusy(null);
      load();
    }
  };

  const freeze = async (suspend: boolean) => {
    const next = new Set(frozen);
    for (const p of freezable) {
      try {
        notify(await guard.suspend(p.pid, suspend));
        if (suspend) next.add(p.pid);
        else next.delete(p.pid);
      } catch (e) {
        notify(String(e), "bad");
      }
    }
    setFrozen(next);
  };

  const block = async () => {
    const r = await guard.block("program", ctx.path!);
    notify(`${basename(r.target)} internete çıkamaz`);
  };

  const contain = () =>
    run("contain", async () => {
      if (freezable.length && !allFrozen) await freeze(true);
      if (canBlock && !ctx.blockedBy) await block();
    });

  const removeAll = () =>
    run("remove", async () => {
      setArmed(false);
      for (const p of running) {
        const r = await api.killProcess(p.pid, false);
        if (!r.ok) throw new Error(r.message);
      }
      if (running.length) await wait(800);
      await guard.quarantineAdd(ctx.path!, f.title);
      notify("İşlem kapatıldı, dosya karantinaya alındı");
    });

  const steps = {
    freeze: (running.length === 0 ? "na" : allFrozen ? "done" : "todo") as StepState,
    block: (!canBlock ? "na" : ctx.blockedBy ? "done" : "todo") as StepState,
    persist: (ctx.startup.length ? "todo" : "na") as StepState,
    remove: (ctx.quarantined ? "done" : !ctx.path || !ctx.fileExists ? "na" : "todo") as StepState,
  };
  const quickPossible = (steps.freeze === "todo" && freezable.length > 0) || steps.block === "todo";
  const self = ctx.lineage[0];
  const parents = ctx.lineage.slice(1);

  return (
    <section className="ir">
      <header className="ir-head">
        <h3>Müdahale</h3>
        {useAyla.getState().enabled && (
          <button className="btn btn--quiet" onClick={() => void talkThrough(f)} title="Ayla bulguyu sesli anlatır ve adımları onayınızla uygular">
            Ayla ile ilerle
          </button>
        )}
        {quickPossible && (
          <button className="btn btn--danger" disabled={busy !== null} onClick={contain} title="İşlemi dondurur ve internetini keser. İkisi de geri alınabilir.">
            {busy === "contain" ? "Sınırlandırılıyor…" : "Hızlı sınırla"}
          </button>
        )}
      </header>
      <p className="ir-lede">
        Önce yayılmasını durdurun, sonra kalıcı izlerini bulun, en son dosyayı kaldırın. Dondurma ve engelleme geri alınabilir; karantinadaki dosya Sağlık → Karantina'dan geri yüklenir.
      </p>

      <ol className="ir-steps">
        <Step n={1} title="Dondur" state={steps.freeze}>
          {running.length === 0 ? (
            <p>Şu anda çalışan eşleşen işlem yok.</p>
          ) : (
            <>
              <p>
                {running.map((p) => `${p.name} (${p.pid})`).join(", ")}
                {anyCritical && " — kritik sistem işlemleri dondurulmaz."}
              </p>
              {freezable.length > 0 && (
                <button className="btn" disabled={busy !== null} onClick={() => run("freeze", () => freeze(!allFrozen))}>
                  {allFrozen ? "Devam ettir" : `${freezable.length} işlemi dondur`}
                </button>
              )}
            </>
          )}
        </Step>

        <Step n={2} title="İnternetini kes" state={steps.block}>
          {!canBlock ? (
            <p>Engellenecek bir program dosyası yok.</p>
          ) : ctx.blockedBy ? (
            <>
              <p>Güvenlik duvarı kuralı etkin: {ctx.blockedBy}</p>
              <button className="btn btn--quiet" disabled={busy !== null} onClick={() => run("unblock", () => guard.unblock(ctx.blockedBy!))}>
                Engeli kaldır
              </button>
            </>
          ) : (
            <>
              <p>Windows Güvenlik Duvarı bu programın bağlantılarını keser. Yönetici onayı istenebilir.</p>
              <button className="btn" disabled={busy !== null} onClick={() => run("block", block)}>
                Güvenlik duvarında engelle
              </button>
            </>
          )}
        </Step>

        <Step n={3} title="Kalıcılığı kontrol et" state={steps.persist}>
          {ctx.startup.length === 0 ? (
            <p>Açılışta bu dosyayı başlatan bir kayıt bulunamadı.</p>
          ) : (
            <>
              <p>Bu dosya Windows açılışında şu kayıtlarla başlıyor. Ghost Monitor kayıtları değiştirmez; programı kaldırın ya da kaydı kendiniz silin.</p>
              <ul className="ir-list">
                {ctx.startup.map((s) => (
                  <li key={s.id}>
                    <b>{s.name}</b> <span className="dim">{s.kind} · {s.location}</span>
                    <code className="mono selectable">{s.command}</code>
                  </li>
                ))}
              </ul>
              <button className="btn btn--quiet" onClick={() => setModule("startup")}>
                Açılış ekranında aç
              </button>
            </>
          )}
        </Step>

        <Step n={4} title="Kapat ve karantinaya al" state={steps.remove}>
          {ctx.quarantined ? (
            <p>Dosya karantinada.</p>
          ) : !ctx.path || !ctx.fileExists ? (
            <p>Diskte kaldırılacak dosya yok.</p>
          ) : anyCritical ? (
            <p>Kritik bir sistem işlemi bu dosyayı çalıştırıyor; kapatılamaz.</p>
          ) : (
            <>
              <p className="mono selectable">{ctx.path}</p>
              {armed ? (
                <div className="ir-confirm">
                  <span>
                    {running.length ? `${running.length} işlem sonlandırılacak ve ` : ""}dosya yerinden kaldırılacak. Emin misiniz?
                  </span>
                  <button className="btn btn--danger" disabled={busy !== null} onClick={removeAll}>
                    {busy === "remove" ? "Uygulanıyor…" : "Evet, kaldır"}
                  </button>
                  <button className="btn btn--quiet" onClick={() => setArmed(false)}>
                    Vazgeç
                  </button>
                </div>
              ) : (
                <button className="btn" disabled={busy !== null} onClick={() => setArmed(true)}>
                  {running.length ? "Kapat ve karantinaya al" : "Karantinaya al"}
                </button>
              )}
            </>
          )}
        </Step>

        <Step n={5} title="İzleri incele" state="todo">
          <div className="ir-trace">
            <div>
              <h5>Kim başlattı</h5>
              {self ? (
                <ol className="ir-lineage">
                  {[...parents].reverse().map((p) => (
                    <li key={p.id} title={p.cmd ?? p.exe ?? ""}>
                      <b>{p.name}</b> <span className="mono dim">{p.pid}</span>
                    </li>
                  ))}
                  <li className="is-self" title={self.cmd ?? ""}>
                    <b>{self.name}</b> <span className="mono dim">{self.pid} · {stamp(self.started)}</span>
                  </li>
                </ol>
              ) : (
                <p className="dim">Süreç geçmişinde kayıt yok.</p>
              )}
              {ctx.runs > 0 && (
                <p className="dim">
                  {ctx.runs} kez çalıştı{ctx.firstRun ? ` · ilk ${stamp(ctx.firstRun)}` : ""}
                </p>
              )}
            </div>
            <div>
              <h5>Bağlandığı adresler (7 gün)</h5>
              {ctx.remotes.length === 0 ? (
                <p className="dim">Kayıtlı internet bağlantısı yok.</p>
              ) : (
                <ul className="ir-list ir-list--tight">
                  {ctx.remotes.map((r) => (
                    <li key={r.remote}>
                      <span className="mono">{r.remote}:{r.port}</span>
                      <span className="dim"> {[r.hostname, r.country].filter(Boolean).join(" · ")} · {ago(r.last)}</span>
                      <button
                        className="link"
                        onClick={() =>
                          guard.block("ip", r.remote).then(
                            () => notify(`${r.remote} engellendi`),
                            (e) => notify(String(e), "bad"),
                          )
                        }
                      >
                        engelle
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h5>Sorguladığı alan adları (7 gün)</h5>
              {ctx.dns.length === 0 ? (
                <p className="dim">Kayıtlı DNS sorgusu yok.</p>
              ) : (
                <ul className="ir-list ir-list--tight">
                  {ctx.dns.map((d) => (
                    <li key={d.name}>
                      <span className="mono">{d.name}</span>
                      <span className="dim"> ×{d.count} · {ago(d.last)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </Step>
      </ol>
    </section>
  );
}
