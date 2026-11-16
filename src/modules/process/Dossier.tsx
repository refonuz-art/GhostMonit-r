import { useState } from "react";
import { Sev, SigMark } from "../../design/components";
import { ago, bytes, stamp } from "../../design/format";
import { Icon } from "../../design/icons";
import { api } from "../../ipc/api";
import { guard } from "../../ipc/guard";
import type { ProcessInfo } from "../../ipc/types";
import { useGhost } from "../../state/store";
import { EvidenceBar } from "../threat/EvidenceBar";

type KillStage = "idle" | "confirm" | "critical" | "busy";

export function Dossier({ pid, proc, onClose }: { pid: number; proc: ProcessInfo | null; onClose: () => void }) {
  const processes = useGhost((s) => s.processes);
  const connections = useGhost((s) => s.connections);
  const findings = useGhost((s) => s.findings);
  const focusProcess = useGhost((s) => s.focusProcess);
  const notify = useGhost((s) => s.notify);
  const elevated = useGhost((s) => s.host?.elevated ?? false);
  const [stage, setStage] = useState<KillStage>("idle");
  const [killMsg, setKillMsg] = useState<string | null>(null);
  const [frozen, setFrozen] = useState(false);
  const [blocking, setBlocking] = useState(false);

  if (!proc) {
    return (
      <aside className="dossier">
        <div className="dossier__top">
          <h2>PID {pid}</h2>
          <button className="btn btn--quiet" onClick={onClose} aria-label="Kapat">
            <Icon.close />
          </button>
        </div>
        <div className="empty">
          <strong>İşlem artık çalışmıyor</strong>
          <span>Bu PID sonlanmış. Geçmiş olayları Zaman Çizelgesi’nde bulabilirsiniz.</span>
        </div>
      </aside>
    );
  }

  const p = proc;
  const byPid = new Map(processes.map((x) => [x.pid, x]));
  const chain: ProcessInfo[] = [];
  let cur = p.ppid != null ? byPid.get(p.ppid) : undefined;
  let child = p;
  while (cur && chain.length < 12 && cur.startTime <= child.startTime && cur.pid !== child.pid) {
    chain.unshift(cur);
    child = cur;
    cur = cur.ppid != null ? byPid.get(cur.ppid) : undefined;
  }
  const children = processes.filter((x) => x.ppid === p.pid && x.startTime >= p.startTime && x.pid !== p.pid);
  const conns = connections.filter((c) => c.pid === p.pid);
  const finding = findings.find((f) => f.pids.includes(p.pid));

  async function kill(confirmed: boolean) {
    setStage("busy");
    const r = await api.killProcess(p.pid, confirmed);
    if (r.ok) {
      notify(r.message, "ok");
      setStage("idle");
    } else if (r.needs === "confirm") {
      setKillMsg(r.message);
      setStage("critical");
    } else {
      setKillMsg(r.message);
      setStage("idle");
      notify(r.message, "bad");
    }
  }

  return (
    <aside className="dossier">
      <div className="dossier__top">
        <div>
          <h2 className="selectable">{p.name}</h2>
          <span className="mono dim">PID {p.pid}</span>
        </div>
        {p.risk && p.risk !== "INFO" && <Sev level={p.risk} />}
        <button className="btn btn--quiet" onClick={onClose} aria-label="Kapat">
          <Icon.close />
        </button>
      </div>

      <div className="dossier__body">
        {p.exe && <div className="dossier__path mono selectable">{p.exe}</div>}

        <div className="dossier__actions">
          {p.exe && (
            <button className="btn" onClick={() => api.reveal(p.exe!).catch((e) => notify(String(e), "bad"))}>
              <Icon.folder /> Konumu aç
            </button>
          )}
          {finding && (
            <button
              className="btn"
              onClick={async () => {
                await api.setTrust(finding.key, true);
                notify(`${p.name} güvenilir olarak işaretlendi`);
              }}
            >
              <Icon.trust /> Güvenilir işaretle
            </button>
          )}
          {p.pid > 4 && !p.critical && (
            <button
              className="btn"
              title="İşlemi kapatmadan durdurur; fidye yazılımına karşı ilk müdahale"
              onClick={() =>
                guard.suspend(p.pid, !frozen).then(
                  (m) => {
                    setFrozen(!frozen);
                    notify(m);
                  },
                  (e) => notify(String(e), "bad"),
                )
              }
            >
              {frozen ? "Devam ettir" : "Dondur"}
            </button>
          )}
          {p.exe && p.pid > 4 && (
            <button
              className="btn"
              disabled={blocking}
              title="Windows Güvenlik Duvarı'nda bu programın internet erişimini engeller (yönetici onayı istenir)"
              onClick={() => {
                setBlocking(true);
                guard
                  .block("program", p.exe!)
                  .then((r) => notify(`${r.target} internete çıkamaz`), (e) => notify(String(e), "bad"))
                  .finally(() => setBlocking(false));
              }}
            >
              {blocking ? "Engelleniyor…" : "İnterneti engelle"}
            </button>
          )}
          {stage === "idle" && (
            <button className="btn btn--danger" onClick={() => setStage("confirm")} disabled={p.pid <= 4}>
              <Icon.kill /> Sonlandır
            </button>
          )}
        </div>

        {stage === "confirm" && (
          <div className="confirm">
            <p>
              <b>{p.name}</b> sonlandırılacak. Kaydedilmemiş veriler kaybolabilir.
            </p>
            <div>
              <button className="btn btn--danger" onClick={() => kill(false)}>
                Sonlandır
              </button>
              <button className="btn btn--quiet" onClick={() => setStage("idle")}>
                Vazgeç
              </button>
            </div>
          </div>
        )}
        {stage === "critical" && (
          <div className="confirm confirm--critical">
            <p>{killMsg}</p>
            <p>Windows çökebilir veya oturum kapanabilir. Yalnızca ne yaptığınızdan eminseniz devam edin.</p>
            <div>
              <button className="btn btn--danger" onClick={() => kill(true)}>
                Kritik işlemi yine de sonlandır
              </button>
              <button className="btn btn--quiet" onClick={() => setStage("idle")}>
                Vazgeç
              </button>
            </div>
          </div>
        )}
        {stage === "busy" && <div className="confirm">Sonlandırılıyor…</div>}
        {stage === "idle" && killMsg && (
          <div className="confirm confirm--note">
            {killMsg}
            {!elevated && killMsg.includes("yönetici") && (
              <button className="btn" onClick={() => api.relaunchAdmin().catch(() => {})}>
                Yönetici olarak yeniden başlat
              </button>
            )}
          </div>
        )}

        {finding && (
          <section className="dsec">
            <h3>Neden işaretlendi</h3>
            <EvidenceBar signals={finding.signals} />
            <ul className="dsignals">
              {finding.signals.map((s, i) => (
                <li key={i}>
                  <span>{s.label}</span>
                  <em className="mono">+{s.weight}</em>
                  <code className="mono selectable">{s.evidence}</code>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="dsec">
          <h3>Kimlik</h3>
          <dl className="facts">
            <dt>Dijital imza</dt>
            <dd>
              <SigMark sig={p.signature} showPublisher={false} />
            </dd>
            <dt>Yayıncı</dt>
            <dd>{p.signature.publisher ?? <span className="dim">—</span>}</dd>
            <dt>Kullanıcı</dt>
            <dd className="mono">{p.user ?? <span className="dim">okunamadı</span>}</dd>
            <dt>Başlangıç</dt>
            <dd>
              {p.startTime ? (
                <>
                  {stamp(p.startTime * 1000)} <span className="dim">({ago(p.startTime * 1000)})</span>
                </>
              ) : (
                "—"
              )}
            </dd>
            <dt>CPU / bellek</dt>
            <dd className="mono">
              {p.cpu.toFixed(1)}% · {bytes(p.memory)}
            </dd>
          </dl>
        </section>

        {p.cmd && (
          <section className="dsec">
            <h3>Komut satırı</h3>
            <pre className="cmdline mono selectable">{p.cmd}</pre>
          </section>
        )}

        <section className="dsec">
          <h3>Soy zinciri</h3>
          <ol className="lineage">
            {chain.length === 0 && p.ppid != null && (
              <li className="dim">Ebeveyn PID {p.ppid} artık çalışmıyor</li>
            )}
            {chain.map((a) => (
              <li key={a.pid}>
                <button onClick={() => focusProcess(a.pid)}>
                  {a.name} <span className="mono dim">{a.pid}</span>
                </button>
              </li>
            ))}
            <li className="is-self">
              {p.name} <span className="mono dim">{p.pid}</span>
            </li>
            {children.map((c) => (
              <li key={c.pid} className="is-child">
                <button onClick={() => focusProcess(c.pid)}>
                  {c.name} <span className="mono dim">{c.pid}</span>
                </button>
              </li>
            ))}
          </ol>
        </section>

        <section className="dsec">
          <h3>Ağ bağlantıları ({conns.length})</h3>
          {conns.length === 0 ? (
            <p className="dim">Bu işlemin açık soketi yok.</p>
          ) : (
            <table className="mini mono">
              <tbody>
                {conns.slice(0, 40).map((c) => (
                  <tr key={c.id}>
                    <td>{c.protocol}</td>
                    <td>
                      {c.localPort}
                    </td>
                    <td>{c.remoteAddr ? `${c.remoteAddr}:${c.remotePort}` : "—"}</td>
                    <td className="dim">{c.state.toLowerCase()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </aside>
  );
}
