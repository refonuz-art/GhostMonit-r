import { useEffect, useMemo, useState } from "react";
import { SigMark } from "../../design/components";
import { duration, stamp } from "../../design/format";
import { v5, type ProcRun } from "../../ipc/v5";
import { buildTree } from "./tree";

const MIN = 60_000;
const HOUR = 60 * MIN;
const RANGES: [string, number][] = [
  ["1 saat", HOUR],
  ["24 saat", 24 * HOUR],
  ["7 gün", 7 * 24 * HOUR],
];
const STEPS: [string, number][] = [
  ["−1 sa", -HOUR],
  ["−10 dk", -10 * MIN],
  ["−1 dk", -MIN],
  ["+1 dk", MIN],
  ["+10 dk", 10 * MIN],
  ["+1 sa", HOUR],
];
/** Starts/exits this close to the chosen moment are highlighted and listed. */
const NEAR = 15 * MIN;

type Node = ProcRun & { startTime: number };

function toLocalInput(ms: number) {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * MIN);
  return d.toISOString().slice(0, 16);
}

function hm(ms: number) {
  return new Date(ms).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function life(r: ProcRun, at: number) {
  const end = r.ended ?? at;
  return duration(Math.max(0, Math.round((end - r.started) / 1000)));
}

function RunDetail({ r }: { r: ProcRun }) {
  const [lineage, setLineage] = useState<ProcRun[] | null>(null);
  useEffect(() => {
    setLineage(null);
    v5.procLineage(r.pid, r.started).then(setLineage, () => setLineage([]));
  }, [r.pid, r.started]);
  return (
    <div className="tm-detail">
      <h3>
        {r.name} <span className="mono dim">PID {r.pid}</span>
      </h3>
      <dl className="facts">
        <dt>Dosya</dt>
        <dd className="mono selectable">{r.exe ?? "okunamadı"}</dd>
        <dt>Komut</dt>
        <dd className="mono selectable">{r.cmd ?? "—"}</dd>
        <dt>Kullanıcı</dt>
        <dd>{r.user ?? "—"}</dd>
        <dt>İmza</dt>
        <dd>
          <SigMark sig={{ state: r.sigState, publisher: r.publisher }} />
        </dd>
        <dt>Başladı</dt>
        <dd className="mono">{stamp(r.started)}</dd>
        <dt>Bitti</dt>
        <dd className="mono">
          {r.ended ? (r.endedApprox ? `${stamp(r.ended)} veya önce (Ghost Monitor kapalıydı)` : stamp(r.ended)) : "hâlâ çalışıyor"}
        </dd>
      </dl>
      <h4>Kim başlattı</h4>
      {lineage === null ? (
        <p className="dim">…</p>
      ) : lineage.length === 0 ? (
        <p className="dim">Üst işlem geçmişte kayıtlı değil.</p>
      ) : (
        <ol className="tm-lineage">
          {[...lineage].reverse().map((p) => (
            <li key={p.id} title={p.cmd ?? p.exe ?? ""}>
              {p.name} <span className="mono dim">{p.pid}</span>
            </li>
          ))}
          <li className="is-self">{r.name}</li>
        </ol>
      )}
    </div>
  );
}

export function TimeMachine() {
  const [now] = useState(() => Date.now());
  const [range, setRange] = useState(24 * HOUR);
  const [ts, setTs] = useState(() => Date.now() - MIN);
  const [runs, setRuns] = useState<ProcRun[] | null>(null);
  const [earliest, setEarliest] = useState<number | null>(null);
  const [near, setNear] = useState<ProcRun[]>([]);
  const [sel, setSel] = useState<ProcRun | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    const t = window.setTimeout(() => {
      v5.procAt(ts).then((r) => {
        setRuns(r.runs);
        setEarliest(r.earliest);
      }, () => setRuns([]));
      v5.procChanges(ts - NEAR, ts + NEAR, 400).then(setNear, () => setNear([]));
    }, 120);
    return () => window.clearTimeout(t);
  }, [ts]);

  const min = Math.max(now - range, earliest ?? now - range);
  const rows = useMemo(() => {
    const nodes: Node[] = (runs ?? []).map((r) => ({ ...r, startTime: r.started }));
    const s = q.trim().toLocaleLowerCase("tr-TR");
    if (s) {
      return nodes
        .filter((n) => n.name.toLocaleLowerCase("tr-TR").includes(s) || (n.exe ?? "").toLocaleLowerCase("tr-TR").includes(s) || String(n.pid) === s)
        .map((p) => ({ p, depth: 0, rails: [], last: true, hasKids: false }));
    }
    return buildTree(nodes);
  }, [runs, q]);

  const events = useMemo(
    () =>
      near
        .flatMap((r) => {
          const out: { at: number; kind: "start" | "stop"; r: ProcRun }[] = [];
          if (Math.abs(r.started - ts) <= NEAR) out.push({ at: r.started, kind: "start", r });
          if (r.ended && !r.endedApprox && Math.abs(r.ended - ts) <= NEAR) out.push({ at: r.ended, kind: "stop", r });
          return out;
        })
        .sort((a, b) => b.at - a.at),
    [near, ts],
  );

  const clamp = (v: number) => Math.min(Date.now(), Math.max(earliest ?? 0, v));
  const noHistory = earliest === null && runs !== null;

  return (
    <div className="tm">
      <div className="tm-bar">
        <div className="tm-when">
          <b className="mono">{stamp(ts)}</b>
          <span className="dim">{runs ? `${runs.length} işlem çalışıyordu` : "yükleniyor…"}</span>
        </div>
        <input
          type="range"
          className="tm-slider"
          min={min}
          max={now}
          step={MIN / 2}
          value={Math.max(min, ts)}
          onChange={(e) => setTs(Number(e.target.value))}
          aria-label="Zaman"
        />
        <div className="tm-controls">
          <div className="seg">
            {RANGES.map(([l, v]) => (
              <button key={l} className={range === v ? "is-on" : ""} onClick={() => setRange(v)}>
                {l}
              </button>
            ))}
          </div>
          <div className="seg">
            {STEPS.map(([l, d]) => (
              <button key={l} onClick={() => setTs((t) => clamp(t + d))}>
                {l}
              </button>
            ))}
          </div>
          <input
            type="datetime-local"
            className="field tm-date"
            value={toLocalInput(ts)}
            onChange={(e) => {
              const v = new Date(e.target.value).getTime();
              if (!Number.isNaN(v)) setTs(clamp(v));
            }}
          />
          <button className="btn btn--quiet" onClick={() => setTs(Date.now())}>
            Şimdi
          </button>
          <input className="field tm-q" placeholder="ad, PID veya yol" value={q} onChange={(e) => setQ(e.target.value)} spellCheck={false} />
        </div>
        {earliest && (
          <p className="tm-note dim">
            Kayıt {stamp(earliest)} itibarıyla başladı. Ghost Monitor kapalıyken başlayıp biten işlemler görünmez.
          </p>
        )}
      </div>

      <div className="tm-body">
        <div className="tm-main">
          <div className="tm-grid tm-head">
            <span>İşlem</span>
            <span className="c-num">PID</span>
            <span>İmza</span>
            <span className="c-num">Başladı</span>
            <span className="c-num">Ömür</span>
          </div>
          <div className="tm-scroll">
            {noHistory && (
              <div className="empty">
                <strong>Henüz geçmiş yok</strong>
                <span>Ghost Monitor bu sürümden itibaren her işlemin başlangıcını ve bitişini kaydeder.</span>
              </div>
            )}
            {rows.map(({ p, depth, rails, last }) => {
              const fresh = Math.abs(p.started - ts) <= NEAR;
              const ending = p.ended != null && !p.endedApprox && p.ended - ts <= NEAR;
              return (
                <div
                  key={p.id}
                  className={`tm-grid tm-row${sel?.id === p.id ? " is-focus" : ""}${fresh ? " is-fresh" : ""}${ending ? " is-ending" : ""}`}
                  onClick={() => setSel(sel?.id === p.id ? null : p)}
                >
                  <span className="c-name">
                    {rails.map((on, i) => (
                      <i key={i} className={`rail${on ? " on" : ""}`} />
                    ))}
                    {depth > 0 && <i className={`elbow${last ? " last" : ""}`} />}
                    <b title={p.exe ?? p.name}>{p.name}</b>
                  </span>
                  <span className="c-num mono">{p.pid}</span>
                  <span>
                    <SigMark sig={{ state: p.sigState, publisher: p.publisher }} />
                  </span>
                  <span className="c-num mono dim">{hm(p.started)}</span>
                  <span className="c-num mono dim">{life(p, ts)}</span>
                </div>
              );
            })}
          </div>
        </div>

        <aside className="tm-side">
          {sel ? (
            <>
              <button className="btn btn--quiet tm-back" onClick={() => setSel(null)}>
                ← Yakın olaylar
              </button>
              <RunDetail r={sel} />
            </>
          ) : (
            <>
              <h3>±15 dakika içinde</h3>
              {events.length === 0 && <p className="dim">Bu ana yakın başlayan ya da kapanan işlem yok.</p>}
              <ol className="tm-events">
                {events.map((e, i) => (
                  <li key={i} className={`is-${e.kind}`}>
                    <button
                      onClick={() => {
                        setTs(e.kind === "start" ? e.at + 1000 : e.at - 1000);
                        setSel(e.r);
                      }}
                    >
                      <span className="mono dim">{hm(e.at)}</span>
                      <em>{e.kind === "start" ? "başladı" : "kapandı"}</em>
                      <b>{e.r.name}</b>
                    </button>
                  </li>
                ))}
              </ol>
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
