import { useMemo, useState } from "react";
import type uPlot from "uplot";
import { Meter, Plot, Sev } from "../../design/components";
import { bytes, clock, duration, pct, rate } from "../../design/format";
import { activeRemote, openPorts, securityLevel, topSeverity } from "../../state/derive";
import { useGhost } from "../../state/store";
import { GhostCore, type CoreAnchor } from "../../viz/GhostCore";
import "./command.css";

const TONE_COLOR = {
  phosphor: "#3dff9a",
  arc: "#22b8ff",
  warn: "#ffb547",
  high: "#ff7a3d",
  bad: "#ff3d4e",
} as const;

const KIND_GLYPH: Record<string, string> = {
  "process.start": "◇",
  "process.kill": "✕",
  "network.new_remote": "◈",
  "threat.finding": "◆",
  "user.trust": "✓",
  "file.new": "▤",
  "usb.inserted": "⊟",
  "usb.removed": "⊟",
};

function SystemColumn() {
  const m = useGhost((s) => s.metrics);
  const host = useGhost((s) => s.host);
  if (!m || !host) return <aside className="cc-sys" />;
  const memP = (m.memUsed / Math.max(1, m.memTotal)) * 100;
  return (
    <aside className="cc-sys">
      <div className="cc-host">
        <b>{host.hostname}</b>
        <span>{host.osName}</span>
        <span className="mono">açık kalma {duration(m.uptime)}</span>
      </div>

      <section className="cc-gauge">
        <header>
          <span>İşlemci</span>
          <span className="mono dim">{host.cpuCount} çekirdek</span>
        </header>
        <div className="cc-big mono">{m.cpu.toFixed(0)}<small>%</small></div>
        <div className="cc-cores" title="Çekirdek başına kullanım">
          {m.cpuCores.map((c, i) => (
            <i key={i} style={{ height: `${Math.max(4, c)}%` }} className={c > 85 ? "hot" : ""} />
          ))}
        </div>
      </section>

      <section className="cc-gauge">
        <header>
          <span>Bellek</span>
          <span className="mono dim">
            {bytes(m.memUsed)} / {bytes(m.memTotal)}
          </span>
        </header>
        <div className="cc-mid mono">{pct(memP)}</div>
        <Meter value={memP} tone={memP > 90 ? "bad" : memP > 75 ? "warn" : "phosphor"} />
      </section>

      <section className="cc-gauge">
        <header>
          <span>Diskler</span>
        </header>
        {m.disks.map((d) => {
          const used = d.total - d.available;
          const p = (used / Math.max(1, d.total)) * 100;
          return (
            <div key={d.mount} className="cc-disk">
              <div>
                <span className="mono">{d.mount}</span>
                <span className="mono dim">
                  {bytes(d.available)} boş
                </span>
              </div>
              <Meter value={p} tone={p > 92 ? "bad" : p > 80 ? "warn" : "arc"} />
            </div>
          );
        })}
      </section>

      <section className="cc-gauge">
        <header>
          <span>Ağ trafiği</span>
        </header>
        <div className="cc-net mono">
          <span>
            <i>↓</i>
            {rate(m.netRxRate)}
          </span>
          <span>
            <i>↑</i>
            {rate(m.netTxRate)}
          </span>
        </div>
      </section>
    </aside>
  );
}

function EventFeed() {
  const all = useGhost((s) => s.liveEvents);
  const setModule = useGhost((s) => s.setModule);
  const [routine, setRoutine] = useState(false);
  const events = routine ? all : all.filter((e) => e.kind !== "process.start");
  const hidden = all.length - events.length;
  return (
    <aside className="cc-feed">
      <header>
        <span>Son güvenlik olayları</span>
        <button className="btn btn--quiet" onClick={() => setModule("timeline")}>
          Zaman çizelgesi
        </button>
      </header>
      <label className="cc-feed__toggle">
        <input type="checkbox" checked={routine} onChange={(e) => setRoutine(e.target.checked)} />
        İşlem başlangıçlarını göster {!routine && hidden > 0 && <span className="mono">({hidden} gizli)</span>}
      </label>
      <ol className="cc-feed__list mono">
        {events.length === 0 && <li className="cc-feed__empty">Henüz olay kaydı yok. İzleme sürdükçe burada görünecek.</li>}
        {events.slice(0, 60).map((e) => (
          <li key={e.id} className={`sevline sevline--${e.severity}`} title={e.detail}>
            <time>{clock(e.ts)}</time>
            <i>{KIND_GLYPH[e.kind] ?? "·"}</i>
            <span>{e.title}</span>
          </li>
        ))}
      </ol>
    </aside>
  );
}

function ActivityStrip() {
  const series = useGhost((s) => s.series);
  const data = useMemo<uPlot.AlignedData>(() => [series.t, series.cpu, series.mem, series.rx, series.tx], [series]);
  return (
    <section className="cc-activity">
      <header>
        <span>Canlı aktivite</span>
        <span className="cc-legend mono">
          <i style={{ background: "#3dff9a" }} />cpu
          <i style={{ background: "#7a8894" }} />ram
          <i style={{ background: "#22b8ff" }} />↓ ağ
          <i style={{ background: "#145f86" }} />↑ ağ
        </span>
      </header>
      {series.t.length > 1 ? (
        <Plot
          data={data}
          height={150}
          scales={{ y: { range: [0, 100] }, y2: { range: (_u, _min, max) => [0, Math.max(1024 * 64, max * 1.15)] } }}
          yFormat={(v) => `${v}%`}
          y2Format={(v) => rate(v)}
          series={[
            { scale: "y", stroke: "#3dff9a", width: 1.5, fill: "rgba(61,255,154,0.06)" },
            { scale: "y", stroke: "#7a8894", width: 1 },
            { scale: "y2", stroke: "#22b8ff", width: 1 },
            { scale: "y2", stroke: "#145f86", width: 1, dash: [3, 3] },
          ]}
        />
      ) : (
        <div className="cc-activity__wait mono">örnek toplanıyor…</div>
      )}
    </section>
  );
}

export default function CommandCenter() {
  const findings = useGhost((s) => s.findings);
  const processes = useGhost((s) => s.processes);
  const connections = useGhost((s) => s.connections);
  const focusProcess = useGhost((s) => s.focusProcess);
  const setModule = useGhost((s) => s.setModule);
  const [anchors, setAnchors] = useState<Record<string, CoreAnchor> | null>(null);
  const [R, setR] = useState(0);

  const level = securityLevel(findings);
  const suspicious = findings.filter((f) => f.severity !== "INFO");
  const pidsFlagged = suspicious.reduce((n, f) => n + f.pids.length, 0);
  const remote = activeRemote(connections);
  const publicCount = remote.filter((c) => c.scope === "public").length;
  const ports = openPorts(connections);
  const exposed = ports.filter((p) => p.scope !== "loopback").length;
  const unsigned = processes.filter((p) => p.signature.state === "unsigned" || p.signature.state === "invalid").length;

  const readouts = anchors && [
    {
      at: anchors.proc,
      value: processes.length,
      label: "aktif işlem",
      sub: unsigned ? `${unsigned} imzasız` : "hepsi imzalı",
      go: () => setModule("process"),
    },
    {
      at: anchors.conn,
      value: remote.length,
      label: "aktif bağlantı",
      sub: `${publicCount} internet`,
      go: () => setModule("network"),
    },
    {
      at: anchors.port,
      value: ports.length,
      label: "açık port",
      sub: `${exposed} dışa açık`,
      go: () => setModule("network"),
    },
    {
      at: anchors.threat,
      value: suspicious.length,
      label: "şüpheli aktivite",
      sub: suspicious[0] ? `${pidsFlagged} işlemde · ${suspicious[0].title}` : "bulgu yok",
      go: () => setModule("threat"),
      hot: topSeverity(findings),
    },
  ];

  return (
    <div className="cc">
      <SystemColumn />

      <section className="cc-core">
        <GhostCore
          ringColor={TONE_COLOR[level.tone]}
          onPick={(pid) => focusProcess(pid)}
          onAnchors={(a, r) => {
            setAnchors(a);
            setR(r);
          }}
        />
        <div className={`cc-level cc-level--${level.tone}`} style={{ width: R * 0.56 }}>
          <span className="cc-level__k">güvenlik seviyesi</span>
          <span className="cc-level__word">{level.word}</span>
          <span className="cc-level__idx mono" title="Etkin bulgulardan hesaplanır: düşük 2, orta 8, yüksek 20, kritik 45 puan düşürür">indeks {level.index}/100</span>
          {level.severity && <Sev level={level.severity} label={false} />}
        </div>
        {readouts?.map((r) => (
          <button
            key={r.label}
            className={`cc-read cc-read--${r.at.side}${r.hot ? ` is-hot sevtx--${r.hot}` : ""}`}
            style={
              r.at.side === "left"
                ? { right: `calc(100% - ${r.at.x}px)`, top: r.at.y }
                : { left: r.at.x, top: r.at.y }
            }
            onClick={r.go}
          >
            <b className="mono">{r.value}</b>
            <span>{r.label}</span>
            <em>{r.sub}</em>
          </button>
        ))}
        <div className="cc-key">
          <span><i className="k-proc" />işlem (uzunluk = CPU)</span>
          <span><i className="k-conn" />bağlantı</span>
          <span><i className="k-port" />dinleyen port</span>
          <span><i className="k-risk" />riskli öğe</span>
        </div>
      </section>

      <EventFeed />
      <ActivityStrip />
    </div>
  );
}
