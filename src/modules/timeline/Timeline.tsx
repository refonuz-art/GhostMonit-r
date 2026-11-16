import { useEffect, useMemo, useState } from "react";
import { SEV_COLOR, SEV_LABEL, Sev } from "../../design/components";
import { clock, day } from "../../design/format";
import { api } from "../../ipc/api";
import type { SecurityEvent, Severity } from "../../ipc/types";
import { SEVERITIES } from "../../ipc/types";
import { useGhost } from "../../state/store";
import "./timeline.css";

const RANGES = [
  { id: "1h", label: "1 saat", ms: 3600e3, buckets: 60 },
  { id: "24h", label: "24 saat", ms: 86400e3, buckets: 96 },
  { id: "7d", label: "7 gün", ms: 7 * 86400e3, buckets: 84 },
  { id: "30d", label: "30 gün", ms: 30 * 86400e3, buckets: 90 },
] as const;

const LANES = [
  { id: "all", label: "Tümü", kinds: [] as string[] },
  { id: "threat", label: "Tehdit", kinds: ["threat.finding"] },
  { id: "network", label: "Ağ", kinds: ["network.new_remote"] },
  { id: "process", label: "İşlem", kinds: ["process.start", "process.kill"] },
  { id: "files", label: "Dosya ve sürücü", kinds: ["file.new", "usb.inserted", "usb.removed"] },
  { id: "startup", label: "Açılış", kinds: ["startup.new", "startup.changed", "startup.removed"] },
  { id: "user", label: "Kullanıcı", kinds: ["user.trust", "process.kill"] },
] as const;

const LANE_OF: Record<string, { glyph: string; name: string }> = {
  "threat.finding": { glyph: "◆", name: "tehdit" },
  "network.new_remote": { glyph: "◈", name: "ağ" },
  "process.start": { glyph: "◇", name: "işlem" },
  "process.kill": { glyph: "✕", name: "kullanıcı" },
  "user.trust": { glyph: "✓", name: "kullanıcı" },
  "file.new": { glyph: "▤", name: "dosya" },
  "usb.inserted": { glyph: "⊟", name: "sürücü" },
  "usb.removed": { glyph: "⊟", name: "sürücü" },
  "startup.new": { glyph: "⏻", name: "açılış" },
  "startup.changed": { glyph: "⏻", name: "açılış" },
  "startup.removed": { glyph: "⏻", name: "açılış" },
  "intel.feed": { glyph: "≡", name: "istihbarat" },
  "report.auto": { glyph: "▦", name: "rapor" },
};

type RangeId = (typeof RANGES)[number]["id"];
type LaneId = (typeof LANES)[number]["id"];

export default function Timeline() {
  const liveCount = useGhost((s) => s.liveEvents[0]?.id ?? 0);
  const focusProcess = useGhost((s) => s.focusProcess);
  const [range, setRange] = useState<RangeId>("24h");
  const [lane, setLane] = useState<LaneId>("all");
  const [minSev, setMinSev] = useState<Severity>("INFO");
  const [q, setQ] = useState("");
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const r = RANGES.find((x) => x.id === range)!;

  useEffect(() => {
    const t = window.setTimeout(() => {
      setLoading(true);
      api
        .events({
          since: Date.now() - r.ms,
          kinds: [...LANES.find((l) => l.id === lane)!.kinds],
          minSeverity: minSev === "INFO" ? undefined : minSev,
          search: q.trim() || undefined,
          limit: 3000,
        })
        .then(setEvents)
        .catch(() => setEvents([]))
        .finally(() => setLoading(false));
    }, 150);
    return () => window.clearTimeout(t);
    // liveCount: refetch as new events stream in
  }, [range, lane, minSev, q, liveCount, r.ms]);

  const now = Date.now();
  const density = useMemo(() => {
    const start = now - r.ms;
    const size = r.ms / r.buckets;
    const b = Array.from({ length: r.buckets }, () => ({ n: 0, top: "INFO" as Severity }));
    for (const e of events) {
      const i = Math.floor((e.ts - start) / size);
      if (i < 0 || i >= r.buckets) continue;
      b[i].n++;
      if (SEVERITIES.indexOf(e.severity) > SEVERITIES.indexOf(b[i].top)) b[i].top = e.severity;
    }
    return b;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, range]);
  const maxN = Math.max(1, ...density.map((d) => d.n));

  const groups = useMemo(() => {
    const out: { day: string; items: SecurityEvent[] }[] = [];
    for (const e of events) {
      const d = day(e.ts);
      if (!out.length || out[out.length - 1].day !== d) out.push({ day: d, items: [] });
      out[out.length - 1].items.push(e);
    }
    return out;
  }, [events]);

  return (
    <div className="tl">
      <div className="tl-bar">
        <div className="seg">
          {RANGES.map((x) => (
            <button key={x.id} className={range === x.id ? "is-on" : ""} onClick={() => setRange(x.id)}>
              {x.label}
            </button>
          ))}
        </div>
        <div className="seg">
          {LANES.map((l) => (
            <button key={l.id} className={lane === l.id ? "is-on" : ""} onClick={() => setLane(l.id)}>
              {l.label}
            </button>
          ))}
        </div>
        <div className="seg">
          {SEVERITIES.map((s) => (
            <button key={s} className={minSev === s ? "is-on" : ""} onClick={() => setMinSev(s)} title={`${SEV_LABEL[s]} ve üstü`}>
              {SEV_LABEL[s]}
              {s !== "CRITICAL" && "+"}
            </button>
          ))}
        </div>
        <input className="field" placeholder="başlık, ayrıntı veya işlem ara" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="mono dim tl-count">{loading ? "…" : `${events.length} olay`}</span>
      </div>

      <div className="tl-density" aria-label="Olay yoğunluğu">
        {density.map((d, i) => (
          <i
            key={i}
            style={{ height: `${d.n ? 12 + (d.n / maxN) * 88 : 0}%`, background: d.n ? SEV_COLOR[d.top] : undefined }}
            title={`${d.n} olay`}
          />
        ))}
        <span className="tl-density__l mono">{r.label} önce</span>
        <span className="tl-density__r mono">şimdi</span>
      </div>

      <div className="tl-scroll">
        {!loading && events.length === 0 && (
          <div className="empty">
            <strong>Bu aralıkta olay yok</strong>
            <span>Aralığı genişletin veya filtreleri gevşetin.</span>
          </div>
        )}
        {groups.map((g) => (
          <section key={g.day} className="tl-day">
            <h3>{g.day}</h3>
            <ol>
              {g.items.map((e) => {
                const ln = LANE_OF[e.kind] ?? { glyph: "·", name: e.kind };
                const pid = typeof e.data?.pid === "number" ? (e.data.pid as number) : null;
                return (
                  <li key={e.id} className={`tl-ev sev-${e.severity}${open === e.id ? " is-open" : ""}`}>
                    <button className="tl-ev__row" onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <time className="mono">{clock(e.ts)}</time>
                      <i className="tl-ev__glyph" title={ln.name}>
                        {ln.glyph}
                      </i>
                      <span className="tl-ev__title">{e.title}</span>
                      {e.severity !== "INFO" && <Sev level={e.severity} />}
                    </button>
                    {open === e.id && (
                      <div className="tl-ev__detail">
                        <p className="selectable">{e.detail || "—"}</p>
                        <pre className="mono selectable">{JSON.stringify(e.data, null, 2)}</pre>
                        {pid !== null && (
                          <button className="btn" onClick={() => focusProcess(pid)}>
                            PID {pid} işlem dosyası
                          </button>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          </section>
        ))}
      </div>
    </div>
  );
}
