import { useVirtualizer } from "@tanstack/react-virtual";
import { useMemo, useRef, useState } from "react";
import { Sev, SigMark } from "../../design/components";
import { bytes } from "../../design/format";
import type { ProcessInfo } from "../../ipc/types";
import { SEVERITIES } from "../../ipc/types";
import { useGhost } from "../../state/store";
import { Dossier } from "./Dossier";
import { TimeMachine } from "./TimeMachine";
import { buildTree, type Row } from "./tree";
import "./process.css";

type View = "tree" | "flat" | "time";
type Filter = "all" | "risk" | "unsigned" | "net";
type SortKey = "name" | "pid" | "cpu" | "memory" | "startTime" | "connections" | "risk";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Tümü" },
  { id: "risk", label: "Şüpheli" },
  { id: "unsigned", label: "İmzasız" },
  { id: "net", label: "Ağ kullanan" },
];

function matches(p: ProcessInfo, q: string) {
  if (!q) return true;
  const s = q.toLocaleLowerCase("tr-TR");
  return (
    p.name.toLocaleLowerCase("tr-TR").includes(s) ||
    String(p.pid) === s ||
    (p.exe ?? "").toLocaleLowerCase("tr-TR").includes(s) ||
    (p.signature.publisher ?? "").toLocaleLowerCase("tr-TR").includes(s)
  );
}

function passes(p: ProcessInfo, f: Filter) {
  switch (f) {
    case "risk":
      return !!p.risk && p.risk !== "INFO";
    case "unsigned":
      return p.signature.state === "unsigned" || p.signature.state === "invalid";
    case "net":
      return p.connections > 0;
    default:
      return true;
  }
}

const riskRank = (p: ProcessInfo) => (p.risk ? SEVERITIES.indexOf(p.risk) + 1 : 0);

export default function ProcessHunter() {
  const processes = useGhost((s) => s.processes);
  const query = useGhost((s) => s.processQuery);
  const focusPid = useGhost((s) => s.focusPid);
  const focusProcess = useGhost((s) => s.focusProcess);
  const [view, setView] = useState<View>("tree");
  const [filter, setFilter] = useState<Filter>("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "cpu", dir: -1 });
  const scroller = useRef<HTMLDivElement>(null);

  const setQuery = (q: string) => useGhost.setState({ processQuery: q });
  const narrowing = query.trim() !== "" || filter !== "all";
  const effectiveView: View = view === "time" ? "time" : narrowing ? "flat" : view;

  const rows = useMemo<Row[]>(() => {
    if (effectiveView === "time") return [];
    if (effectiveView === "tree") return buildTree(processes);
    const list = processes.filter((p) => matches(p, query.trim()) && passes(p, filter));
    const k = sort.key;
    list.sort((a, b) => {
      const va = k === "risk" ? riskRank(a) : (a[k] as number | string);
      const vb = k === "risk" ? riskRank(b) : (b[k] as number | string);
      const c = typeof va === "string" ? va.localeCompare(vb as string, "tr") : (va as number) - (vb as number);
      return c * sort.dir || a.pid - b.pid;
    });
    return list.map((p) => ({ p, depth: 0, rails: [], last: true, hasKids: false }));
  }, [processes, effectiveView, query, filter, sort]);

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 27,
    overscan: 12,
  });

  const counts = useMemo(
    () => ({
      risk: processes.filter((p) => passes(p, "risk")).length,
      unsigned: processes.filter((p) => passes(p, "unsigned")).length,
      net: processes.filter((p) => passes(p, "net")).length,
    }),
    [processes],
  );

  const head = (key: SortKey, label: string, cls = "") => (
    <button
      className={`ph-h ${cls}${sort.key === key && effectiveView === "flat" ? " is-sorted" : ""}`}
      onClick={() => {
        setSort((s) => ({ key, dir: s.key === key ? ((-s.dir) as 1 | -1) : key === "name" ? 1 : -1 }));
        setView("flat");
      }}
      title="Sırala"
    >
      {label}
      {sort.key === key && effectiveView === "flat" ? (sort.dir === 1 ? " ▴" : " ▾") : ""}
    </button>
  );

  const focused = focusPid != null ? (processes.find((p) => p.pid === focusPid) ?? null) : null;

  if (effectiveView === "time")
    return (
      <div className="ph">
        <div className="ph-main">
          <div className="ph-bar">
            <div className="seg" aria-label="Görünüm">
              <button onClick={() => setView("tree")}>Soy ağacı</button>
              <button onClick={() => setView("flat")}>Liste</button>
              <button className="is-on">Zaman makinesi</button>
            </div>
            <span className="ph-count mono">geçmişteki bir anın işlem ağacı</span>
          </div>
          <TimeMachine />
        </div>
      </div>
    );

  return (
    <div className={`ph${focusPid != null ? " has-dossier" : ""}`}>
      <div className="ph-main">
        <div className="ph-bar">
          <input
            className="field ph-search"
            placeholder="ad, PID, dosya yolu veya yayıncı ara"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
          />
          <div className="seg" aria-label="Görünüm">
            <button
              className={effectiveView === "tree" ? "is-on" : ""}
              onClick={() => {
                setView("tree");
                setFilter("all");
                setQuery("");
              }}
            >
              Soy ağacı
            </button>
            <button className={effectiveView === "flat" ? "is-on" : ""} onClick={() => setView("flat")}>
              Liste
            </button>
            <button onClick={() => setView("time")}>Zaman makinesi</button>
          </div>
          <div className="seg" aria-label="Filtre">
            {FILTERS.map((f) => (
              <button key={f.id} className={filter === f.id ? "is-on" : ""} onClick={() => setFilter(f.id)}>
                {f.label}
                {f.id !== "all" && <i className="mono">{counts[f.id]}</i>}
              </button>
            ))}
          </div>
          <span className="ph-count mono">
            {rows.length} / {processes.length}
          </span>
        </div>

        <div className="ph-grid ph-head">
          {head("name", "İşlem", "c-name")}
          {head("pid", "PID", "c-num")}
          {head("cpu", "CPU %", "c-cpu")}
          {head("memory", "Bellek", "c-num")}
          <span className="ph-h c-sig">İmza / yayıncı</span>
          {head("connections", "Ağ", "c-num")}
          {head("startTime", "Başlangıç", "c-num")}
          {head("risk", "Risk", "c-risk")}
        </div>

        <div className="ph-scroll" ref={scroller}>
          {rows.length === 0 && (
            <div className="empty">
              <strong>Eşleşen işlem yok</strong>
              <span>Aramayı veya filtreyi değiştirin.</span>
            </div>
          )}
          <div style={{ height: virt.getTotalSize(), position: "relative" }}>
            {virt.getVirtualItems().map((vi) => {
              const r = rows[vi.index];
              const p = r.p;
              const risky = p.risk && p.risk !== "INFO";
              return (
                <div
                  key={p.pid}
                  className={`ph-grid ph-row${p.pid === focusPid ? " is-focus" : ""}${risky ? ` is-risk risk-${p.risk}` : ""}`}
                  style={{ transform: `translateY(${vi.start}px)` }}
                  onClick={() => focusProcess(p.pid === focusPid ? null : p.pid)}
                >
                  <span className="c-name">
                    {r.rails.map((on, i) => (
                      <i key={i} className={`rail${on ? " on" : ""}`} />
                    ))}
                    {r.depth > 0 && <i className={`elbow${r.last ? " last" : ""}`} />}
                    <b title={p.exe ?? p.name}>{p.name}</b>
                    {p.critical && (
                      <em className="crit" title="Kritik sistem işlemi — sonlandırma ek onay ister">
                        korumalı
                      </em>
                    )}
                  </span>
                  <span className="c-num mono">{p.pid}</span>
                  <span className="c-cpu mono">
                    {p.cpu >= 0.05 && <i className="cpu-bar" style={{ width: `${Math.min(100, p.cpu * 2)}%` }} />}
                    {p.cpu >= 0.05 ? p.cpu.toFixed(1) : "·"}
                  </span>
                  <span className="c-num mono">{p.memory > 0 ? bytes(p.memory) : <span className="dim" title="Bu yetkiyle okunamadı">—</span>}</span>
                  <span className="c-sig">
                    <SigMark sig={p.signature} />
                  </span>
                  <span className="c-num mono">{p.connections || "·"}</span>
                  <span className="c-num mono dim">
                    {p.startTime
                      ? new Date(p.startTime * 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" })
                      : "—"}
                  </span>
                  <span className="c-risk">{risky ? <Sev level={p.risk!} /> : null}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {focusPid != null && <Dossier key={focusPid} pid={focusPid} proc={focused} onClose={() => focusProcess(null)} />}
    </div>
  );
}
