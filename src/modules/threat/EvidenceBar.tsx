import type { Signal } from "../../ipc/types";
import "./evidence.css";

const MAX = 120;
const MARKS = [
  { at: 15, label: "düşük" },
  { at: 30, label: "orta" },
  { at: 55, label: "yüksek" },
  { at: 80, label: "kritik" },
];

/** Strongest signal per rule — same de-duplication the engine applies. */
export function distinct(signals: Signal[]) {
  const m = new Map<string, Signal>();
  for (const s of signals) {
    const cur = m.get(s.rule);
    if (!cur || s.weight > cur.weight) m.set(s.rule, s);
  }
  return [...m.values()].sort((a, b) => b.weight - a.weight);
}

/** Shows how each independent signal adds up to the score, against severity thresholds. */
export function EvidenceBar({ signals }: { signals: Signal[] }) {
  const d = distinct(signals);
  const total = d.reduce((s, x) => s + x.weight, 0);
  const capped = d.length === 1 && total > 54 && d[0].weight < 100;
  return (
    <div className="evb">
      <div className="evb__track">
        {d.map((s, i) => (
          <i
            key={s.rule}
            className="evb__seg"
            style={{ width: `${(Math.min(MAX, s.weight) / MAX) * 100}%`, opacity: 1 - i * 0.12 }}
            title={`${s.label}: +${s.weight}`}
          />
        ))}
        {MARKS.map((m) => (
          <b key={m.at} className="evb__mark" style={{ left: `${(m.at / MAX) * 100}%` }}>
            <span>{m.label}</span>
          </b>
        ))}
      </div>
      <div className="evb__meta mono">
        puan {total} · {d.length} bağımsız sinyal
        {capped && <em> — tek sinyal en fazla “orta” seviyeye çıkabilir</em>}
      </div>
    </div>
  );
}
