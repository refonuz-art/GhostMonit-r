import { useEffect, useState } from "react";
import { Sev } from "../../design/components";
import { stamp } from "../../design/format";
import { v5, type WeeklyDiff, type WeeklySection } from "../../ipc/v5";

const STATUS_TR: Record<string, string> = { ok: "tamam", warn: "dikkat", bad: "sorun", unknown: "bilinmiyor" };

function Delta({ now, prev }: { now: number; prev: number }) {
  const d = now - prev;
  if (d === 0) return <span className="wk-delta dim">geçen haftayla aynı</span>;
  return (
    <span className={`wk-delta ${d > 0 ? "is-up" : "is-down"}`}>
      {d > 0 ? "▲" : "▼"} {Math.abs(d)} <span className="dim">geçen hafta {prev}</span>
    </span>
  );
}

function Block({ s }: { s: WeeklySection }) {
  const [open, setOpen] = useState(s.now > 0 && s.now <= 5);
  return (
    <section className={`wk-sec${s.now > 0 ? " has-change" : ""}`}>
      <button className="wk-sec__head" onClick={() => setOpen(!open)} disabled={s.items.length === 0}>
        <b className="mono">{s.now}</b>
        <span className="wk-sec__t">{s.title}</span>
        <Delta now={s.now} prev={s.prev} />
        {s.items.length > 0 && <i className="dim">{open ? "gizle" : "göster"}</i>}
      </button>
      {s.note && <p className="wk-note">{s.note}</p>}
      {open && s.items.length > 0 && (
        <ul className="wk-items">
          {s.items.map((it, i) => (
            <li key={i}>
              {it.severity && it.severity !== "INFO" ? <Sev level={it.severity} label={false} /> : <span className="wk-dot" />}
              <span className="wk-items__t">{it.title}</span>
              <span className="wk-items__d mono dim">{it.detail}</span>
              <span className="mono dim">{stamp(it.ts)}</span>
            </li>
          ))}
          {s.now > s.items.length && <li className="dim">…ve {s.now - s.items.length} tane daha</li>}
        </ul>
      )}
    </section>
  );
}

export function Weekly() {
  const [d, setD] = useState<WeeklyDiff | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    v5.weekly().then(setD, (e) => setErr(String(e)));
  }, []);
  if (err) return <p className="dim">Karşılaştırma yapılamadı: {err}</p>;
  if (!d) return <div className="module-loading" />;
  const h = d.health;
  const changed = d.sections.filter((s) => s.now > 0).length;
  return (
    <div className="wk">
      <header className="wk-head">
        <div>
          <h3>Geçen haftaya göre</h3>
          <p className="dim">
            {stamp(d.since)} – {stamp(d.until)} · önceki 7 günle karşılaştırılıyor · {changed} alanda değişiklik var
          </p>
        </div>
        <div className="wk-score">
          {h.now != null && h.then != null ? (
            <>
              <span className="dim">sağlık puanı</span>
              <b className="mono">
                {h.then} → {h.now}
              </b>
              <Delta now={h.now} prev={h.then} />
            </>
          ) : (
            <span className="dim">
              {h.now != null ? `Sağlık puanı ${h.now}. Bir hafta önceki puan henüz kayıtlı değil (puanlar bu sürümden itibaren günlük saklanıyor).` : "Sağlık puanı henüz hesaplanmadı."}
            </span>
          )}
        </div>
      </header>
      {h.changed.length > 0 && (
        <ul className="wk-checks">
          {h.changed.map((c) => (
            <li key={c.label}>
              <span>{c.label}</span>
              <span className={`wk-st is-${c.from}`}>{STATUS_TR[c.from] ?? c.from}</span>→
              <span className={`wk-st is-${c.to}`}>{STATUS_TR[c.to] ?? c.to}</span>
            </li>
          ))}
        </ul>
      )}
      {d.sections.map((s) => (
        <Block key={s.id} s={s} />
      ))}
    </div>
  );
}
