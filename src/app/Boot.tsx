import { useEffect, useState } from "react";
import { isTauri } from "../ipc/api";
import { useGhost } from "../state/store";

/**
 * Opening sequence. Every line reports a real check — nothing is staged.
 * Any key or click skips it.
 */
export function Boot({ onDone }: { onDone: () => void }) {
  const host = useGhost((s) => s.host);
  const procs = useGhost((s) => s.processes.length);
  const socks = useGhost((s) => s.connections.length);
  const [step, setStep] = useState(0);
  const [leaving, setLeaving] = useState(false);

  const scanned = procs > 0;
  const lines: [string, string | null][] = [
    ["çekirdek", isTauri ? "bağlandı" : "masaüstü ortamı yok"],
    ["işletim sistemi", host ? `${host.osName}` : null],
    ["bilgisayar", host ? host.hostname : null],
    ["yetki", host ? (host.elevated ? "yönetici" : "standart kullanıcı") : null],
    ["veri deposu", host ? "ghost.db hazır" : null],
    ["ilk tarama", scanned ? `${procs} işlem, ${socks} soket` : null],
  ];

  // Advance one line at a time, but never past a line whose value hasn't arrived.
  useEffect(() => {
    if (step >= lines.length) {
      const t = window.setTimeout(() => setLeaving(true), 450);
      return () => window.clearTimeout(t);
    }
    if (lines[step][1] === null && isTauri) return;
    const t = window.setTimeout(() => setStep((s) => s + 1), 170);
    return () => window.clearTimeout(t);
  });

  useEffect(() => {
    if (!leaving) return;
    const t = window.setTimeout(onDone, 520);
    return () => window.clearTimeout(t);
  }, [leaving, onDone]);

  // Safety net: never trap the user behind the boot screen.
  useEffect(() => {
    const t = window.setTimeout(() => setLeaving(true), 9000);
    const skip = () => setLeaving(true);
    window.addEventListener("keydown", skip);
    window.addEventListener("mousedown", skip);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("keydown", skip);
      window.removeEventListener("mousedown", skip);
    };
  }, []);

  return (
    <div className={`boot${leaving ? " is-leaving" : ""}`} aria-live="polite">
      <div className="boot__frame">
        <div className="boot__mark">
          <svg viewBox="0 0 120 120" className="boot__glyph" aria-hidden="true">
            <circle cx="60" cy="60" r="52" className="boot__ring" />
            <circle cx="60" cy="60" r="36" className="boot__ring boot__ring--inner" />
            <path d="M60 30c13 12 13 48 0 60-13-12-13-48 0-60Z" className="boot__eye" />
          </svg>
          <div>
            <div className="boot__title">ghost monitor</div>
            <div className="boot__sub mono">{host ? `v${host.appVersion}` : "başlatılıyor"}</div>
          </div>
        </div>
        <ol className="boot__log mono">
          {lines.slice(0, step + 1).map(([k, v], i) => (
            <li key={k} className={i === step && step < lines.length ? "is-current" : ""}>
              <span className="boot__k">{k}</span>
              <span className="boot__dots" />
              <span className="boot__v">{v ?? "…"}</span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
