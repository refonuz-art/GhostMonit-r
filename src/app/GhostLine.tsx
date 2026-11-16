import { useEffect, useRef, useState } from "react";
import { bytes, pct, rate } from "../design/format";
import { api } from "../ipc/api";
import { useGhost } from "../state/store";
import { runCommand } from "./commands";

/** Persistent command line + live status. Focus with ":" or Ctrl+K from anywhere. */
export function GhostLine() {
  const m = useGhost((s) => s.metrics);
  const host = useGhost((s) => s.host);
  const [value, setValue] = useState("");
  const [out, setOut] = useState<{ ok: boolean; text: string } | null>(null);
  const [hist, setHist] = useState<string[]>([]);
  const [hi, setHi] = useState(-1);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement)?.closest("input, textarea");
      if ((e.key === ":" && !typing) || (e.ctrlKey && e.key.toLowerCase() === "k")) {
        e.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  async function submit() {
    const v = value;
    setValue("");
    setHi(-1);
    if (!v.trim()) return;
    setHist((h) => [v, ...h.filter((x) => x !== v)].slice(0, 50));
    const r = await runCommand(v);
    setOut(r.text ? r : null);
  }

  const mem = m ? (m.memUsed / Math.max(1, m.memTotal)) * 100 : 0;

  return (
    <footer className="gline">
      {out && (
        <pre className={`gline__out${out.ok ? "" : " is-bad"}`} onClick={() => setOut(null)}>
          {out.text}
        </pre>
      )}
      <label className="gline__prompt">
        <span className="gline__caret">❯</span>
        <input
          ref={input}
          className="gline__input mono"
          value={value}
          spellCheck={false}
          placeholder="komut yazın — yardım için “yardım”  ( : ile odaklan )"
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
            else if (e.key === "Escape") {
              setOut(null);
              (e.target as HTMLInputElement).blur();
            } else if (e.key === "ArrowUp" && hist.length) {
              e.preventDefault();
              const n = Math.min(hist.length - 1, hi + 1);
              setHi(n);
              setValue(hist[n]);
            } else if (e.key === "ArrowDown") {
              e.preventDefault();
              const n = hi - 1;
              setHi(n);
              setValue(n >= 0 ? hist[n] : "");
            }
          }}
        />
      </label>

      <div className="gline__status mono">
        <span title="İşlemci">
          cpu <b>{m ? pct(m.cpu) : "—"}</b>
        </span>
        <span title="Bellek">
          ram <b>{m ? pct(mem) : "—"}</b> <i>{m ? bytes(m.memUsed) : ""}</i>
        </span>
        <span title="Ağ: indirme / yükleme">
          ↓ <b>{m ? rate(m.netRxRate) : "—"}</b> ↑ <b>{m ? rate(m.netTxRate) : "—"}</b>
        </span>
        {host && (
          <button
            className={`gline__priv${host.elevated ? " is-admin" : ""}`}
            title={
              host.elevated
                ? "Yönetici yetkisiyle çalışıyor"
                : "Standart yetki: bazı korumalı işlemlerin yolu ve imzası okunamaz. Tıklayın: yönetici olarak yeniden başlat"
            }
            onClick={() => !host.elevated && api.relaunchAdmin().catch((e) => setOut({ ok: false, text: String(e) }))}
          >
            {host.elevated ? "yönetici" : "standart yetki"}
          </button>
        )}
      </div>
    </footer>
  );
}
