import { getCurrentWindow } from "@tauri-apps/api/window";
import { useLayoutEffect, useRef, useState } from "react";
import { Icon } from "../design/icons";
import { isTauri } from "../ipc/api";
import { topSeverity } from "../state/derive";
import { useGhost } from "../state/store";
import { MODULES } from "./modules";

/** Window chrome and module navigation are the same strip. */
export function TitleBar() {
  const module = useGhost((s) => s.module);
  const setModule = useGhost((s) => s.setModule);
  const findings = useGhost((s) => s.findings);
  const navRef = useRef<HTMLElement>(null);
  const [trace, setTrace] = useState({ left: 0, width: 0 });

  const threatCount = findings.filter((f) => f.severity !== "INFO").length;
  const top = topSeverity(findings);

  useLayoutEffect(() => {
    const nav = navRef.current;
    if (!nav) return;
    const measure = () => {
      const el = nav.querySelector<HTMLElement>(`[data-id="${module}"]`);
      if (!el) return;
      const a = el.getBoundingClientRect();
      const b = nav.getBoundingClientRect();
      setTrace({ left: a.left - b.left, width: a.width });
    };
    measure();
    // Tab widths shift when fonts finish loading or the threat badge changes size.
    const ro = new ResizeObserver(measure);
    nav.querySelectorAll("[data-id]").forEach((t) => ro.observe(t));
    document.fonts?.ready.then(measure);
    return () => ro.disconnect();
  }, [module]);

  const win = isTauri ? getCurrentWindow() : null;

  return (
    <header className="chrome" data-tauri-drag-region>
      <div className="chrome__mark" data-tauri-drag-region>
        <Icon.ghost className="chrome__logo" />
        <span className="chrome__name" data-tauri-drag-region>
          ghost<b>monitor</b>
        </span>
      </div>

      <nav className="chrome__nav" ref={navRef} aria-label="Modüller">
        {MODULES.map((m, i) => (
          <button
            key={m.id}
            data-id={m.id}
            className={`chrome__tab${m.id === module ? " is-active" : ""}${m.ready ? "" : " is-planned"}`}
            onClick={() => setModule(m.id)}
            title={`${m.label}${i < 10 ? ` (Ctrl+${(i + 1) % 10})` : ""}${m.ready ? "" : " — henüz geliştirilmedi"}`}
          >
            <m.icon />
            <span>{m.label}</span>
            {m.id === "threat" && threatCount > 0 && <em className={`chrome__badge sevbg--${top}`}>{threatCount}</em>}
          </button>
        ))}
        <i className="chrome__trace" style={{ transform: `translateX(${trace.left}px)`, width: trace.width }} />
      </nav>

      <div className="chrome__spacer" data-tauri-drag-region />

      <div className="chrome__win">
        <button
          aria-label="Ayarlar"
          title="Ayarlar (Ctrl+,)"
          className={module === "settings" ? "is-active" : ""}
          onClick={() => setModule("settings")}
        >
          <Icon.settings />
        </button>
        <button aria-label="Küçült" onClick={() => win?.minimize()}>
          <Icon.minimize />
        </button>
        <button aria-label="Büyüt" onClick={() => win?.toggleMaximize()}>
          <Icon.maximize />
        </button>
        <button aria-label="Kapat" className="is-close" onClick={() => win?.close()}>
          <Icon.close />
        </button>
      </div>
    </header>
  );
}
