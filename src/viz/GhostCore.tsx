// Ghost Core — the home screen instrument.
//   outer ring   : every running process, one tick each (length = CPU, colour = risk)
//   middle bands : established remote connections (inner = local network, outer = internet)
//   inner ring   : listening ports, placed by port number
//   centre       : security level (DOM overlay)
// A slow radar sweep brightens whatever it passes; flagged items flare red.

import { useEffect, useRef, useState } from "react";
import { frameGate } from "./frameGate";
import { hash01 } from "../design/format";
import type { ConnectionInfo, ProcessInfo, Severity } from "../ipc/types";
import { SEV_COLOR } from "../design/components";
import { useGhost } from "../state/store";

const TAU = Math.PI * 2;
const SWEEP_MS = 7000;

export interface CoreAnchor {
  x: number;
  y: number;
  side: "left" | "right";
}

interface Hover {
  x: number;
  y: number;
  title: string;
  lines: string[];
  pid: number;
}

interface Geo {
  w: number;
  h: number;
  cx: number;
  cy: number;
  R: number;
}

const PHOS = [61, 255, 154];
const ARC = [34, 184, 255];
const rgba = (c: number[], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${a.toFixed(3)})`;
const hexA = (hex: string, a: number) => {
  const n = parseInt(hex.slice(1), 16);
  return rgba([(n >> 16) & 255, (n >> 8) & 255, n & 255], a);
};

function angDiff(sweep: number, a: number) {
  // How far behind the sweep line `a` is (0..TAU)
  return (((sweep - a) % TAU) + TAU) % TAU;
}

export function GhostCore({
  onPick,
  onAnchors,
  ringColor,
}: {
  onPick: (pid: number) => void;
  onAnchors: (a: Record<"proc" | "conn" | "port" | "threat", CoreAnchor>, R: number) => void;
  ringColor: string;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const geo = useRef<Geo>({ w: 0, h: 0, cx: 0, cy: 0, R: 0 });
  const data = useRef({ procs: [] as ProcessInfo[], conns: [] as ConnectionInfo[] });
  const hoverRef = useRef<Hover | null>(null);
  const [hover, setHover] = useState<Hover | null>(null);
  const ringRef = useRef(ringColor);
  ringRef.current = ringColor;
  const anchorsCb = useRef(onAnchors);
  anchorsCb.current = onAnchors;

  // Keep latest data in a ref so the render loop never restarts.
  useEffect(() => {
    const pick = (s: ReturnType<typeof useGhost.getState>) => {
      data.current = {
        procs: [...s.processes].sort((a, b) => a.pid - b.pid),
        conns: s.connections,
      };
    };
    pick(useGhost.getState());
    return useGhost.subscribe((s, prev) => {
      if (s.processes !== prev.processes || s.connections !== prev.connections) pick(s);
    });
  }, []);

  // Resize → geometry + readout anchors.
  useEffect(() => {
    const el = wrap.current!;
    const cv = canvas.current!;
    const ro = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      const dpr = window.devicePixelRatio || 1;
      cv.width = Math.round(w * dpr);
      cv.height = Math.round(h * dpr);
      cv.style.width = `${w}px`;
      cv.style.height = `${h}px`;
      const R = Math.max(80, Math.min(w * 0.36, h / 2 - 34));
      const g = { w, h, cx: w / 2, cy: h / 2, R };
      geo.current = g;
      const at = (deg: number, r: number) => {
        const a = (deg * Math.PI) / 180;
        return { x: g.cx + Math.cos(a) * r, y: g.cy + Math.sin(a) * r };
      };
      const ex = R + 34;
      const p = at(-140, ex);
      const c = at(-40, ex);
      const o = at(140, ex);
      const t = at(40, ex);
      anchorsCb.current(
        {
          proc: { ...p, side: "left" },
          conn: { ...c, side: "right" },
          port: { ...o, side: "left" },
          threat: { ...t, side: "right" },
        },
        R,
      );
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Render loop.
  useEffect(() => {
    const cv = canvas.current!;
    const ctx = cv.getContext("2d")!;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    const gate = frameGate();
    const t0 = performance.now();

    // Static layer (rings, bezel, leader lines) is drawn once per size, then blitted.
    const staticLayer = document.createElement("canvas");
    let staticKey = "";
    const paintStatic = (w: number, h: number, dpr: number, cx: number, cy: number, R: number) => {
      staticLayer.width = cv.width;
      staticLayer.height = cv.height;
      const s = staticLayer.getContext("2d")!;
      s.setTransform(dpr, 0, 0, dpr, 0, 0);
      s.lineWidth = 1;
      s.strokeStyle = "#1a242c";
      s.beginPath();
      for (const k of [1, 0.8, 0.76, 0.56, 0.4, 0.33]) {
        s.moveTo(cx + R * k, cy);
        s.arc(cx, cy, R * k, 0, TAU);
      }
      s.stroke();
      for (const major of [false, true]) {
        s.strokeStyle = major ? "#2f414e" : "#1d2730";
        s.beginPath();
        for (let d = 0; d < 360; d += 5) {
          if ((d % 30 === 0) !== major) continue;
          const a = (d * Math.PI) / 180;
          const r1 = R + 6;
          const r2 = R + (major ? 14 : 9);
          s.moveTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
          s.lineTo(cx + Math.cos(a) * r2, cy + Math.sin(a) * r2);
        }
        s.stroke();
      }
      s.strokeStyle = "#2f414e";
      s.fillStyle = "#4a5762";
      for (const [deg, k] of [
        [-140, 1],
        [-40, 0.74],
        [140, 0.365],
        [40, 1],
      ] as const) {
        const a = (deg * Math.PI) / 180;
        const r1 = R * k + 4;
        const r2 = R + 34;
        s.beginPath();
        s.moveTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
        s.lineTo(cx + Math.cos(a) * r2, cy + Math.sin(a) * r2);
        s.stroke();
        s.fillRect(cx + Math.cos(a) * r1 - 1.5, cy + Math.sin(a) * r1 - 1.5, 3, 3);
      }
      staticKey = `${w}x${h}@${dpr}`;
    };

    // Batch strokes by style: hundreds of stroke() calls become a few dozen.
    const q = (v: number) => Math.round(Math.min(1, v) * 20) / 20;
    const batches = new Map<string, Path2D>();
    const seg = (style: string, x1: number, y1: number, x2: number, y2: number) => {
      let p = batches.get(style);
      if (!p) batches.set(style, (p = new Path2D()));
      p.moveTo(x1, y1);
      p.lineTo(x2, y2);
    };
    const flush = (lineWidth: number) => {
      ctx.lineWidth = lineWidth;
      for (const [style, p] of batches) {
        ctx.strokeStyle = style;
        ctx.stroke(p);
      }
      batches.clear();
    };

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      if (!gate(now)) return;
      const { w, h, cx, cy, R } = geo.current;
      if (!w) return;
      const dpr = cv.width / w;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, cv.width, cv.height);
      if (staticKey !== `${w}x${h}@${dpr}` || staticLayer.width !== cv.width) paintStatic(w, h, dpr, cx, cy, R);
      ctx.drawImage(staticLayer, 0, 0);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const t = now - t0;
      const sweep = reduced ? -Math.PI / 2 : (-Math.PI / 2 + (t / SWEEP_MS) * TAU) % TAU;
      const { procs, conns } = data.current;
      const hov = hoverRef.current;
      ctx.lineWidth = 1;

      // --- sweep wedge (only the visible sector is filled) ---
      if (!reduced) {
        const span = 0.9;
        const g = ctx.createConicGradient(sweep - span, cx, cy);
        const f = span / TAU;
        g.addColorStop(0, rgba(PHOS, 0));
        g.addColorStop(f * 0.999, rgba(PHOS, 0.09));
        g.addColorStop(f, rgba(PHOS, 0));
        g.addColorStop(1, rgba(PHOS, 0));
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, R, sweep - span, sweep);
        ctx.closePath();
        ctx.fill();
        ctx.strokeStyle = rgba(PHOS, 0.45);
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(sweep) * R * 0.33, cy + Math.sin(sweep) * R * 0.33);
        ctx.lineTo(cx + Math.cos(sweep) * R, cy + Math.sin(sweep) * R);
        ctx.stroke();
      }

      // --- connections ---
      const remote = conns.filter((c) => c.remoteAddr && c.state === "ESTABLISHED" && c.scope !== "loopback");
      for (const c of remote) {
        const a = hash01(c.remoteAddr!) * TAU;
        const pub = c.scope === "public";
        const band = pub ? [0.6, 0.74] : [0.42, 0.54];
        const r = R * (band[0] + (band[1] - band[0]) * hash01(`${c.remotePort}${c.pid}`));
        const x = cx + Math.cos(a) * r;
        const y = cy + Math.sin(a) * r;
        const flare = Math.exp(-angDiff(sweep, a) * 2.4);
        const risk = c.risk && c.risk !== "INFO" ? SEV_COLOR[c.risk as Severity] : null;
        const isHov = hov?.pid === c.pid;

        seg(
          risk ? hexA(risk, 0.35) : rgba(ARC, q((pub ? 0.07 : 0.04) + flare * 0.15 + (isHov ? 0.4 : 0))),
          cx + Math.cos(a) * R * 0.33,
          cy + Math.sin(a) * R * 0.33,
          x,
          y,
        );

        if (pub && !reduced) {
          const ph = (t / 1800 + hash01(c.id)) % 1;
          const pr = R * 0.33 + (r - R * 0.33) * ph;
          ctx.fillStyle = rgba(ARC, 0.6 * (1 - ph));
          ctx.fillRect(cx + Math.cos(a) * pr - 1, cy + Math.sin(a) * pr - 1, 2, 2);
        }

        ctx.fillStyle = risk ?? rgba(ARC, (pub ? 0.55 : 0.3) + flare * 0.45);
        const s = isHov ? 5 : pub ? 3 : 2.5;
        ctx.fillRect(x - s / 2, y - s / 2, s, s);
      }
      flush(1);

      // --- listening ports ---
      for (const c of conns) {
        if (c.protocol !== "tcp" || c.state !== "LISTEN") continue;
        const a = (c.localPort / 65536) * TAU - Math.PI / 2;
        const r = R * 0.365;
        const exposed = c.scope !== "loopback";
        const flare = Math.exp(-angDiff(sweep, a) * 3);
        ctx.fillStyle = exposed ? rgba(PHOS, 0.45 + flare * 0.5) : "rgba(122,136,148,0.35)";
        ctx.fillRect(cx + Math.cos(a) * r - 1.5, cy + Math.sin(a) * r - 1.5, 3, 3);
      }

      // --- processes ---
      const n = procs.length || 1;
      for (let i = 0; i < procs.length; i++) {
        const p = procs[i];
        const a = -Math.PI / 2 + (i / n) * TAU;
        const load = Math.min(1, Math.sqrt(p.cpu / 100) * 1.6);
        const len = 6 + load * R * 0.16;
        const r0 = R * 0.81;
        const flare = Math.exp(-angDiff(sweep, a) * 3.2);
        const risk = p.risk && p.risk !== "INFO" ? SEV_COLOR[p.risk] : null;
        const isHov = hov?.pid === p.pid;
        const cos = Math.cos(a);
        const sin = Math.sin(a);
        if (risk || isHov) {
          ctx.lineWidth = 2.2;
          ctx.strokeStyle = risk ?? "#e8eef2";
          ctx.beginPath();
          ctx.moveTo(cx + cos * r0, cy + sin * r0);
          ctx.lineTo(cx + cos * (r0 + len), cy + sin * (r0 + len));
          ctx.stroke();
        } else {
          seg(rgba(PHOS, q(0.34 + load * 0.5 + flare * 0.45)), cx + cos * r0, cy + sin * r0, cx + cos * (r0 + len), cy + sin * (r0 + len));
        }

        if (risk) {
          const pulse = reduced ? 0.6 : 0.5 + 0.5 * Math.sin(t / 260 + i);
          const rr = R + 22;
          const x = cx + cos * rr;
          const y = cy + sin * rr;
          ctx.fillStyle = risk;
          ctx.save();
          ctx.translate(x, y);
          ctx.rotate(Math.PI / 4);
          ctx.fillRect(-3.5, -3.5, 7, 7);
          ctx.restore();
          ctx.strokeStyle = hexA(risk, 0.5 * pulse);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(x, y, 7 + pulse * 5, 0, TAU);
          ctx.stroke();
        }
      }
      flush(1.4);
      ctx.lineWidth = 1;

      // --- core disc ---
      const breathe = reduced ? 0 : Math.sin(t / 1400) * 0.5 + 0.5;
      ctx.fillStyle = "#0b0f13";
      ctx.beginPath();
      ctx.arc(cx, cy, R * 0.3, 0, TAU);
      ctx.fill();
      ctx.strokeStyle = ringRef.current;
      ctx.globalAlpha = 0.55 + breathe * 0.45;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 0.3, 0, TAU);
      ctx.stroke();
      ctx.globalAlpha = 0.25;
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 4]);
      ctx.beginPath();
      ctx.arc(cx, cy, R * 0.3 + 6 + breathe * 3, 0, TAU);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, []);

  function hitTest(mx: number, my: number): Hover | null {
    const { cx, cy, R } = geo.current;
    const dx = mx - cx;
    const dy = my - cy;
    const r = Math.hypot(dx, dy);
    const a = Math.atan2(dy, dx);
    const { procs, conns } = data.current;
    if (r >= R * 0.79 && r <= R + 30 && procs.length) {
      let i = Math.round((((a + Math.PI / 2) % TAU) + TAU) % TAU / TAU * procs.length) % procs.length;
      const p = procs[i];
      return {
        x: mx,
        y: my,
        pid: p.pid,
        title: p.name,
        lines: [`PID ${p.pid}`, `CPU ${p.cpu.toFixed(1)}%`, `${(p.memory / 1048576).toFixed(0)} MB`, p.connections ? `${p.connections} bağlantı` : ""].filter(Boolean),
      };
    }
    if (r >= R * 0.4 && r <= R * 0.76) {
      let best: ConnectionInfo | null = null;
      let bd = 10;
      for (const c of conns) {
        if (!c.remoteAddr || c.state !== "ESTABLISHED" || c.scope === "loopback") continue;
        const ca = hash01(c.remoteAddr) * TAU;
        const pub = c.scope === "public";
        const band = pub ? [0.6, 0.74] : [0.42, 0.54];
        const cr = R * (band[0] + (band[1] - band[0]) * hash01(`${c.remotePort}${c.pid}`));
        const d = Math.hypot(cx + Math.cos(ca) * cr - mx, cy + Math.sin(ca) * cr - my);
        if (d < bd) {
          bd = d;
          best = c;
        }
      }
      if (best)
        return {
          x: mx,
          y: my,
          pid: best.pid,
          title: `${best.remoteAddr}:${best.remotePort}`,
          lines: [best.processName ?? `PID ${best.pid}`, best.scope === "public" ? "internet" : "yerel ağ"],
        };
    }
    return null;
  }

  return (
    <div
      ref={wrap}
      className="core"
      onMouseMove={(e) => {
        const b = wrap.current!.getBoundingClientRect();
        const h = hitTest(e.clientX - b.left, e.clientY - b.top);
        hoverRef.current = h;
        setHover(h);
      }}
      onMouseLeave={() => {
        hoverRef.current = null;
        setHover(null);
      }}
      onClick={() => hover && onPick(hover.pid)}
      style={{ cursor: hover ? "pointer" : "default" }}
    >
      <canvas ref={canvas} />
      {hover && (
        <div className="core__tip" style={{ left: hover.x + 14, top: hover.y + 10 }}>
          <b>{hover.title}</b>
          {hover.lines.map((l) => (
            <span key={l} className="mono">
              {l}
            </span>
          ))}
          <em>tıkla: işlem dosyası</em>
        </div>
      )}
    </div>
  );
}
