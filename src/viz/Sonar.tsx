// Network sonar: this machine at the centre. Each remote host is a contact.
//   angle   — by network prefix, so hosts in the same network cluster together
//   band    — inner = local network, outer = internet
//   radius  — newest contacts sit at the band's outer edge and drift inward with age
//   size    — number of sockets to that host

import { useEffect, useRef, useState } from "react";
import { frameGate } from "./frameGate";
import { SEV_COLOR } from "../design/components";
import { hash01 } from "../design/format";
import type { ConnectionInfo, Severity } from "../ipc/types";
import { SEVERITIES } from "../ipc/types";

const TAU = Math.PI * 2;
const AGE_SPAN = 30 * 60 * 1000;

export interface Contact {
  ip: string;
  conns: ConnectionInfo[];
  pub: boolean;
  newest: number;
  risk: Severity | null;
  label: string;
}

function prefix(ip: string) {
  if (ip.includes(":")) return ip.split(":").slice(0, 3).join(":");
  return ip.split(".").slice(0, 2).join(".");
}

export function contactsOf(conns: ConnectionInfo[]): Contact[] {
  const m = new Map<string, Contact>();
  for (const c of conns) {
    if (!c.remoteAddr || c.scope === "loopback" || c.scope === "unspecified") continue;
    if (c.state !== "ESTABLISHED" && c.state !== "SYN_SENT" && c.state !== "CLOSE_WAIT") continue;
    let k = m.get(c.remoteAddr);
    if (!k) {
      k = { ip: c.remoteAddr, conns: [], pub: c.scope === "public", newest: 0, risk: null, label: c.hostname ?? c.remoteAddr };
      m.set(c.remoteAddr, k);
    }
    k.conns.push(c);
    k.newest = Math.max(k.newest, c.started);
    if (c.hostname) k.label = c.hostname;
    if (c.risk && c.risk !== "INFO" && (!k.risk || SEVERITIES.indexOf(c.risk) > SEVERITIES.indexOf(k.risk))) k.risk = c.risk;
  }
  return [...m.values()];
}

function place(k: Contact, R: number, now: number) {
  const a = hash01(prefix(k.ip)) * TAU + (hash01(k.ip) - 0.5) * 0.35;
  const band = k.pub ? [0.56, 0.95] : [0.18, 0.46];
  const age = Math.min(1, Math.max(0, (now - k.newest) / AGE_SPAN));
  const r = R * (band[1] - (band[1] - band[0]) * age);
  return { a, r };
}

export function Sonar({
  contacts,
  selected,
  onSelect,
}: {
  contacts: Contact[];
  selected: string | null;
  onSelect: (ip: string | null) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const cv = useRef<HTMLCanvasElement>(null);
  const data = useRef({ contacts, selected });
  data.current = { contacts, selected };
  const hovRef = useRef<string | null>(null);
  const [hov, setHov] = useState<{ k: Contact; x: number; y: number } | null>(null);
  const size = useRef({ w: 0, h: 0 });

  useEffect(() => {
    const el = wrap.current!;
    const c = cv.current!;
    const ro = new ResizeObserver(() => {
      const w = el.clientWidth;
      const h = el.clientHeight;
      const dpr = window.devicePixelRatio || 1;
      c.width = w * dpr;
      c.height = h * dpr;
      c.style.width = `${w}px`;
      c.style.height = `${h}px`;
      size.current = { w, h };
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const c = cv.current!;
    const ctx = c.getContext("2d")!;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    const gate = frameGate();
    const frame = (t: number) => {
      raf = requestAnimationFrame(frame);
      if (!gate(t)) return;
      const { w, h } = size.current;
      if (!w) return;
      const dpr = c.width / w;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const cx = w / 2;
      const cy = h / 2;
      const R = Math.min(w, h) / 2 - 18;
      const now = Date.now();
      const { contacts, selected } = data.current;

      // bands
      ctx.fillStyle = "rgba(34,184,255,0.025)";
      ctx.beginPath();
      ctx.arc(cx, cy, R * 0.95, 0, TAU);
      ctx.arc(cx, cy, R * 0.56, 0, TAU, true);
      ctx.fill();
      ctx.strokeStyle = "#1a242c";
      ctx.lineWidth = 1;
      for (const k of [0.18, 0.46, 0.56, 0.95]) {
        ctx.beginPath();
        ctx.arc(cx, cy, R * k, 0, TAU);
        ctx.stroke();
      }
      ctx.strokeStyle = "#141c22";
      for (let i = 0; i < 12; i++) {
        const a = (i / 12) * TAU;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(a) * R * 0.18, cy + Math.sin(a) * R * 0.18);
        ctx.lineTo(cx + Math.cos(a) * R * 0.95, cy + Math.sin(a) * R * 0.95);
        ctx.stroke();
      }
      ctx.fillStyle = "#4a5762";
      ctx.font = "10px 'IBM Plex Sans Condensed'";
      ctx.fillText("yerel ağ", cx + 4, cy - R * 0.46 + 12);
      ctx.fillText("internet", cx + 4, cy - R * 0.95 + 12);

      // pulse ring from the centre (ping)
      if (!reduced) {
        const ph = (t % 3200) / 3200;
        ctx.strokeStyle = `rgba(34,184,255,${(0.35 * (1 - ph)).toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(cx, cy, R * (0.06 + ph * 0.89), 0, TAU);
        ctx.stroke();
      }

      // contacts
      for (const k of contacts) {
        const { a, r } = place(k, R, now);
        const x = cx + Math.cos(a) * r;
        const y = cy + Math.sin(a) * r;
        const sel = selected === k.ip;
        const hv = hovRef.current === k.ip;
        const col = k.risk ? SEV_COLOR[k.risk] : k.pub ? "#22b8ff" : "#5d7f93";
        const dim = selected && !sel ? 0.25 : 1;

        ctx.globalAlpha = dim * (sel || hv ? 0.9 : 0.28);
        ctx.strokeStyle = col;
        ctx.lineWidth = sel ? 1.5 : 1;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(x, y);
        ctx.stroke();

        if (!reduced) {
          // packets travelling along the link; count scales with sockets
          const n = Math.min(3, k.conns.length);
          for (let i = 0; i < n; i++) {
            const ph = (t / (1400 + hash01(k.ip) * 900) + i / n + hash01(k.ip)) % 1;
            const out = i % 2 === 0;
            const f = out ? ph : 1 - ph;
            ctx.globalAlpha = dim * 0.85 * Math.sin(ph * Math.PI);
            ctx.fillStyle = col;
            ctx.fillRect(cx + (x - cx) * f - 1.2, cy + (y - cy) * f - 1.2, 2.4, 2.4);
          }
        }

        ctx.globalAlpha = dim;
        const s = 3 + Math.min(6, Math.sqrt(k.conns.length) * 2);
        ctx.fillStyle = col;
        if (k.risk) {
          ctx.save();
          ctx.translate(x, y);
          ctx.rotate(Math.PI / 4);
          ctx.fillRect(-s / 2, -s / 2, s, s);
          ctx.restore();
        } else {
          ctx.fillRect(x - s / 2, y - s / 2, s, s);
        }
        if (sel || hv) {
          ctx.strokeStyle = "#e8eef2";
          ctx.lineWidth = 1;
          ctx.strokeRect(x - s / 2 - 4, y - s / 2 - 4, s + 8, s + 8);
        }
        if (sel || hv || k.conns.length >= 4 || k.risk) {
          ctx.fillStyle = sel || hv ? "#e8eef2" : "#7a8894";
          ctx.font = "10.5px 'JetBrains Mono'";
          const lbl = k.label.length > 28 ? `…${k.label.slice(-27)}` : k.label;
          const tw = ctx.measureText(lbl).width;
          let right = x > cx;
          if (right && x + s + 6 + tw > w - 4) right = false;
          if (!right && x - s - 6 - tw < 4) right = true;
          ctx.textAlign = right ? "left" : "right";
          ctx.fillText(lbl, x + (right ? s + 6 : -s - 6), y + 3);
          ctx.textAlign = "left";
        }
      }
      ctx.globalAlpha = 1;

      // this machine
      ctx.fillStyle = "#080b0e";
      ctx.strokeStyle = "#3dff9a";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(cx, cy, 9, 0, TAU);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = "#3dff9a";
      ctx.fillRect(cx - 2, cy - 2, 4, 4);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, []);

  function pick(mx: number, my: number): { k: Contact; x: number; y: number } | null {
    const { w, h } = size.current;
    const R = Math.min(w, h) / 2 - 18;
    const now = Date.now();
    let best: Contact | null = null;
    let bd = 12;
    for (const k of data.current.contacts) {
      const { a, r } = place(k, R, now);
      const d = Math.hypot(w / 2 + Math.cos(a) * r - mx, h / 2 + Math.sin(a) * r - my);
      if (d < bd) {
        bd = d;
        best = k;
      }
    }
    return best ? { k: best, x: mx, y: my } : null;
  }

  return (
    <div
      ref={wrap}
      className="sonar"
      onMouseMove={(e) => {
        const b = wrap.current!.getBoundingClientRect();
        const p = pick(e.clientX - b.left, e.clientY - b.top);
        hovRef.current = p?.k.ip ?? null;
        setHov(p);
      }}
      onMouseLeave={() => {
        hovRef.current = null;
        setHov(null);
      }}
      onClick={() => onSelect(hov ? (hov.k.ip === selected ? null : hov.k.ip) : null)}
      style={{ cursor: hov ? "pointer" : "default" }}
    >
      <canvas ref={cv} />
      {hov && (
        <div className="core__tip" style={{ left: hov.x + 14, top: hov.y + 10 }}>
          <b className="mono">{hov.k.ip}</b>
          {hov.k.label !== hov.k.ip && <span>{hov.k.label}</span>}
          <span>
            {[...new Set(hov.k.conns.map((c) => c.processName ?? `PID ${c.pid}`))].join(", ")}
          </span>
          <span className="mono">
            {hov.k.conns.length} soket · port {[...new Set(hov.k.conns.map((c) => c.remotePort))].join(", ")}
          </span>
          {(hov.k.conns[0].country || hov.k.conns[0].asn) && (
            <span>{[hov.k.conns[0].country, hov.k.conns[0].asn].filter(Boolean).join(" · ")}</span>
          )}
        </div>
      )}
    </div>
  );
}
