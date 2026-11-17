// The assistant's body: a point-cloud bust projected above an emitter disc.
// Built procedurally (no image assets): an ellipsoid head shaped into a face, long hair
// strands that sway, neck and shoulders that breathe. Lips follow the voice loudness,
// eyes blink and drift, and the whole figure re-tints and glitches when an alert comes in.
import { useEffect, useRef } from "react";
import type { Severity } from "../ipc/types";
import type { Mode } from "./store";

type Kind = "skin" | "hair" | "strand" | "body" | "eye" | "iris" | "brow" | "nose" | "lipU" | "lipL" | "seam";

interface Geo {
  x: Float32Array;
  y: Float32Array;
  z: Float32Array;
  b: Float32Array; // base brightness
  p: Float32Array; // per-point parameter (strand t, lip x, phase)
  q: Float32Array; // second parameter (strand phase)
  k: Kind[];
  n: number;
}

const A = 0.72, B = 0.95, C = 0.82;
const taperX = (dy: number) => (dy < 0 ? 1 - 0.36 * Math.pow(-dy, 1.6) : 1 - 0.06 * dy * dy);
const taperZ = (dy: number) => (dy < 0 ? 1 - 0.18 * -dy : 1);
const g2 = (x: number, y: number, sx: number, sy: number) => Math.exp(-((x / sx) ** 2 + (y / sy) ** 2));

/** Front-face relief: nose, eye sockets, lips, chin. */
function relief(x: number, y: number) {
  return (
    0.15 * g2(x, y + 0.06, 0.07, 0.17) +
    0.05 * g2(x, y + 0.2, 0.06, 0.05) -
    0.06 * g2(Math.abs(x) - 0.25, y - 0.1, 0.11, 0.07) +
    0.035 * g2(x, y + 0.45, 0.17, 0.06) +
    0.04 * g2(x, y + 0.82, 0.15, 0.08)
  );
}

/** z of the face surface at (x, y), for placing features on it. */
function frontZ(x: number, y: number) {
  const dy = y / B;
  const dx = x / (A * taperX(dy));
  const dz = Math.sqrt(Math.max(0, 1 - dx * dx - dy * dy));
  return dz * C * taperZ(dy) + relief(x, y) + 0.008;
}

function build(): Geo {
  const pts: [number, number, number, number, Kind, number, number][] = [];
  const add = (x: number, y: number, z: number, b: number, k: Kind, p = 0, q = 0) => pts.push([x, y, z, b, k, p, q]);
  const golden = Math.PI * (3 - Math.sqrt(5));
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);

  // Head surface (Fibonacci sphere → shaped ellipsoid).
  const N = 1700;
  for (let i = 0; i < N; i++) {
    const dy = 1 - (i / (N - 1)) * 2;
    const r = Math.sqrt(1 - dy * dy);
    const th = golden * i;
    const dx = Math.cos(th) * r, dz = Math.sin(th) * r;
    if (dy < -0.93) continue; // open where the neck joins
    const x = dx * A * taperX(dy), y = dy * B;
    let z = dz * C * taperZ(dy);
    if (dz > 0) z += relief(x, y) * Math.min(1, dz * 2);
    add(x, y, z, dz > 0.35 ? 0.5 : 0.28, "skin");
  }

  // Hair cap: a shell over the crown, back and sides, leaving the face open.
  const H = 1500;
  for (let i = 0; i < H; i++) {
    const dy = 1 - (i / (H - 1)) * 2;
    const r = Math.sqrt(1 - dy * dy);
    const th = golden * i;
    const dx = Math.cos(th) * r, dz = Math.sin(th) * r;
    const crown = dy > 0.5;
    const sides = dy > -0.5 && (dz < 0.12 || Math.abs(dx) > 0.8);
    // Side-swept fringe: lower on the left of the face than on the right.
    const fringe = dz > 0 && dy > 0.36 + 0.14 * (dx + 0.6);
    if (!(crown || sides || fringe)) continue;
    const s = 1.08 + 0.03 * rnd();
    add(dx * A * taperX(dy) * s, dy * B * s + 0.03, dz * C * taperZ(dy) * s, 0.36, "hair");
  }

  // Long strands falling from the back and sides past the shoulders.
  for (let j = 0; j < 84; j++) {
    const ang = (-150 + (300 * j) / 83) * (Math.PI / 180) + Math.PI; // around the back
    const front = Math.cos(ang) > 0.55; // skip the face side
    if (front) continue;
    const sx = Math.sin(ang), sz = Math.cos(ang);
    const phase = rnd() * Math.PI * 2;
    const len = 1.35 + rnd() * 0.5;
    for (let t = 0; t <= 1.0001; t += 1 / 22) {
      const rad = 0.62 + 0.38 * t + 0.05 * Math.sin(t * 7 + phase);
      add(sx * rad, -0.25 - t * len, sz * rad * 0.9 - 0.05, 0.34 * (1 - t * 0.55), "strand", t, phase);
    }
  }

  // Neck.
  for (let i = 0; i < 170; i++) {
    const a = (i * golden) % (Math.PI * 2);
    const y = -0.72 - (i / 170) * 0.68;
    add(Math.cos(a) * 0.25, y, Math.sin(a) * 0.23, Math.sin(a) > 0 ? 0.32 : 0.18, "body");
  }

  // Shoulders and upper chest: superellipse slices that widen below the neck.
  const smooth = (e0: number, e1: number, v: number) => {
    const t = Math.min(1, Math.max(0, (v - e0) / (e1 - e0)));
    return t * t * (3 - 2 * t);
  };
  for (let i = 0; i < 900; i++) {
    const y = -1.32 - rnd() * 0.98;
    const w = 0.27 + 1.12 * smooth(-1.3, -1.78, y);
    const d = 0.24 + 0.24 * smooth(-1.3, -1.78, y);
    const a = rnd() * Math.PI * 2;
    const c = Math.cos(a), s = Math.sin(a);
    const x = w * Math.sign(c) * Math.pow(Math.abs(c), 0.55);
    const z = d * Math.sign(s) * Math.pow(Math.abs(s), 0.55);
    const fade = 1 - smooth(-1.75, -2.3, y);
    add(x, y, z, (s > 0 ? 0.34 : 0.16) * fade, "body");
  }
  // Neckline and collarbones.
  for (let t = -1; t <= 1.001; t += 0.04) {
    add(t * 0.36, -1.48 - (1 - Math.abs(t)) * 0.24, 0.42 - 0.04 * Math.abs(t), 0.7, "body");
    add(t * 0.85, -1.55 + 0.05 * Math.abs(t), 0.43 - 0.15 * Math.abs(t), 0.45, "body");
  }

  // Face features on the surface.
  for (const cx of [-0.25, 0.25]) {
    for (let t = 0; t <= 1.0001; t += 1 / 30) {
      const x = cx + 0.115 * (2 * t - 1) * (cx < 0 ? -1 : 1);
      const lift = 0.012 * (2 * t - 1); // outer corner slightly higher
      add(x, 0.1 + 0.046 * Math.sin(Math.PI * t) + lift, frontZ(x, 0.1), 1, "eye", 1, cx);
      add(x, 0.1 - 0.028 * Math.sin(Math.PI * t) + lift, frontZ(x, 0.1), 0.75, "eye", -1, cx);
      const bx = cx + 0.14 * (2 * t - 1) * (cx < 0 ? -1 : 1);
      add(bx, 0.235 + 0.035 * Math.sin(Math.PI * (t * 0.85 + 0.1)) - 0.01 * t, frontZ(bx, 0.24), 0.8, "brow");
    }
    for (let a = 0; a < Math.PI * 2; a += Math.PI / 9) {
      add(cx + Math.cos(a) * 0.03, 0.105 + Math.sin(a) * 0.03, frontZ(cx, 0.1) + 0.01, 1, "iris", 0, cx);
    }
  }
  for (let t = 0; t <= 1.0001; t += 1 / 10) add(0, 0.06 - t * 0.24, frontZ(0, 0.06 - t * 0.24), 0.55, "nose");
  for (const s of [-1, 1])
    for (let t = 0; t <= 1.0001; t += 1 / 6) {
      const x = s * (0.035 + 0.03 * Math.sin(Math.PI * t));
      add(x, -0.215 - 0.012 * Math.cos(Math.PI * t), frontZ(x, -0.215), 0.7, "nose");
    }
  for (let t = -1; t <= 1.0001; t += 1 / 18) {
    const x = t * 0.16;
    add(x, 0, frontZ(x, -0.43), 0.95, "lipU", t);
    add(x, 0, frontZ(x, -0.47), 0.85, "lipL", t);
    add(x, 0, frontZ(x, -0.45), 0.6, "seam", t);
  }

  const n = pts.length;
  const geo: Geo = {
    x: new Float32Array(n), y: new Float32Array(n), z: new Float32Array(n),
    b: new Float32Array(n), p: new Float32Array(n), q: new Float32Array(n), k: new Array(n), n,
  };
  pts.forEach(([x, y, z, b, k, p, q], i) => {
    geo.x[i] = x; geo.y[i] = y; geo.z[i] = z; geo.b[i] = b; geo.k[i] = k; geo.p[i] = p; geo.q[i] = q;
  });
  return geo;
}

let GEO: Geo | null = null;

const TINT: Record<string, [number, number, number]> = {
  idle: [34, 184, 255],
  thinking: [90, 205, 255],
  speaking: [130, 220, 255],
  listening: [61, 255, 154],
  MEDIUM: [255, 181, 71],
  HIGH: [255, 122, 61],
  CRITICAL: [255, 61, 78],
};

export function Hologram({
  mode,
  alert,
  level,
}: {
  mode: Mode;
  alert: Severity | null;
  level: () => number;
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const live = useRef({ mode, alert, level });
  live.current = { mode, alert, level };

  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    GEO ??= build();
    const g = GEO;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let last = 0;
    let mouth = 0;
    let blinkAt = performance.now() + 2500;
    let gaze = { x: 0, y: 0, tx: 0, ty: 0, next: 0 };
    let glitch = { until: 0, y0: 0, h: 0, dx: 0 };
    let lastAlert: Severity | null = null;
    const tint = [...TINT.idle];
    const sx = new Float32Array(g.n), sy = new Float32Array(g.n), sa = new Float32Array(g.n);

    const resize = () => {
      const r = cv.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      cv.width = Math.max(1, Math.round(r.width * dpr));
      cv.height = Math.max(1, Math.round(r.height * dpr));
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(cv);

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw);
      if (document.hidden) return;
      const fps = document.hasFocus() ? 30 : 10;
      if (now - last < 1000 / fps - 1) return;
      last = now;
      const { mode: md, alert: al, level: lv } = live.current;
      const t = reduced ? 0 : now / 1000;
      const W = cv.width, Hh = cv.height;

      // Colour eases toward the current state.
      const want = TINT[al ?? md] ?? TINT.idle;
      for (let i = 0; i < 3; i++) tint[i] += (want[i] - tint[i]) * 0.12;
      if (al && al !== lastAlert) glitch = { until: now + 900, y0: 0, h: 0, dx: 0 };
      lastAlert = al;

      const target = md === "speaking" ? lv() : 0;
      mouth += (target - mouth) * 0.5;

      // Eyes: blink every few seconds, small saccades.
      let blink = 1;
      if (now > blinkAt) {
        const k = (now - blinkAt) / 150;
        blink = k < 1 ? Math.abs(1 - 2 * k) : 1;
        if (k >= 1) blinkAt = now + 2500 + Math.random() * 4000;
      }
      if (now > gaze.next) {
        gaze.tx = md === "listening" ? 0 : (Math.random() - 0.5) * 0.02;
        gaze.ty = (Math.random() - 0.5) * 0.012;
        gaze.next = now + 900 + Math.random() * 2200;
      }
      gaze.x += (gaze.tx - gaze.x) * 0.25;
      gaze.y += (gaze.ty - gaze.y) * 0.25;

      const bodyYaw = 0.1 * Math.sin(t * 0.21);
      const headYaw = bodyYaw + (md === "listening" ? 0 : 0.2 * Math.sin(t * 0.33 + 1));
      const headPitch = 0.05 * Math.sin(t * 0.5) + mouth * 0.03 + (md === "thinking" ? -0.06 : 0);
      const headRoll = 0.03 * Math.sin(t * 0.27 + 2);
      const breathe = Math.sin(t * 1.3);

      const D = 5.5;
      const scale = Math.min(W / 3.2, Hh / 3.9);
      const cx = W / 2, cy = Hh * 0.36;
      const ch = Math.cos(headYaw), shh = Math.sin(headYaw);
      const cp = Math.cos(headPitch), sp = Math.sin(headPitch);
      const cr = Math.cos(headRoll), sr = Math.sin(headRoll);
      const cb = Math.cos(bodyYaw), sb = Math.sin(bodyYaw);
      const scanY = ((t * (md === "thinking" ? 0.9 : 0.32)) % 1.4) * 3.6 - 2.5;

      for (let i = 0; i < g.n; i++) {
        let x = g.x[i], y = g.y[i], z = g.z[i];
        const k = g.k[i];
        let bright = g.b[i];
        let head = true;
        if (k === "body") {
          head = false;
          y += 0.012 * breathe * (y < -1.3 ? 1 : 0.4);
        } else if (k === "strand") {
          const st = g.p[i];
          x += 0.05 * Math.sin(t * 0.9 + g.q[i] + st * 2.2) * st;
          z += 0.03 * Math.cos(t * 0.7 + g.q[i]) * st;
        } else if (k === "lipU") {
          const u = g.p[i];
          y = -0.428 - 0.018 * u * u + 0.006 * Math.exp(-((u / 0.18) ** 2)) + mouth * 0.018 * (1 - u * u);
        } else if (k === "lipL") {
          const u = g.p[i];
          y = -0.47 - 0.025 * (1 - u * u) - mouth * 0.085 * (1 - u * u);
        } else if (k === "seam") {
          const u = g.p[i];
          y = -0.452 - mouth * 0.035 * (1 - u * u);
          bright = 0.6 - mouth * 0.5;
        } else if (k === "eye") {
          const cyEye = 0.1;
          y = cyEye + (y - cyEye) * blink;
        } else if (k === "iris") {
          x += gaze.x;
          y = 0.105 + (y - 0.105) * blink + gaze.y;
          bright = blink < 0.4 ? 0 : 1;
        }
        // Strands follow the head near the scalp and the body further down.
        const w = k === "strand" ? 1 - g.p[i] * 0.85 : head ? 1 : 0;
        // Head transform: roll, pitch, yaw around the neck pivot.
        let hx = x, hy = y + 0.75, hz = z;
        let t1 = hx * cr - hy * sr;
        hy = hx * sr + hy * cr;
        hx = t1;
        t1 = hy * cp - hz * sp;
        hz = hy * sp + hz * cp;
        hy = t1;
        t1 = hx * ch + hz * shh;
        hz = -hx * shh + hz * ch;
        hx = t1;
        hy -= 0.75;
        // Body transform: yaw only.
        const bx = x * cb + z * sb, bz = -x * sb + z * cb;
        const X = hx * w + bx * (1 - w), Y = hy * w + y * (1 - w), Z = hz * w + bz * (1 - w);

        const f = D / (D - Z);
        sx[i] = cx + X * f * scale;
        sy[i] = cy - (Y - 0.15) * f * scale;
        const depth = 0.45 + 0.55 * Math.min(1, Math.max(0, (Z + 0.9) / 1.8));
        const band = Math.exp(-(((Y - scanY) / 0.08) ** 2)) * 0.6;
        sa[i] = Math.min(1, bright * depth + band * bright);
      }

      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, W, Hh);
      const [r, gg, bb] = tint.map(Math.round);
      const rgb = `${r},${gg},${bb}`;

      // Emitter disc and light column.
      const baseY = Hh * 0.95;
      const col = ctx.createLinearGradient(0, baseY, 0, Hh * 0.25);
      col.addColorStop(0, `rgba(${rgb},0.16)`);
      col.addColorStop(1, `rgba(${rgb},0)`);
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.moveTo(cx - W * 0.2, baseY);
      ctx.lineTo(cx + W * 0.2, baseY);
      ctx.lineTo(cx + W * 0.42, Hh * 0.25);
      ctx.lineTo(cx - W * 0.42, Hh * 0.25);
      ctx.fill();
      ctx.strokeStyle = `rgba(${rgb},0.55)`;
      ctx.lineWidth = Math.max(1, W / 260);
      ctx.beginPath();
      ctx.ellipse(cx, baseY, W * 0.22, W * 0.035, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([W * 0.02, W * 0.03]);
      ctx.lineDashOffset = -t * W * 0.05;
      ctx.beginPath();
      ctx.ellipse(cx, baseY, W * 0.3, W * 0.05, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      // Glitch: a horizontal slice jumps sideways (always on alerts, rarely otherwise).
      if (!reduced && now < glitch.until) {
        if (Math.random() < 0.35) glitch = { ...glitch, y0: Math.random() * Hh, h: Hh * (0.03 + Math.random() * 0.08), dx: (Math.random() - 0.5) * W * 0.08 };
      } else if (!reduced && Math.random() < 0.002) {
        glitch = { until: now + 120, y0: Math.random() * Hh, h: Hh * 0.05, dx: (Math.random() - 0.5) * W * 0.05 };
      }
      const flicker = reduced ? 1 : 0.9 + 0.1 * Math.sin(t * 37) * Math.sin(t * 13);

      ctx.globalCompositeOperation = "lighter";
      ctx.fillStyle = `rgb(${rgb})`;
      const size = Math.max(1, W / 240);
      for (let i = 0; i < g.n; i++) {
        const a = sa[i] * flicker;
        if (a < 0.03) continue;
        let px = sx[i];
        if (now < glitch.until && sy[i] > glitch.y0 && sy[i] < glitch.y0 + glitch.h) px += glitch.dx;
        const k = g.k[i];
        const s = k === "iris" ? size * 1.6 : k === "eye" || k === "lipU" || k === "lipL" ? size * 1.25 : size;
        ctx.globalAlpha = a;
        ctx.fillRect(px - s / 2, sy[i] - s / 2, s, s);
      }
      ctx.globalAlpha = 1;

      // Glowing irises (one glow per eye).
      const lit = new Set<number>();
      for (let i = 0; i < g.n; i++) {
        if (g.k[i] !== "iris" || sa[i] < 0.5 || lit.has(g.q[i])) continue;
        lit.add(g.q[i]);
        const gr = ctx.createRadialGradient(sx[i], sy[i], 0, sx[i], sy[i], size * 6);
        gr.addColorStop(0, `rgba(${rgb},0.12)`);
        gr.addColorStop(1, `rgba(${rgb},0)`);
        ctx.fillStyle = gr;
        ctx.fillRect(sx[i] - size * 6, sy[i] - size * 6, size * 12, size * 12);
      }
      ctx.globalCompositeOperation = "source-over";

      // Scanlines.
      ctx.globalCompositeOperation = "destination-out";
      ctx.fillStyle = "rgba(0,0,0,0.35)";
      const step = Math.max(2, Math.round(Hh / 160));
      const off = reduced ? 0 : Math.floor(t * 20) % step;
      for (let y = off; y < Hh; y += step) ctx.fillRect(0, y, W, 1);
      ctx.globalCompositeOperation = "source-over";
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return <canvas ref={ref} className="ayla-holo" aria-hidden="true" />;
}
