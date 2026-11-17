// The assistant's body: a crimson point-cloud bust projected above an emitter disc.
// Built procedurally (no image assets): a gaunt face with slit-pupil eyes that burn white,
// light that drips from the eyes, embers rising off the body, long swaying hair. She stares
// at the viewer, twitches now and then, glitches with a colour split, and flares on alerts.
import { useEffect, useRef } from "react";
import type { Severity } from "../ipc/types";
import type { Mode } from "./store";

type Kind =
  | "skin" | "hair" | "strand" | "body" | "eye" | "iris" | "slit" | "brow" | "nose"
  | "lipU" | "lipL" | "seam" | "drip" | "ember";

const GLOW = new Set<Kind>(["iris", "slit"]);

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
const taperX = (dy: number) => (dy < 0 ? 1 - 0.42 * Math.pow(-dy, 1.5) : 1 - 0.06 * dy * dy);
const taperZ = (dy: number) => (dy < 0 ? 1 - 0.18 * -dy : 1);
const g2 = (x: number, y: number, sx: number, sy: number) => Math.exp(-((x / sx) ** 2 + (y / sy) ** 2));

/** Front-face relief: sharp nose, deep sockets, high cheekbones over hollow cheeks, pointed chin. */
function relief(x: number, y: number) {
  const ax = Math.abs(x);
  return (
    0.15 * g2(x, y + 0.06, 0.06, 0.17) +
    0.05 * g2(x, y + 0.2, 0.05, 0.05) -
    0.1 * g2(ax - 0.25, y - 0.1, 0.12, 0.08) +
    0.045 * g2(ax - 0.37, y + 0.05, 0.09, 0.05) -
    0.06 * g2(ax - 0.31, y + 0.33, 0.1, 0.13) +
    0.03 * g2(x, y + 0.45, 0.15, 0.05) +
    0.05 * g2(x, y + 0.85, 0.11, 0.08)
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
    const side = cx < 0 ? -1 : 1;
    for (let t = 0; t <= 1.0001; t += 1 / 30) {
      // Narrow almond, outer corner swept up.
      const x = cx + 0.12 * (2 * t - 1) * side;
      const lift = 0.03 * (2 * t - 1);
      add(x, 0.1 + 0.03 * Math.sin(Math.PI * t) + lift, frontZ(x, 0.1), 1.4, "eye", 1, cx);
      add(x, 0.1 - 0.02 * Math.sin(Math.PI * t) + lift * 0.6, frontZ(x, 0.1), 0.8, "eye", -1, cx);
      // Brows pulled down toward the nose.
      const bx = cx + 0.15 * (2 * t - 1) * side;
      add(bx, 0.18 + 0.09 * t + 0.015 * Math.sin(Math.PI * t), frontZ(bx, 0.22), 0.9, "brow");
    }
    for (let a = 0; a < Math.PI * 2; a += Math.PI / 9) {
      add(cx + Math.cos(a) * 0.026, 0.1 + Math.sin(a) * 0.026, frontZ(cx, 0.1) + 0.01, 0.9, "iris", 0, cx);
    }
    // Vertical slit pupil.
    for (let t = -1; t <= 1.0001; t += 1 / 4) add(cx, 0.1 + t * 0.024, frontZ(cx, 0.1) + 0.012, 1, "slit", 0, cx);
    // Light running down from the lower lid: three trails per eye (p = index along trail, q = phase).
    for (const [dx, ph] of [[-0.05, 0.1], [0.004, 0.55], [0.045, 0.32]] as const)
      for (let j = 0; j < 16; j++) add(cx + dx * side, 0, 0, 1, "drip", j, ph + (cx < 0 ? 0 : 0.21));
  }
  // Embers rising off the shoulders and hair ends (p = phase, q = sway seed).
  for (let i = 0; i < 260; i++) add((rnd() * 2 - 1) * 1.15, 0, (rnd() - 0.3) * 0.5, 1, "ember", rnd(), rnd() * 6.28);
  for (let t = 0; t <= 1.0001; t += 1 / 10) add(0, 0.06 - t * 0.24, frontZ(0, 0.06 - t * 0.24), 0.55, "nose");
  for (const s of [-1, 1])
    for (let t = 0; t <= 1.0001; t += 1 / 6) {
      const x = s * (0.035 + 0.03 * Math.sin(Math.PI * t));
      add(x, -0.215 - 0.012 * Math.cos(Math.PI * t), frontZ(x, -0.215), 0.7, "nose");
    }
  for (let t = -1; t <= 1.0001; t += 1 / 18) {
    const x = t * 0.16;
    add(x, 0, frontZ(x, -0.43), 0.6, "lipU", t);
    add(x, 0, frontZ(x, -0.47), 0.5, "lipL", t);
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
  idle: [230, 22, 44],
  thinking: [255, 40, 110],
  speaking: [255, 52, 60],
  listening: [255, 110, 30],
  MEDIUM: [255, 150, 40],
  HIGH: [255, 70, 20],
  CRITICAL: [255, 225, 220],
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
    // Sudden head twitch every few seconds.
    let twitch = { at: performance.now() + 4000, until: 0, roll: 0, yaw: 0 };
    let tr = 0, ty = 0;
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

      if (!reduced && now > twitch.at) {
        const s = Math.random() < 0.5 ? -1 : 1;
        twitch = { at: now + 4000 + Math.random() * 7000, until: now + 500 + Math.random() * 900, roll: s * (0.1 + Math.random() * 0.1), yaw: -s * Math.random() * 0.12 };
        glitch = { until: now + 140, y0: 0, h: 0, dx: 0 };
      }
      const twitching = now < twitch.until;
      tr += ((twitching ? twitch.roll : 0) - tr) * (twitching ? 0.75 : 0.06);
      ty += ((twitching ? twitch.yaw : 0) - ty) * (twitching ? 0.75 : 0.06);

      // She mostly stares straight out, head slightly tilted.
      const bodyYaw = 0.05 * Math.sin(t * 0.21);
      const headYaw = bodyYaw + ty + (md === "listening" ? 0 : 0.07 * Math.sin(t * 0.33 + 1));
      const headPitch = 0.05 + 0.03 * Math.sin(t * 0.5) + mouth * 0.03 + (md === "thinking" ? -0.06 : 0);
      const headRoll = 0.07 + 0.02 * Math.sin(t * 0.27 + 2) + tr;
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
        } else if (k === "ember") {
          head = false;
          const f = (t * 0.07 + g.p[i]) % 1;
          y = -2.3 + f * 2.9;
          x = g.x[i] * (1 - f * 0.4) + 0.07 * Math.sin(t * 0.8 + g.q[i] + f * 6);
          bright = 0.5 * Math.sin(Math.PI * f) * (0.6 + 0.4 * Math.sin(t * 5 + g.q[i]));
        } else if (k === "drip") {
          const f = ((t * 0.09 + g.q[i]) % 1) - g.p[i] * 0.013;
          if (f < 0) {
            bright = 0;
          } else {
            y = 0.075 - f * 0.62;
            x = g.x[i] + 0.006 * Math.sin(f * 11 + g.q[i] * 9);
            z = frontZ(x, y) + 0.012;
            bright = 0.95 * (1 - g.p[i] / 16) * Math.pow(1 - f, 1.4);
          }
        } else if (k === "strand") {
          const st = g.p[i];
          x += 0.05 * Math.sin(t * 0.9 + g.q[i] + st * 2.2) * st;
          z += 0.03 * Math.cos(t * 0.7 + g.q[i]) * st;
        } else if (k === "lipU") {
          const u = g.p[i];
          y = -0.428 + 0.004 * u * u + 0.006 * Math.exp(-((u / 0.18) ** 2)) + mouth * 0.018 * (1 - u * u);
        } else if (k === "lipL") {
          const u = g.p[i];
          y = -0.465 + 0.005 * u * u - 0.022 * (1 - u * u) - mouth * 0.09 * (1 - u * u);
        } else if (k === "seam") {
          const u = g.p[i];
          y = -0.452 + 0.012 * u * u - mouth * 0.035 * (1 - u * u);
          bright = 0.6 - mouth * 0.5;
        } else if (k === "eye") {
          const cyEye = 0.1;
          y = cyEye + (y - cyEye) * blink;
        } else if (k === "iris" || k === "slit") {
          x += gaze.x;
          y = 0.1 + (y - 0.1) * blink + gaze.y;
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
      } else if (!reduced && Math.random() < 0.006) {
        glitch = { until: now + 120, y0: Math.random() * Hh, h: Hh * 0.05, dx: (Math.random() - 0.5) * W * 0.05 };
      }
      const flicker = reduced ? 1 : 0.88 + 0.12 * Math.sin(t * 37) * Math.sin(t * 13);

      ctx.globalCompositeOperation = "lighter";
      const size = Math.max(1, W / 240);
      const glitching = now < glitch.until;
      const split = glitching ? size * 3 : size * 1.2;
      const pass = (style: string, dx: number, alpha: number, glowOnly: boolean) => {
        ctx.fillStyle = style;
        for (let i = 0; i < g.n; i++) {
          const k = g.k[i];
          if (GLOW.has(k) !== glowOnly) continue;
          const a = sa[i] * flicker * alpha;
          if (a < 0.03) continue;
          let px = sx[i] + dx;
          if (glitching && sy[i] > glitch.y0 && sy[i] < glitch.y0 + glitch.h) px += glitch.dx;
          const s = k === "iris" || k === "slit" ? size * 1.5 : k === "eye" || k === "lipU" || k === "lipL" || k === "drip" ? size * 1.25 : size;
          ctx.globalAlpha = Math.min(1, a);
          ctx.fillRect(px - s / 2, sy[i] - s / 2, s, s);
        }
      };
      // Colour split: a faint cold ghost offset from the body, stronger while glitching.
      pass("rgb(40,170,255)", split, glitching ? 0.4 : 0.14, false);
      pass(`rgb(${rgb})`, 0, 1, false);
      // Eyes burn near-white over the red.
      pass("rgb(255,236,228)", 0, 1, true);
      ctx.globalAlpha = 1;

      // Eye glow (one per eye), brighter on alerts and while speaking.
      const flare = (al === "CRITICAL" || al === "HIGH" ? 1.8 : 1) * (0.8 + mouth * 0.8);
      const lit = new Set<number>();
      for (let i = 0; i < g.n; i++) {
        if (g.k[i] !== "slit" || sa[i] < 0.5 || lit.has(g.q[i])) continue;
        lit.add(g.q[i]);
        const R = size * 11;
        const gr = ctx.createRadialGradient(sx[i], sy[i], 0, sx[i], sy[i], R);
        gr.addColorStop(0, `rgba(255,90,80,${Math.min(0.6, 0.32 * flare * flicker)})`);
        gr.addColorStop(0.35, `rgba(${rgb},${Math.min(0.3, 0.12 * flare)})`);
        gr.addColorStop(1, `rgba(${rgb},0)`);
        ctx.fillStyle = gr;
        ctx.fillRect(sx[i] - R, sy[i] - R, R * 2, R * 2);
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
