// The assistant's body: a crimson point-cloud demon projected above an emitter, with a
// turning sigil behind her. Built procedurally (no image assets): a gaunt horned face with
// slit-pupil eyes that burn white, light dripping from the eyes, long wild hair, a collar
// and chains, embers rising off the body and, on the big stage, a clawed hand reaching
// toward the viewer. She stares out, twitches now and then, glitches with a colour split,
// her lips follow the voice and she flares on alerts.
import { useEffect, useRef } from "react";
import type { Severity } from "../ipc/types";
import type { Mode } from "./store";

type Kind =
  | "skin" | "hair" | "strand" | "body" | "eye" | "iris" | "slit" | "brow" | "nose"
  | "lipU" | "lipL" | "seam" | "drip" | "ember" | "horn" | "collar" | "arm" | "claw";

const GLOW = new Set<Kind>(["iris", "slit"]);
/** Kinds that follow the body; everything else moves with the head. */
const BODY = new Set<Kind>(["body", "ember", "collar", "arm", "claw"]);

type V3 = [number, number, number];
const sub = (a: V3, b: V3): V3 => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const cross = (a: V3, b: V3): V3 => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const norm = (a: V3): V3 => {
  const l = Math.hypot(a[0], a[1], a[2]) || 1;
  return [a[0] / l, a[1] / l, a[2] / l];
};
const mix = (a: V3, b: V3, t: number): V3 => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
const along = (p: V3, d: V3, k: number): V3 => [p[0] + d[0] * k, p[1] + d[1] * k, p[2] + d[2] * k];
const turn = (a: V3, b: V3, ang: number): V3 =>
  norm([a[0] * Math.cos(ang) + b[0] * Math.sin(ang), a[1] * Math.cos(ang) + b[1] * Math.sin(ang), a[2] * Math.cos(ang) + b[2] * Math.sin(ang)]);

interface Geo {
  x: Float32Array;
  y: Float32Array;
  z: Float32Array;
  b: Float32Array; // base brightness
  p: Float32Array; // per-point parameter (strand t, lip x, phase, arm reach weight)
  q: Float32Array; // second parameter (strand phase, eye centre)
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

/** Points on rings around a curved centre line. `emit` gets the point, the position along
 *  the line, how much the surface faces the viewer, and the ring index. */
function tube(
  path: (s: number) => V3,
  radius: (s: number) => number,
  steps: number,
  around: number,
  emit: (p: V3, s: number, facing: number, ring: number) => void,
) {
  const r0 = radius(0);
  for (let i = 0; i <= steps; i++) {
    const s = i / steps;
    const c = path(s);
    const T = norm(sub(path(Math.min(1, s + 0.01)), path(Math.max(0, s - 0.01))));
    const N = norm(cross(T, Math.abs(T[1]) < 0.9 ? [0, 1, 0] : [1, 0, 0]));
    const M = cross(T, N);
    const r = radius(s);
    const n = Math.max(4, Math.round(around * Math.max(0.3, r / r0)));
    for (let k = 0; k < n; k++) {
      const a = (k / n) * Math.PI * 2 + i * 0.37;
      const ca = Math.cos(a), sa = Math.sin(a);
      const d: V3 = [ca * N[0] + sa * M[0], ca * N[1] + sa * M[1], ca * N[2] + sa * M[2]];
      emit(along(c, d, r), s, d[2], i);
    }
  }
}

function build(stage: boolean): Geo {
  const pts: [number, number, number, number, Kind, number, number][] = [];
  const add = (x: number, y: number, z: number, b: number, k: Kind, p = 0, q = 0) => pts.push([x, y, z, b, k, p, q]);
  const addV = (v: V3, b: number, k: Kind, p = 0, q = 0) => add(v[0], v[1], v[2], b, k, p, q);
  const golden = Math.PI * (3 - Math.sqrt(5));
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const smooth = (e0: number, e1: number, v: number) => {
    const t = Math.min(1, Math.max(0, (v - e0) / (e1 - e0)));
    return t * t * (3 - 2 * t);
  };

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

  // Hair cap with a centre parting, leaving the face open.
  const H = 1500;
  for (let i = 0; i < H; i++) {
    const dy = 1 - (i / (H - 1)) * 2;
    const r = Math.sqrt(1 - dy * dy);
    const th = golden * i;
    const dx = Math.cos(th) * r, dz = Math.sin(th) * r;
    const parting = dz > 0.2 && Math.abs(dx) < 0.05;
    const crown = dy > 0.5 && !parting;
    const sides = dy > -0.55 && (dz < 0.12 || Math.abs(dx) > 0.78);
    const fringe = dz > 0 && dy > 0.42 && !parting;
    if (!(crown || sides || fringe)) continue;
    const s = 1.08 + 0.04 * rnd();
    add(dx * A * taperX(dy) * s, dy * B * s + 0.03, dz * C * taperZ(dy) * s, 0.36, "hair");
  }

  // Long wild strands: most fall down the back, some spill forward over the shoulders.
  const strands = stage ? 120 : 90;
  for (let j = 0; j < strands; j++) {
    const ang = (-165 + (330 * j) / (strands - 1)) * (Math.PI / 180) + Math.PI;
    if (Math.cos(ang) > 0.45) continue; // keep the face clear
    const sx = Math.sin(ang), sz = Math.cos(ang);
    const forward = Math.abs(sx) > 0.85 && sz > -0.3 ? 0.35 + rnd() * 0.25 : 0;
    const phase = rnd() * Math.PI * 2;
    const len = 1.7 + rnd() * 0.7;
    const top = 0.1 + rnd() * 0.35;
    for (let t = 0; t <= 1.0001; t += 1 / 24) {
      const rad = 0.66 + 0.5 * t + 0.08 * Math.sin(t * 8 + phase);
      add(sx * rad, top - t * len - 0.25, sz * rad * 0.9 - 0.05 + forward * t, 0.34 * (1 - t * 0.5), "strand", t, phase);
    }
  }

  // Horns: thick at the temple, sweeping up and out, tips curling back in.
  for (const side of [-1, 1]) {
    tube(
      (s) => [side * (0.3 + 0.95 * s - 0.78 * s * s), 0.68 + 1.12 * s - 0.12 * s * s, 0.3 - 0.22 * s - 0.38 * s * s],
      (s) => 0.12 * Math.pow(1 - s, 0.8) + 0.006,
      32,
      16,
      (p, s, facing, ring) => addV(p, (ring % 4 === 0 ? 0.8 : 0.42) * (0.65 + 0.35 * facing) + 0.25 * s, "horn"),
    );
  }

  // Neck.
  for (let i = 0; i < 170; i++) {
    const a = (i * golden) % (Math.PI * 2);
    const y = -0.72 - (i / 170) * 0.68;
    add(Math.cos(a) * 0.25, y, Math.sin(a) * 0.23, Math.sin(a) > 0 ? 0.32 : 0.18, "body");
  }
  // Collar with studs and a pendant.
  for (let i = 0; i < 64; i++) {
    const a = (i / 64) * Math.PI * 2;
    for (const [y, r] of [[-1.0, 0.275], [-1.09, 0.28]] as const)
      add(Math.cos(a) * r, y, Math.sin(a) * r * 0.93, Math.sin(a) > 0 ? 0.85 : 0.3, "collar");
    if (i % 4 === 0) add(Math.cos(a) * 0.29, -1.045, Math.sin(a) * 0.27, Math.sin(a) > 0 ? 1 : 0.3, "collar");
  }
  for (let t = 0; t <= 1.0001; t += 1 / 14) {
    add(-0.07 + 0.07 * t, -1.14 - 0.17 * t, 0.3, 0.95, "collar");
    add(0.07 - 0.07 * t, -1.14 - 0.17 * t, 0.3, 0.95, "collar");
    add(-0.07 + 0.14 * t, -1.14, 0.3, 0.95, "collar");
  }

  // Shoulders and upper chest: superellipse slices that widen below the neck.
  const bodyPts = stage ? 1300 : 900;
  const depthBelow = stage ? 1.35 : 0.98;
  for (let i = 0; i < bodyPts; i++) {
    const y = -1.32 - rnd() * depthBelow;
    const w = 0.27 + 1.15 * smooth(-1.3, -1.78, y) - 0.25 * smooth(-2.0, -2.6, y);
    const d = 0.24 + 0.24 * smooth(-1.3, -1.78, y);
    const a = rnd() * Math.PI * 2;
    const c = Math.cos(a), s = Math.sin(a);
    const x = w * Math.sign(c) * Math.pow(Math.abs(c), 0.55);
    const z = d * Math.sign(s) * Math.pow(Math.abs(s), 0.55);
    const fade = 1 - smooth(stage ? -2.2 : -1.75, stage ? -2.67 : -2.3, y);
    add(x, y, z, (s > 0 ? 0.32 : 0.15) * fade, "body");
  }
  // Collarbones.
  for (let t = -1; t <= 1.001; t += 0.04) add(t * 0.85, -1.55 + 0.05 * Math.abs(t), 0.43 - 0.15 * Math.abs(t), 0.4, "body");
  // Chains: from the collar to a ring on the sternum, then down and out.
  const ring: V3 = [0, -1.62, 0.47];
  const chain = (a: V3, b: V3, sag: number) => {
    const n = Math.round(Math.hypot(...sub(b, a)) / 0.028);
    for (let i = 0; i <= n; i++) {
      const t = i / n;
      const p = mix(a, b, t);
      p[1] -= sag * Math.sin(Math.PI * t);
      add(p[0], p[1], p[2], i % 2 ? 0.95 : 0.45, "collar");
    }
  };
  chain([-0.24, -1.1, 0.16], ring, 0.06);
  chain([0.24, -1.1, 0.16], ring, 0.06);
  if (stage) {
    chain(ring, [-0.62, -2.25, 0.36], 0.05);
    chain(ring, [0.62, -2.25, 0.36], 0.05);
  }
  for (let i = 0; i < 18; i++) {
    const a = (i / 18) * Math.PI * 2;
    add(ring[0] + Math.cos(a) * 0.045, ring[1] + Math.sin(a) * 0.045, ring[2] + 0.01, 1, "collar");
  }

  // Stage only: her right arm reaching toward the viewer, ending in a clawed hand (p = reach weight).
  if (stage) {
    const S: V3 = [-0.95, -1.62, 0.05], E: V3 = [-1.42, -2.0, 0.7], W: V3 = [-1.25, -1.55, 1.55];
    const arm = (s: number): V3 => mix(mix(S, E, s), mix(E, W, s), s);
    tube(arm, (s) => 0.14 - 0.065 * s, 40, 18, (p, s, facing, i) => {
      const bracer = s > 0.74 && s < 0.86;
      addV(p, bracer ? (i % 2 ? 0.95 : 0.55) : 0.22 + 0.2 * Math.max(0, facing), bracer ? "claw" : "arm", s * s);
    });
    const f = norm(sub(W, E));
    const u = norm(cross(f, [0, 1, 0]));
    const v = cross(u, f);
    const P = along(W, f, 0.05);
    // Palm: a slightly cupped disc facing the viewer.
    for (let i = 0; i < 140; i++) {
      const r = Math.sqrt(rnd()), a = rnd() * Math.PI * 2;
      const pu = Math.cos(a) * r * 0.13, pv = Math.sin(a) * r * 0.15 + 0.04;
      addV(along(along(along(P, u, pu), v, pv), f, -0.03 * r * r), 0.42, "arm", 1);
    }
    const digit = (base: V3, dir0: V3, len: number, curl: number, r0: number) => {
      const path = (s: number): V3 => along(base, mix(dir0, turn(dir0, f, curl * s), 0.5), len * s);
      tube(path, (s) => r0 * (1 - 0.3 * s), 12, 8, (p) => addV(p, 0.45, "arm", 1));
      const tip = path(1);
      const clawDir = norm(mix(norm(sub(tip, path(0.9))), f, 0.45));
      tube((s) => along(tip, norm(mix(clawDir, f, 0.6 * s)), 0.17 * s), (s) => r0 * 0.85 * (1 - s) + 0.003, 10, 7, (p) =>
        addV(p, 0.95, "claw", 1),
      );
    };
    // Four fingers spread up and out, curling toward the viewer, then long claws; then the thumb.
    for (const [off, spread, len] of [[0.1, 0.42, 0.27], [0.035, 0.12, 0.33], [-0.035, -0.12, 0.31], [-0.1, -0.38, 0.25]] as const)
      digit(along(along(P, u, off), v, 0.17), turn(v, u, spread), len, 0.7, 0.028);
    digit(along(along(P, u, -0.14), v, -0.03), norm(mix(v, [-u[0], -u[1], -u[2]], 0.65)), 0.2, 0.5, 0.032);
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
  for (let t = 0; t <= 1.0001; t += 1 / 10) add(0, 0.06 - t * 0.24, frontZ(0, 0.06 - t * 0.24), 0.55, "nose");
  for (const s of [-1, 1])
    for (let t = 0; t <= 1.0001; t += 1 / 6) {
      const x = s * (0.035 + 0.03 * Math.sin(Math.PI * t));
      add(x, -0.215 - 0.012 * Math.cos(Math.PI * t), frontZ(x, -0.215), 0.7, "nose");
    }
  for (let t = -1; t <= 1.0001; t += 1 / 18) {
    const x = t * 0.16;
    add(x, 0, frontZ(x, -0.43), 0.7, "lipU", t);
    add(x, 0, frontZ(x, -0.47), 0.6, "lipL", t);
    add(x, 0, frontZ(x, -0.45), 0.6, "seam", t);
  }
  // Embers rising off the shoulders and hair ends (p = phase, q = sway seed).
  const embers = stage ? 420 : 260;
  for (let i = 0; i < embers; i++) add((rnd() * 2 - 1) * 1.25, 0, (rnd() - 0.3) * 0.6, 1, "ember", rnd(), rnd() * 6.28);

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

const GEO: { dock?: Geo; stage?: Geo } = {};

/** Rune marks around the sigil (fixed pattern). */
const RUNES = Array.from({ length: 36 }, (_, i) => {
  const h = Math.sin(i * 91.7) * 43758.5453;
  return h - Math.floor(h);
});

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
  variant = "dock",
}: {
  mode: Mode;
  alert: Severity | null;
  level: () => number;
  /** "stage" is the large figure with the reaching hand and a bigger sigil. */
  variant?: "dock" | "stage";
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const live = useRef({ mode, alert, level });
  live.current = { mode, alert, level };

  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const stage = variant === "stage";
    const g = (GEO[variant] ??= build(stage));
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let last = 0;
    let mouth = 0;
    let blinkAt = performance.now() + 2500;
    const gaze = { x: 0, y: 0, tx: 0, ty: 0, next: 0 };
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
      // The hand drifts toward the viewer and reaches further while she speaks or warns.
      const reach = 0.1 * Math.sin(t * 0.45) + mouth * 0.12 + (al ? 0.12 : 0);

      const D = 5.5;
      const scale = stage ? Math.min(W / 4.6, Hh / 4.9) : Math.min(W / 3.6, Hh / 4.4);
      const cx = stage ? W * 0.53 : W / 2, cy = Hh * (stage ? 0.4 : 0.42);
      const ch = Math.cos(headYaw), shh = Math.sin(headYaw);
      const cp = Math.cos(headPitch), sp = Math.sin(headPitch);
      const cr = Math.cos(headRoll), sr = Math.sin(headRoll);
      const cb = Math.cos(bodyYaw), sb = Math.sin(bodyYaw);
      const scanY = ((t * (md === "thinking" ? 0.9 : 0.32)) % 1.4) * 4.2 - 2.6;

      for (let i = 0; i < g.n; i++) {
        let x = g.x[i], y = g.y[i], z = g.z[i];
        const k = g.k[i];
        let bright = g.b[i];
        if (k === "body" || k === "collar") {
          y += 0.012 * breathe * (y < -1.3 ? 1 : 0.4);
        } else if (k === "arm" || k === "claw") {
          const w = g.p[i];
          z += reach * w * 0.9;
          y += (0.012 * breathe + 0.04 * Math.sin(t * 0.6)) * w;
        } else if (k === "ember") {
          const f = (t * 0.07 + g.p[i]) % 1;
          y = -2.6 + f * 3.3;
          x = g.x[i] * (1 - f * 0.4) + 0.07 * Math.sin(t * 0.8 + g.q[i] + f * 6);
          bright = 0.5 * Math.sin(Math.PI * f) * (0.6 + 0.4 * Math.sin(t * 5 + g.q[i]));
        } else if (k === "strand") {
          const st = g.p[i];
          x += 0.06 * Math.sin(t * 0.9 + g.q[i] + st * 2.2) * st;
          z += 0.03 * Math.cos(t * 0.7 + g.q[i]) * st;
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
        } else if (k === "lipU") {
          const u = g.p[i];
          y = -0.428 + 0.004 * u * u + 0.006 * Math.exp(-((u / 0.18) ** 2)) + mouth * 0.018 * (1 - u * u);
        } else if (k === "lipL") {
          const u = g.p[i];
          y = -0.465 + 0.005 * u * u - 0.022 * (1 - u * u) - mouth * 0.09 * (1 - u * u);
        } else if (k === "seam") {
          const u = g.p[i];
          y = -0.452 + 0.004 * u * u - mouth * 0.035 * (1 - u * u);
          bright = 0.6 - mouth * 0.5;
        } else if (k === "eye") {
          y = 0.1 + (y - 0.1) * blink;
        } else if (k === "iris" || k === "slit") {
          x += gaze.x;
          y = 0.1 + (y - 0.1) * blink + gaze.y;
          bright = blink < 0.4 ? 0 : 1;
        }
        // Strands follow the head near the scalp and the body further down.
        const w = k === "strand" ? 1 - g.p[i] * 0.85 : BODY.has(k) ? 0 : 1;
        const bx = x * cb + z * sb, bz = -x * sb + z * cb;
        let X = bx, Y = y, Z = bz;
        if (w > 0) {
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
          X = hx * w + bx * (1 - w);
          Y = hy * w + y * (1 - w);
          Z = hz * w + bz * (1 - w);
        }

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
      ctx.globalCompositeOperation = "lighter";

      // Sigil behind the head: two rings with rune marks, an inverted star, a small inner ring.
      {
        const R = scale * (stage ? 1.75 : 1.45);
        const hx = cx, hy = cy - 0.3 * scale;
        const pulse = 0.22 + 0.18 * mouth + (al ? 0.2 : 0) + 0.05 * Math.sin(t * 1.7);
        ctx.save();
        ctx.translate(hx, hy);
        ctx.strokeStyle = `rgba(${rgb},${pulse * (stage ? 1 : 0.7)})`;
        ctx.lineWidth = Math.max(1, scale / 90);
        ctx.rotate(t * 0.04);
        for (const k of [1, 0.9, 0.36]) {
          ctx.beginPath();
          ctx.arc(0, 0, R * k, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.beginPath();
        for (let i = 0; i <= 5; i++) {
          const a = Math.PI / 2 + (i * 4 * Math.PI) / 5; // inverted: one point downward
          const px = Math.cos(a) * R * 0.9, py = Math.sin(a) * R * 0.9;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.stroke();
        const r0 = R * 0.915, r1 = R * 0.985;
        for (let i = 0; i < RUNES.length; i++) {
          const h = RUNES[i];
          ctx.save();
          ctx.rotate((i / RUNES.length) * Math.PI * 2);
          ctx.beginPath();
          ctx.moveTo(r0, 0);
          ctx.lineTo(r1, 0);
          if (h > 0.33) {
            ctx.moveTo(r0 + (r1 - r0) * h, -R * 0.02);
            ctx.lineTo(r0 + (r1 - r0) * h, R * 0.02);
          }
          if (h > 0.66) {
            ctx.moveTo(r0, R * 0.018);
            ctx.lineTo(r1, -R * 0.018);
          }
          ctx.stroke();
          ctx.restore();
        }
        ctx.restore();
        const halo = ctx.createRadialGradient(hx, hy, 0, hx, hy, R * 1.1);
        halo.addColorStop(0, `rgba(${rgb},${0.1 + 0.08 * mouth})`);
        halo.addColorStop(1, `rgba(${rgb},0)`);
        ctx.fillStyle = halo;
        ctx.fillRect(hx - R * 1.1, hy - R * 1.1, R * 2.2, R * 2.2);
      }

      // Emitter disc and light column.
      const baseY = Hh * 0.95;
      const ew = stage ? Math.min(W * 0.3, scale * 1.6) : W * 0.22;
      const col = ctx.createLinearGradient(0, baseY, 0, Hh * 0.25);
      col.addColorStop(0, `rgba(${rgb},0.14)`);
      col.addColorStop(1, `rgba(${rgb},0)`);
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.moveTo(cx - ew * 0.9, baseY);
      ctx.lineTo(cx + ew * 0.9, baseY);
      ctx.lineTo(cx + ew * 1.9, Hh * 0.25);
      ctx.lineTo(cx - ew * 1.9, Hh * 0.25);
      ctx.fill();
      ctx.strokeStyle = `rgba(${rgb},0.55)`;
      ctx.lineWidth = Math.max(1, W / 260);
      ctx.beginPath();
      ctx.ellipse(cx, baseY, ew, ew * 0.16, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([ew * 0.09, ew * 0.14]);
      ctx.lineDashOffset = -t * ew * 0.2;
      ctx.beginPath();
      ctx.ellipse(cx, baseY, ew * 1.35, ew * 0.22, 0, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);

      // Glitch: a horizontal slice jumps sideways (always on alerts, now and then otherwise).
      if (!reduced && now < glitch.until) {
        if (Math.random() < 0.35) glitch = { ...glitch, y0: Math.random() * Hh, h: Hh * (0.03 + Math.random() * 0.08), dx: (Math.random() - 0.5) * W * 0.08 };
      } else if (!reduced && Math.random() < 0.006) {
        glitch = { until: now + 120, y0: Math.random() * Hh, h: Hh * 0.05, dx: (Math.random() - 0.5) * W * 0.05 };
      }
      const flicker = reduced ? 1 : 0.88 + 0.12 * Math.sin(t * 37) * Math.sin(t * 13);

      const size = Math.max(1, stage ? Math.min(W, Hh * 1.2) / 330 : W / 240);
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
          const s =
            k === "iris" || k === "slit"
              ? size * 1.5
              : k === "eye" || k === "lipU" || k === "lipL" || k === "drip" || k === "claw"
                ? size * 1.25
                : size;
          ctx.globalAlpha = Math.min(1, a);
          ctx.fillRect(px - s / 2, sy[i] - s / 2, s, s);
        }
      };
      // Colour split: a faint cold ghost offset from the body, stronger while glitching.
      pass("rgb(40,170,255)", split, glitching ? 0.4 : 0.12, false);
      pass(`rgb(${rgb})`, 0, 1, false);
      // Pupils burn near-white over the red.
      pass("rgb(255,236,228)", 0, 1, true);
      ctx.globalAlpha = 1;

      // Eye glow (one per eye), brighter on alerts and while speaking.
      const flare = (al === "CRITICAL" || al === "HIGH" ? 1.8 : 1) * (0.8 + mouth * 0.8);
      const lit = new Set<number>();
      for (let i = 0; i < g.n; i++) {
        if (g.k[i] !== "slit" || sa[i] < 0.5 || lit.has(g.q[i])) continue;
        lit.add(g.q[i]);
        const R = size * (stage ? 14 : 11);
        const gr = ctx.createRadialGradient(sx[i], sy[i], 0, sx[i], sy[i], R);
        gr.addColorStop(0, `rgba(255,90,80,${Math.min(0.6, 0.32 * flare * flicker)})`);
        gr.addColorStop(0.35, `rgba(${rgb},${Math.min(0.3, 0.12 * flare)})`);
        gr.addColorStop(1, `rgba(${rgb},0)`);
        ctx.fillStyle = gr;
        ctx.fillRect(sx[i] - R, sy[i] - R, R * 2, R * 2);
      }

      // Scanlines.
      ctx.globalCompositeOperation = "destination-out";
      ctx.fillStyle = "rgba(0,0,0,0.35)";
      const step = Math.max(2, Math.round(Hh / (stage ? 260 : 160)));
      const off = reduced ? 0 : Math.floor(t * 20) % step;
      for (let y = off; y < Hh; y += step) ctx.fillRect(0, y, W, 1);
      ctx.globalCompositeOperation = "source-over";
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [variant]);

  return <canvas ref={ref} className={`ayla-holo${variant === "stage" ? " ayla-holo--stage" : ""}`} aria-hidden="true" />;
}
