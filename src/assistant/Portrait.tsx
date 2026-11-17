// Ayla as a living picture: the user's own artwork, warped in real time on the GPU.
// A fragment shader bends the image around a few landmarks (eyes, lips, neck, shoulder, palm)
// so she breathes, tilts her head, blinks, opens her mouth with the voice, flexes the reaching
// hand and her hair drifts. Red neon in the picture pulses with her voice, embers rise, and
// alerts glitch the frame. Pictures without a landmark preset get the light effects only.
import { useEffect, useRef, useState } from "react";
import { assistantApi } from "../ipc/assistant";
import type { Severity } from "../ipc/types";
import type { Mode } from "./store";

type P2 = [number, number];
interface Rig {
  /** Part of the picture to show, in image pixels: x, y, w, h. */
  crop: [number, number, number, number];
  eyeL: P2;
  eyeR: P2;
  lipL: P2; // mouth corners along the lip line
  lipR: P2;
  head: P2; // centre of the head (incl. horns)
  headR: number;
  neck: P2; // pivot for head turns
  chest: P2;
  shoulder: P2; // pivot for the reaching arm
  knuckles: P2; // pivot for the fingers
  armMaxX: number; // the arm/hand region ends left of this x
  hairL: number; // x of the hair falling at each side
  hairR: number;
}

/** Landmarks measured on the supplied 1672×941 artwork. */
const PRESETS: Record<string, Rig> = {
  "1672x941": {
    crop: [395, 0, 940, 866],
    eyeL: [852, 170],
    eyeR: [934, 152],
    lipL: [888, 232],
    lipR: [952, 214],
    head: [895, 150],
    headR: 175,
    neck: [905, 300],
    chest: [960, 560],
    shoulder: [740, 345],
    knuckles: [585, 515],
    armMaxX: 790,
    hairL: 775,
    hairR: 1090,
  },
};

const VERT = `attribute vec2 a;varying vec2 v;void main(){v=a*.5+.5;gl_Position=vec4(a,0.,1.);}`;

const FRAG = `
precision highp float;
varying vec2 v;
uniform sampler2D tex;
uniform vec2 img;      // full image size (px)
uniform vec4 crop;     // x, y, w, h (px)
uniform vec2 view;     // canvas size (px)
uniform float t, rig, breath, headA, armA, fingA, mouth, blink, glow, glitch, gy, gh, gdx, alertK;
uniform vec2 headS;
uniform vec2 eyeL, eyeR, lipL, lipR, head, neck, chest, shoulder, knuckles;
uniform float headR, armMaxX, hairL, hairR;

vec2 rot(vec2 p, float a){ float c=cos(a), s=sin(a); return vec2(c*p.x-s*p.y, s*p.x+c*p.y); }
float gs(vec2 d, float r){ return exp(-dot(d,d)/(r*r)); }
float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1,311.7)))*43758.5453); }
vec3 texAt(vec2 q){ return texture2D(tex, (q)/img).rgb; }

// Inverse warp: where in the picture this output pixel comes from. 'inside' > 0 marks the open mouth.
vec2 warp(vec2 q, out float inside, out float depthIn, out float lid){
  inside = 0.; depthIn = 0.; lid = 0.;
  vec2 s = q;
  if (rig < .5) return s;
  // Breathing: chest and shoulders rise and fall.
  s.y += breath * 3.2 * gs(q - chest, 260.) ;
  s.y += breath * 1.6 * gs(q - neck, 220.);
  // Head: tilt and drift around the neck; the weight fades out below the neck.
  float wh = (1. - smoothstep(headR*.85, headR*1.45, length(q - head))) * smoothstep(neck.y + 30., neck.y - 40., q.y);
  s = neck + rot(s - neck, -headA * wh) - headS * wh;
  // Reaching arm: swings around the shoulder; fingers flex around the knuckles.
  float wa = smoothstep(40., 190., length(s - shoulder)) * (1. - smoothstep(armMaxX - 70., armMaxX + 30., s.x))
           * smoothstep(shoulder.y - 30., shoulder.y + 20., s.y);
  s = shoulder + rot(s - shoulder, -armA * wa);
  float wf = smoothstep(50., 150., length(s - knuckles)) * smoothstep(knuckles.y - 30., knuckles.y + 30., s.y)
           * (1. - smoothstep(armMaxX - 40., armMaxX + 40., s.x));
  s = knuckles + rot(s - knuckles, -fingA * wf);
  // Hair drifts, more toward the ends.
  float hl = gs(vec2((s.x - hairL)/40., 0.), 1.) * smoothstep(440., 600., s.y);
  float hr = gs(vec2((s.x - hairR)/45., 0.), 1.) * smoothstep(260., 420., s.y);
  s.x += (hl + hr) * sin(t*1.1 + s.y*.018) * 2.6 * clamp((s.y - 260.)/400., 0., 1.);

  // Mouth: open along the lip line; the jaw follows a little.
  vec2 mc = (lipL + lipR) * .5;
  vec2 ax = normalize(lipR - lipL);
  float half_ = length(lipR - lipL) * .5;
  vec2 l = vec2(dot(s - mc, ax), dot(s - mc, vec2(-ax.y, ax.x)));
  float wx = clamp(1. - pow(l.x / (half_ * 1.05), 2.), 0., 1.);
  float D = mouth * 8. * wx;       // lower lip drop
  float U = mouth * 1.6 * wx;      // upper lip lift
  if (abs(l.x) < half_ * 1.3) {
    if (l.y >= D) {
      // Lower lip and chin follow the jaw, fading out toward the neck.
      float fd = l.y < 14. ? 1. : 1. - smoothstep(14., 60., l.y);
      l.y = max(l.y - D * fd, 0.);
    } else if (l.y < -U) {
      l.y += U * (1. - smoothstep(-U - 2., -20., l.y));
    } else if (D > .3) {
      // Between the lips: soft-edged dark mouth.
      float e = min(l.y + U, D - l.y);
      inside = smoothstep(0., 1.6, e) * smoothstep(0., .25, wx);
      depthIn = clamp((l.y + U) / max(D + U, .001), 0., 1.);
      l.y = 0.;
    }
    s = mc + ax * l.x + vec2(-ax.y, ax.x) * l.y;
  }

  // Blink: upper lids come down over each eye.
  vec2 ea = normalize(eyeR - eyeL);
  for (int i = 0; i < 2; i++) {
    vec2 e = i == 0 ? eyeL : eyeR;
    vec2 le = vec2(dot(s - e, ea), dot(s - e, vec2(-ea.y, ea.x)));
    float wxe = clamp(1. - pow(le.x / 19., 2.), 0., 1.);
    float c = blink * 8. * wxe;
    if (le.y < 6. && le.y > -22.) {
      float f = le.y > -10. ? 1. : 1. - smoothstep(-10., -22., le.y);
      le.y -= c * f;
      lid = max(lid, blink * wxe * step(-10., le.y) * (1. - step(4., le.y)));
      s = e + ea * le.x + vec2(-ea.y, ea.x) * le.y;
    }
  }
  return s;
}

void main(){
  // Fit the crop into the canvas (contain), centred.
  vec2 frag = vec2(v.x, 1. - v.y) * view;
  float k = min(view.x / crop.z, view.y / crop.w);
  vec2 off = (view - crop.zw * k) * .5;
  vec2 q = crop.xy + (frag - off) / k;
  // Glitch: a slice jumps sideways.
  if (glitch > 0. && frag.y > gy && frag.y < gy + gh) q.x += gdx / k;
  float inside, depthIn, lid;
  vec2 s = warp(q, inside, depthIn, lid);
  vec3 col;
  float split = (1.2 + glitch * 5.) ;
  col.r = texAt(s + vec2(split, 0.)).r;
  col.g = texAt(s).g;
  col.b = texAt(s - vec2(split, 0.)).b;
  if (inside > 0.) {
    // Mouth interior: dark red, teeth catching light just under the upper lip.
    vec3 seam = texAt(s);
    vec3 inner = mix(vec3(.2, .03, .04), vec3(.05, 0., .01), smoothstep(.15, .8, depthIn));
    inner += vec3(.55, .42, .44) * smoothstep(.3, .05, depthIn) * .5;
    col = mix(col, inner * (.6 + .4 * seam.r), inside);
  }
  col *= 1. - lid * .25;
  // Red neon in the picture (sigil, rim light) pulses with her voice and alerts.
  float neon = clamp((col.r - max(col.g, col.b)) * 2.2 - .35, 0., 1.);
  col += neon * vec3(1., .15, .2) * (glow * .55 + alertK * .4);
  // Eyes burn.
  if (rig > .5) {
    for (int i = 0; i < 2; i++) {
      vec2 e = i == 0 ? eyeL : eyeR;
      vec2 d = (q - e);
      col += vec3(1., .2, .15) * exp(-dot(d,d)/(7.*7.)) * (0.35 + glow * .6 + alertK * .6) * (1. - blink);
      col += vec3(1., .1, .1) * exp(-dot(d,d)/(26.*26.)) * (0.06 + glow * .12);
    }
  }
  // Embers rising through the frame.
  for (int L = 0; L < 3; L++) {
    float fl = float(L);
    float cell = 46. + fl * 21.;
    vec2 p = vec2(q.x, q.y + t * (28. + fl * 14.));
    vec2 id = floor(p / cell);
    vec2 c = (id + vec2(hash(id + fl), hash(id * 1.7 + fl))) * cell;
    c.x += sin(t * .7 + id.y + fl) * 6.;
    float h = hash(id * 3.1 + fl);
    float tw = .5 + .5 * sin(t * 3. + h * 20.);
    float d = length(p - c);
    col += vec3(1., .35, .15) * smoothstep(2.4, 0., d) * step(.72, h) * tw * smoothstep(crop.y, crop.y + crop.w * .45, q.y) * .9;
  }
  // Hologram: fine scanlines, flicker, soft edges into the dark.
  float scan = .93 + .07 * sin(frag.y * 1.6 + t * 6.);
  float flick = .96 + .04 * sin(t * 37.) * sin(t * 13.);
  vec2 u = (q - crop.xy) / crop.zw;
  float edge = smoothstep(0., .07, u.x) * smoothstep(1., .93, u.x) * smoothstep(0., .04, u.y) * smoothstep(1., .9, u.y);
  bool out_ = u.x < 0. || u.y < 0. || u.x > 1. || u.y > 1.;
  col *= scan * flick * edge;
  gl_FragColor = vec4(out_ ? vec3(0.) : col, out_ ? 0. : edge);
}`;

function compile(gl: WebGLRenderingContext, type: number, src: string) {
  const sh = gl.createShader(type)!;
  gl.shaderSource(sh, src);
  gl.compileShader(sh);
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh) ?? "shader");
  return sh;
}

export type PortraitState = "loading" | "none" | "ready" | "error";

export function Portrait({
  mode,
  alert,
  level,
  onState,
}: {
  mode: Mode;
  alert: Severity | null;
  level: () => number;
  onState?: (s: PortraitState, rigged?: boolean) => void;
}) {
  const ref = useRef<HTMLCanvasElement>(null);
  const live = useRef({ mode, alert, level });
  live.current = { mode, alert, level };
  const [bitmap, setBitmap] = useState<ImageBitmap | null>(null);
  const report = useRef(onState);
  report.current = onState;

  // Load the saved picture (and again when Settings/Ayla screen replaces it).
  useEffect(() => {
    let alive = true;
    const load = () => {
      report.current?.("loading");
      assistantApi
        .portraitGet()
        .then(async (buf) => {
          if (!alive) return;
          if (!buf || buf.byteLength === 0) {
            setBitmap(null);
            report.current?.("none");
            return;
          }
          const bmp = await createImageBitmap(new Blob([buf]));
          if (alive) setBitmap(bmp);
        })
        .catch(() => alive && report.current?.("error"));
    };
    load();
    window.addEventListener("gm-portrait", load);
    return () => {
      alive = false;
      window.removeEventListener("gm-portrait", load);
    };
  }, []);

  useEffect(() => {
    if (!bitmap) return;
    const cv = ref.current!;
    const gl = cv.getContext("webgl", { premultipliedAlpha: false, alpha: true });
    if (!gl) {
      report.current?.("error");
      return;
    }
    const rigDef = PRESETS[`${bitmap.width}x${bitmap.height}`];
    report.current?.("ready", !!rigDef);
    const prog = gl.createProgram()!;
    try {
      gl.attachShader(prog, compile(gl, gl.VERTEX_SHADER, VERT));
      gl.attachShader(prog, compile(gl, gl.FRAGMENT_SHADER, FRAG));
    } catch (e) {
      console.error(e);
      report.current?.("error");
      return;
    }
    gl.linkProgram(prog);
    gl.useProgram(prog);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "a");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, bitmap);

    const U = (n: string) => gl.getUniformLocation(prog, n);
    const set1 = (n: string, x: number) => gl.uniform1f(U(n), x);
    const set2 = (n: string, p: P2) => gl.uniform2f(U(n), p[0], p[1]);
    gl.uniform2f(U("img"), bitmap.width, bitmap.height);
    const r: Rig = rigDef ?? {
      crop: [0, 0, bitmap.width, bitmap.height],
      eyeL: [-999, -999], eyeR: [-998, -999], lipL: [-999, -999], lipR: [-998, -999],
      head: [-999, -999], headR: 1, neck: [-999, -999], chest: [-999, -999], shoulder: [-999, -999],
      knuckles: [-999, -999], armMaxX: -999, hairL: -999, hairR: -999,
    };
    gl.uniform4f(U("crop"), ...r.crop);
    set1("rig", rigDef ? 1 : 0);
    for (const k of ["eyeL", "eyeR", "lipL", "lipR", "head", "neck", "chest", "shoulder", "knuckles"] as const) set2(k, r[k]);
    set1("headR", r.headR);
    set1("armMaxX", r.armMaxX);
    set1("hairL", r.hairL);
    set1("hairR", r.hairR);

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0, last = 0, mouth = 0, glow = 0, alertK = 0;
    let blinkAt = performance.now() + 2000;
    let twitch = { at: performance.now() + 5000, until: 0, a: 0 };
    let tw = 0;
    let glitch = { until: 0, y: 0, h: 0, dx: 0 };
    let lastAlert: Severity | null = null;

    const resize = () => {
      const b = cv.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      cv.width = Math.max(1, Math.round(b.width * dpr));
      cv.height = Math.max(1, Math.round(b.height * dpr));
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(cv);

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw);
      if (document.hidden) return;
      const fps = document.hasFocus() ? 40 : 12;
      if (now - last < 1000 / fps - 1) return;
      last = now;
      const { mode: md, alert: al, level: lv } = live.current;
      const t = reduced ? 0 : now / 1000;

      // Voice: snappy opening, slower closing, so syllables read as speech.
      // Syllable rhythm (~6 per second) on top of the loudness, so the jaw moves like speech
      // even with the Windows voice, which reports no real loudness.
      const syll = Math.abs(Math.sin(t * 19 + Math.sin(t * 3.7) * 1.8));
      const target = md === "speaking" ? Math.min(1, lv() * 1.5) * (0.25 + 0.75 * syll) : 0;
      mouth += (target - mouth) * (target > mouth ? 0.65 : 0.35);
      glow += ((md === "speaking" ? 0.35 + mouth * 0.65 : md === "listening" ? 0.45 : md === "thinking" ? 0.3 + 0.2 * Math.sin(t * 4) : 0.12) - glow) * 0.15;
      alertK += ((al ? (al === "CRITICAL" ? 1 : al === "HIGH" ? 0.8 : 0.5) : 0) - alertK) * 0.1;
      if (al && al !== lastAlert) glitch = { until: now + 900, y: 0, h: 0, dx: 0 };
      lastAlert = al;

      let blink = 0;
      if (now > blinkAt) {
        const k = (now - blinkAt) / 170;
        blink = k < 1 ? 1 - Math.abs(1 - 2 * k) : 0;
        if (k >= 1) blinkAt = now + 2200 + Math.random() * 4500;
      }
      // Rare, sudden head twitch.
      if (!reduced && now > twitch.at) {
        twitch = { at: now + 6000 + Math.random() * 9000, until: now + 380 + Math.random() * 400, a: (Math.random() < 0.5 ? -1 : 1) * (0.025 + Math.random() * 0.02) };
        glitch = { until: now + 120, y: 0, h: 0, dx: 0 };
      }
      tw += ((now < twitch.until ? twitch.a : 0) - tw) * (now < twitch.until ? 0.6 : 0.08);

      const talkNod = md === "speaking" ? 0.006 * Math.sin(t * 5.3) * (0.4 + mouth) : 0;
      const headA = 0.012 * Math.sin(t * 0.37) + 0.006 * Math.sin(t * 0.83 + 1) + talkNod + tw + (md === "listening" ? 0.012 : 0);
      const headS: P2 = [1.6 * Math.sin(t * 0.29), 1.2 * Math.sin(t * 0.41) - mouth * 1.2];
      const armA = 0.03 * Math.sin(t * 0.52) + 0.008 * Math.sin(t * 1.3) + (md === "speaking" ? 0.015 * mouth : 0) + (al ? 0.02 : 0);
      const fingA = 0.015 + 0.05 * (0.5 + 0.5 * Math.sin(t * 0.8)) + (md === "speaking" ? 0.03 * mouth : 0) + (al ? 0.04 : 0);

      if (!reduced && now < glitch.until) {
        if (Math.random() < 0.35) glitch = { ...glitch, y: Math.random() * cv.height, h: cv.height * (0.02 + Math.random() * 0.07), dx: (Math.random() - 0.5) * cv.width * 0.06 };
      } else if (!reduced && Math.random() < 0.003) {
        glitch = { until: now + 90, y: Math.random() * cv.height, h: cv.height * 0.03, dx: (Math.random() - 0.5) * cv.width * 0.03 };
      }
      const gOn = now < glitch.until ? 1 : 0;

      gl.viewport(0, 0, cv.width, cv.height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(U("view"), cv.width, cv.height);
      set1("t", t);
      set1("breath", Math.sin(t * 1.25));
      set1("headA", headA);
      gl.uniform2f(U("headS"), headS[0], headS[1]);
      set1("armA", armA);
      set1("fingA", fingA);
      set1("mouth", mouth);
      set1("blink", blink);
      set1("glow", glow);
      set1("alertK", alertK);
      set1("glitch", gOn);
      set1("gy", glitch.y);
      set1("gh", gOn ? glitch.h : 0);
      set1("gdx", glitch.dx);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      gl.deleteTexture(tex);
      gl.deleteBuffer(buf);
      gl.deleteProgram(prog);
    };
  }, [bitmap]);

  return <canvas ref={ref} className="ayla-portrait" aria-hidden="true" />;
}
