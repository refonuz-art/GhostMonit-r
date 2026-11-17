// The assistant's voice. Two engines:
//  - "windows": an installed Turkish voice through speechSynthesis (offline, works today);
//  - "azure":   Azure neural voice (Emel/Ahmet) fetched by the backend and played through
//               WebAudio, which also gives a real loudness signal for the hologram's mouth.
// Utterances are queued; urgent ones (alerts) jump the queue.
import { assistantApi } from "../ipc/assistant";

export type Engine = "windows" | "azure";

interface Item {
  text: string;
  resolve: () => void;
}

const listeners = new Set<(speaking: boolean, text: string | null) => void>();

let engine: Engine = "windows";
let rate = 1;
let queue: Item[] = [];
let current: Item | null = null;
let ctx: AudioContext | null = null;
let analyser: AnalyserNode | null = null;
let source: AudioBufferSourceNode | null = null;
let buf: Uint8Array<ArrayBuffer> | null = null;
// speechSynthesis gives no audio access; word boundaries drive a synthetic level instead.
let pulse = 0;
let lastError: string | null = null;

export function configure(e: Engine, r: number) {
  engine = e;
  rate = r;
}

export function onSpeaking(cb: (speaking: boolean, text: string | null) => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function emit(speaking: boolean, text: string | null) {
  listeners.forEach((l) => l(speaking, text));
}

export function turkishVoice(): SpeechSynthesisVoice | null {
  if (typeof speechSynthesis === "undefined") return null;
  const vs = speechSynthesis.getVoices();
  return vs.find((v) => v.lang.toLowerCase().startsWith("tr")) ?? null;
}

/** 0..1 loudness right now, for lip movement. */
export function level(): number {
  if (!current) return 0;
  if (analyser && buf && source) {
    analyser.getByteTimeDomainData(buf);
    let sum = 0;
    for (let i = 0; i < buf.length; i++) {
      const v = (buf[i] - 128) / 128;
      sum += v * v;
    }
    return Math.min(1, Math.sqrt(sum / buf.length) * 4);
  }
  pulse *= 0.86;
  // Gentle jitter between boundaries so the mouth never freezes mid-sentence.
  return Math.min(1, pulse + 0.18 + Math.random() * 0.22);
}

export function lastVoiceError() {
  return lastError;
}

/** Make text pleasant to hear: no paths, extensions or symbols read out letter by letter. */
export function speakable(text: string): string {
  return text
    .replace(/[A-Za-z]:\\(?:[^\\\s]+\\)*([^\\\s]+)/g, "$1")
    .replace(/\.(exe|dll|lnk|bat|ps1)\b/gi, "")
    .replace(/https?:\/\/\S+/g, "bağlantı")
    .replace(/[*_#`>|]/g, "")
    .replace(/\s*·\s*/g, ", ")
    .replace(/\s+/g, " ")
    .trim();
}

async function playAzure(text: string) {
  const data = await assistantApi.tts(text);
  ctx ??= new AudioContext();
  if (ctx.state === "suspended") await ctx.resume();
  const audio = await ctx.decodeAudioData(data.slice(0));
  analyser ??= ctx.createAnalyser();
  analyser.fftSize = 512;
  buf = new Uint8Array(new ArrayBuffer(analyser.fftSize));
  const src = ctx.createBufferSource();
  src.buffer = audio;
  src.connect(analyser);
  analyser.connect(ctx.destination);
  source = src;
  await new Promise<void>((res) => {
    src.onended = () => res();
    src.start();
  });
  source = null;
}

function playWindows(text: string) {
  return new Promise<void>((res, rej) => {
    if (typeof speechSynthesis === "undefined") return rej(new Error("Bu sistemde ses sentezi yok"));
    const u = new SpeechSynthesisUtterance(text);
    const v = turkishVoice();
    if (v) u.voice = v;
    u.lang = "tr-TR";
    u.rate = rate;
    u.pitch = 1.05;
    u.onboundary = () => (pulse = 0.75);
    u.onend = () => res();
    u.onerror = (e) => (e.error === "interrupted" || e.error === "canceled" ? res() : rej(new Error(e.error)));
    speechSynthesis.speak(u);
  });
}

async function pump() {
  if (current || !queue.length) return;
  current = queue.shift()!;
  const item = current;
  emit(true, item.text);
  try {
    if (engine === "azure") {
      try {
        await playAzure(item.text);
        lastError = null;
      } catch (e) {
        // Neural voice unavailable (no key, offline, quota): fall back to the Windows voice.
        lastError = String(e);
        if (current === item) await playWindows(item.text);
      }
    } else {
      await playWindows(item.text);
    }
  } catch (e) {
    lastError = String(e);
  }
  item.resolve();
  // If stop() interrupted this item it already reset state and may have started the next one.
  if (current === item) {
    current = null;
    emit(false, null);
  }
  pump();
}

/** Queue `text`. `urgent` interrupts what is being said (used for alerts). */
export function say(text: string, urgent = false): Promise<void> {
  const clean = speakable(text);
  if (!clean) return Promise.resolve();
  return new Promise((resolve) => {
    const item = { text: clean, resolve };
    if (urgent) {
      queue = [item, ...queue];
      stop(false);
    } else queue.push(item);
    pump();
  });
}

/** Silence now. `clearQueue` also drops what was waiting. */
export function stop(clearQueue = true) {
  if (clearQueue) {
    queue.forEach((q) => q.resolve());
    queue = [];
  }
  const was = current;
  current = null;
  try {
    source?.stop();
  } catch {
    /* already stopped */
  }
  source = null;
  if (typeof speechSynthesis !== "undefined") speechSynthesis.cancel();
  if (was) {
    was.resolve();
    emit(false, null);
  }
  if (!clearQueue) queueMicrotask(pump);
}

export function isSpeaking() {
  return current !== null;
}
