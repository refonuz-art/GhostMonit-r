// Push-to-talk recording: 16 kHz mono PCM, ends on its own after a pause in speech.
// Produces a WAV the backend forwards to Azure speech recognition.

export interface Recording {
  /** Resolves with the WAV once speech ends (or `finish()` is called); null if nothing was said. */
  done: Promise<Uint8Array | null>;
  finish: () => void;
  cancel: () => void;
  /** 0..1 microphone loudness, for the listening animation. */
  level: () => number;
}

const RATE = 16000;
const MAX_MS = 12000;
const SILENCE_MS = 1300;
const NO_SPEECH_MS = 6000;

export function encodeWav(samples: Float32Array, rate = RATE): Uint8Array {
  const out = new DataView(new ArrayBuffer(44 + samples.length * 2));
  const str = (o: number, s: string) => [...s].forEach((c, i) => out.setUint8(o + i, c.charCodeAt(0)));
  str(0, "RIFF");
  out.setUint32(4, 36 + samples.length * 2, true);
  str(8, "WAVE");
  str(12, "fmt ");
  out.setUint32(16, 16, true);
  out.setUint16(20, 1, true);
  out.setUint16(22, 1, true);
  out.setUint32(24, rate, true);
  out.setUint32(28, rate * 2, true);
  out.setUint16(32, 2, true);
  out.setUint16(34, 16, true);
  str(36, "data");
  out.setUint32(40, samples.length * 2, true);
  for (let i = 0; i < samples.length; i++) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    out.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
  }
  return new Uint8Array(out.buffer);
}

export async function record(): Promise<Recording> {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true },
  });
  const ctx = new AudioContext({ sampleRate: RATE });
  const src = ctx.createMediaStreamSource(stream);
  // ScriptProcessor is deprecated but needs no separate worklet file under the app's CSP.
  const proc = ctx.createScriptProcessor(4096, 1, 1);
  const chunks: Float32Array[] = [];
  let lvl = 0;
  let noise = 0.01;
  let heard = false;
  let lastVoice = performance.now();
  const started = performance.now();
  let finished = false;
  let resolve!: (v: Uint8Array | null) => void;
  const done = new Promise<Uint8Array | null>((r) => (resolve = r));

  const end = (keep: boolean) => {
    if (finished) return;
    finished = true;
    proc.disconnect();
    src.disconnect();
    stream.getTracks().forEach((t) => t.stop());
    ctx.close().catch(() => {});
    if (!keep || !heard) return resolve(null);
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const all = new Float32Array(total);
    let o = 0;
    for (const c of chunks) {
      all.set(c, o);
      o += c.length;
    }
    resolve(encodeWav(all));
  };

  proc.onaudioprocess = (e) => {
    const data = e.inputBuffer.getChannelData(0);
    chunks.push(new Float32Array(data));
    let sum = 0;
    for (let i = 0; i < data.length; i++) sum += data[i] * data[i];
    const rms = Math.sqrt(sum / data.length);
    lvl = Math.min(1, rms * 8);
    const now = performance.now();
    // Track the room's background level so a fan or hum doesn't count as speech.
    if (rms < noise * 2) noise = noise * 0.95 + rms * 0.05;
    if (rms > Math.max(0.02, noise * 3)) {
      heard = true;
      lastVoice = now;
    }
    if (now - started > MAX_MS) end(true);
    else if (heard && now - lastVoice > SILENCE_MS) end(true);
    else if (!heard && now - started > NO_SPEECH_MS) end(false);
  };
  src.connect(proc);
  proc.connect(ctx.destination);

  return { done, finish: () => end(true), cancel: () => end(false), level: () => lvl };
}
