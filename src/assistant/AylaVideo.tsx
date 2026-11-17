import { useCallback, useEffect, useRef, useState, type ComponentProps } from "react";
import { assistantApi, type VideoSlot } from "../ipc/assistant";
import { Hologram } from "./Hologram";
import type { Mode } from "./store";

type Alert = ComponentProps<typeof Hologram>["alert"];
export type VideoState = "loading" | "none" | "ready" | "error";

/** The small Ayla (corner figure and side panel): her video when one is saved, else the hologram. */
export function AylaFigure({ mode, alert, level }: { mode: Mode; alert: Alert; level: () => number }) {
  const [has, setHas] = useState(true);
  const onState = useCallback((s: VideoState) => setHas(s === "ready" || s === "loading"), []);
  return (
    <>
      <AylaVideo mode={mode} alert={alert} level={level} onState={onState} variant="dock" />
      {!has && <Hologram mode={mode} alert={alert} level={level} />}
    </>
  );
}

const SLOTS: VideoSlot[] = ["idle", "talk"];

function mime(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf, 0, Math.min(4, buf.byteLength));
  return b[0] === 0x1a && b[1] === 0x45 ? "video/webm" : "video/mp4";
}

/**
 * Ayla as the user's own video loops: the idle loop always plays, and the talking loop
 * (when one is saved) fades in while she speaks. Both are muted; her voice comes from TTS.
 */
export function AylaVideo({
  mode,
  alert,
  level,
  onState,
  variant = "stage",
}: {
  mode: Mode;
  alert: Alert;
  level: () => number;
  onState: (s: VideoState, has: Record<VideoSlot, boolean>) => void;
  variant?: "stage" | "dock";
}) {
  const [urls, setUrls] = useState<Record<VideoSlot, string | null>>({ idle: null, talk: null });
  const box = useRef<HTMLDivElement>(null);
  const speaking = mode === "speaking";

  useEffect(() => {
    let live = true;
    let made: string[] = [];
    const load = async () => {
      onState("loading", { idle: false, talk: false });
      try {
        const bufs = await Promise.all(SLOTS.map((s) => assistantApi.videoGet(s)));
        if (!live) return;
        made.forEach((u) => URL.revokeObjectURL(u));
        made = [];
        const next = { idle: null, talk: null } as Record<VideoSlot, string | null>;
        SLOTS.forEach((s, i) => {
          if (bufs[i].byteLength) {
            next[s] = URL.createObjectURL(new Blob([bufs[i]], { type: mime(bufs[i]) }));
            made.push(next[s]!);
          }
        });
        setUrls(next);
        onState(next.idle || next.talk ? "ready" : "none", { idle: !!next.idle, talk: !!next.talk });
      } catch {
        if (live) onState("error", { idle: false, talk: false });
      }
    };
    void load();
    const reload = () => void load();
    window.addEventListener("gm-video", reload);
    return () => {
      live = false;
      window.removeEventListener("gm-video", reload);
      made.forEach((u) => URL.revokeObjectURL(u));
    };
  }, [onState]);

  // Voice level drives the glow; smoothed so it breathes rather than flickers.
  useEffect(() => {
    let raf = 0;
    let v = 0;
    const tick = () => {
      const target = speaking ? Math.min(1, level() * 1.4) : 0;
      v += (target - v) * (target > v ? 0.35 : 0.08);
      box.current?.style.setProperty("--lv", v.toFixed(3));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [speaking, level]);

  const talkOn = speaking && !!urls.talk;
  const base = urls.idle ?? urls.talk;
  if (!base) return null;
  return (
    <div ref={box} className={`ayla-video ayla-video--${variant} is-${mode}${alert ? " is-alert" : ""}`}>
      <video src={base} muted loop autoPlay playsInline disablePictureInPicture aria-hidden="true" />
      {urls.talk && urls.idle && (
        <video className={talkOn ? "is-on" : ""} src={urls.talk} muted loop autoPlay playsInline disablePictureInPicture aria-hidden="true" />
      )}
      <div className="ayla-video__glow" />
    </div>
  );
}
