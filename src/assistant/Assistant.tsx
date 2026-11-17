// The assistant on screen: a small hologram in the corner of every module that grows into
// a conversation panel. It announces alerts aloud and on screen, listens on Ctrl+Space
// (push to talk) and answers typed commands too.
import { useCallback, useEffect, useRef, useState } from "react";
import { assistantApi, type AssistantStatus } from "../ipc/assistant";
import { settingsApi, type AppSettings } from "../ipc/settings";
import type { SecurityEvent, Severity } from "../ipc/types";
import { useGhost } from "../state/store";
import { configureAgent, handle, resetConversation } from "./agent";
import { Hologram } from "./Hologram";
import { record, type Recording } from "./mic";
import { useAyla, type Mode } from "./store";
import * as voice from "./voice";
import "./assistant.css";

const RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const STATE_TEXT: Record<Mode, string> = {
  idle: "dinlemeye hazır",
  listening: "dinliyorum…",
  thinking: "düşünüyorum…",
  speaking: "konuşuyor",
};

export function alertSpeech(evs: SecurityEvent[]): string {
  const top = [...evs].sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.ts - a.ts)[0];
  const lead =
    top.severity === "CRITICAL" ? "Acil durum!" : top.severity === "HIGH" ? "Dikkat, şüpheli bir durum var." : "Bilginize.";
  const tail = RANK[top.severity] >= 3 ? " Ayrıntılar Tehdit ekranında." : "";
  return evs.length === 1
    ? `${lead} ${top.title}.${tail}`
    : `${lead} ${evs.length} yeni uyarı var. En önemlisi: ${top.title}.${tail}`;
}

export function Assistant() {
  const [cfg, setCfg] = useState<AppSettings | null>(null);
  const [st, setSt] = useState<AssistantStatus | null>(null);
  const { open, mode, lines, pending, alert, subtitle, muted } = useAyla();
  const ay = useAyla.getState;
  const setModule = useGhost((s) => s.setModule);
  const [text, setText] = useState("");
  const rec = useRef<Recording | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  // Settings and key status; refreshed whenever Settings saves.
  useEffect(() => {
    settingsApi.get().then(setCfg, () => {});
    assistantApi.status().then(setSt, () => {});
    const onSave = (e: Event) => {
      const saved = (e as CustomEvent<AppSettings | undefined>).detail;
      if (saved) setCfg(saved);
    };
    const onKeys = () => assistantApi.status().then(setSt, () => {});
    window.addEventListener("gm-settings", onSave);
    window.addEventListener("gm-assistant-keys", onKeys);
    return () => {
      window.removeEventListener("gm-settings", onSave);
      window.removeEventListener("gm-assistant-keys", onKeys);
    };
  }, []);

  useEffect(() => {
    if (!cfg) return;
    useAyla.setState({ enabled: cfg.assistantEnabled });
    voice.configure(cfg.assistantVoice === "azure" && st?.azure ? "azure" : "windows", cfg.assistantRate);
    configureAgent(cfg.assistantName, !!st?.claude);
  }, [cfg, st]);

  // Speaking state drives the hologram and the subtitle.
  useEffect(
    () =>
      voice.onSpeaking((speaking, said) => {
        const s = ay();
        if (speaking) {
          s.setMode("speaking");
          s.setSubtitle(said);
        } else {
          if (s.mode === "speaking") s.setMode("idle");
          window.setTimeout(() => !voice.isSpeaking() && ay().setSubtitle(null), 1800);
        }
      }),
    [ay],
  );

  // Alerts: new events at or above the threshold, batched for a moment so a burst is one sentence.
  useEffect(() => {
    if (!cfg?.assistantEnabled) return;
    let lastId = Math.max(0, ...useGhost.getState().liveEvents.map((e) => e.id));
    const startedAt = Date.now();
    let batch: SecurityEvent[] = [];
    let timer: number | undefined;
    let clearAlert: number | undefined;
    const flush = () => {
      const evs = batch;
      batch = [];
      if (!evs.length) return;
      const s = ay();
      const top = evs.reduce((a, b) => (RANK[b.severity] > RANK[a.severity] ? b : a));
      const said = alertSpeech(evs);
      s.add("alert", said, top.severity);
      s.setAlert(top.severity);
      window.clearTimeout(clearAlert);
      clearAlert = window.setTimeout(() => ay().setAlert(null), 7000);
      if (cfg.assistantSpeakAlerts && !s.muted) void voice.say(said, RANK[top.severity] >= 3);
      else s.setSubtitle(said);
    };
    const unsub = useGhost.subscribe((g, prev) => {
      if (g.liveEvents === prev.liveEvents) return;
      for (const e of g.liveEvents) {
        if (e.id <= lastId) break;
        // Older events merged in by the initial history load are not news.
        if (e.ts < startedAt - 10_000) continue;
        if (RANK[e.severity] >= RANK[cfg.assistantMinSeverity]) batch.push(e);
      }
      lastId = Math.max(lastId, ...g.liveEvents.slice(0, 50).map((e) => e.id));
      if (batch.length) {
        window.clearTimeout(timer);
        timer = window.setTimeout(flush, 1500);
      }
    });
    return () => {
      unsub();
      window.clearTimeout(timer);
      window.clearTimeout(clearAlert);
    };
  }, [cfg, ay]);

  const listen = useCallback(async () => {
    const s = ay();
    if (rec.current) {
      rec.current.finish();
      return;
    }
    s.setOpen(true);
    if (!st?.azure && !st?.localStt) {
      const msg =
        "Sesli komut için konuşma tanımayı kurmam gerekiyor. Ayarlar'daki Asistan bölümünden “Konuşma tanımayı kur” düğmesine basın; internetsiz çalışır. Şimdilik yazarak konuşabiliriz.";
      s.add("ayla", msg);
      void voice.say(msg);
      return;
    }
    voice.stop();
    try {
      rec.current = await record();
    } catch {
      s.add("ayla", "Mikrofona erişemedim. Windows gizlilik ayarlarında mikrofon iznini kontrol edin.");
      return;
    }
    s.setMode("listening");
    const wav = await rec.current.done;
    rec.current = null;
    if (!wav) {
      s.setMode("idle");
      s.setSubtitle("Sizi duyamadım.");
      window.setTimeout(() => ay().setSubtitle(null), 2500);
      return;
    }
    s.setMode("thinking");
    try {
      const heard = await assistantApi.stt(wav);
      if (!heard.trim()) {
        s.setMode("idle");
        const msg = "Anlayamadım, tekrar söyler misiniz?";
        s.add("ayla", msg);
        void voice.say(msg);
        return;
      }
      await handle(heard);
    } catch (e) {
      s.setMode("idle");
      s.add("ayla", String(e));
    }
  }, [st, ay]);

  // Ctrl+Space: talk. Escape (in the panel): close.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.code === "Space") {
        e.preventDefault();
        listen();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [listen]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [lines, open]);

  const level = useCallback(() => (rec.current ? rec.current.level() : voice.level()), []);

  if (!cfg?.assistantEnabled) return null;
  const name = cfg.assistantName;
  const tone = alert ? ` is-${alert.toLowerCase()}` : ` is-${mode}`;

  const submit = () => {
    const v = text.trim();
    setText("");
    if (v) void handle(v);
  };

  if (!open) {
    if (!cfg.assistantFloat) return null;
    return (
      <div className={`ayla-dock${tone}`}>
        {subtitle && (
          <p className="ayla-bubble" role="status">
            {subtitle}
          </p>
        )}
        <button className="ayla-dock__fig" onClick={() => ay().setOpen(true)} title={`${name} ile konuş (Ctrl+Boşluk)`}>
          <Hologram mode={mode} alert={alert} level={level} />
          <span className="ayla-dock__name">
            {name}
            {muted && <i> · sessiz</i>}
          </span>
        </button>
      </div>
    );
  }

  return (
    <aside className={`ayla-panel${tone}`} aria-label={`${name} asistan`}>
      <header className="ayla-panel__head">
        <div>
          <b>{name}</b>
          <span>{alert ? "uyarı" : STATE_TEXT[mode]}</span>
        </div>
        <button
          className="btn btn--quiet"
          title="Konuşma geçmişini temizler"
          onClick={() => {
            resetConversation();
            useAyla.setState({ lines: [], pending: null });
          }}
        >
          Yeni konuşma
        </button>
        <button
          className="btn btn--quiet"
          title={muted ? "Uyarılar yeniden sesli okunur" : "Uyarılar yalnızca ekranda gösterilir"}
          onClick={() => ay().setMuted(!muted)}
        >
          {muted ? "Sesi aç" : "Sessiz"}
        </button>
        <button className="btn btn--quiet" onClick={() => ay().setOpen(false)} aria-label="Paneli küçült">
          Küçült
        </button>
      </header>

      <div className="ayla-panel__holo">
        <Hologram mode={mode} alert={alert} level={level} />
        {subtitle && <p className="ayla-sub">{subtitle}</p>}
      </div>

      <div className="ayla-log" ref={logRef}>
        {lines.length === 0 && (
          <p className="ayla-hint">
            “Opera'yı aç”, “İstanbul'da hava nasıl”, “durum raporu ver”, “chrome'un internetini kes” gibi konuşabilirsiniz.
            {!st?.claude && " Serbest sohbet ve genel sorular için Ayarlar'dan Claude anahtarı ekleyin."}
          </p>
        )}
        {lines.map((l) => (
          <p
            key={l.id}
            className={`ayla-line is-${l.who}${l.severity ? ` sev-${l.severity.toLowerCase()}` : ""}`}
            onClick={l.who === "alert" ? () => setModule("threat") : undefined}
          >
            {l.text}
          </p>
        ))}
      </div>

      {pending && (
        <div className="ayla-confirm">
          <span>{pending.question}</span>
          <button className="btn btn--danger" onClick={() => handle("evet")}>
            Evet
          </button>
          <button className="btn" onClick={() => handle("hayır")}>
            Hayır
          </button>
        </div>
      )}

      <form
        className="ayla-input"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <button
          type="button"
          className={`ayla-mic${mode === "listening" ? " is-on" : ""}`}
          onClick={listen}
          title={st?.azure || st?.localStt ? "Konuşmak için basın (Ctrl+Boşluk)" : "Sesli komut için önce Ayarlar → Asistan’dan konuşma tanımayı kurun"}
        >
          {mode === "listening" ? "Bitir" : "Konuş"}
        </button>
        <input
          className="field"
          value={text}
          placeholder="Yazın ya da Ctrl+Boşluk ile konuşun…"
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Escape" && ay().setOpen(false)}
        />
      </form>
    </aside>
  );
}
