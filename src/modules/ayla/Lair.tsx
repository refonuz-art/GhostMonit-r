// Ayla's own screen: the full-size hologram in the middle, live system panels around her,
// and a place to talk to her. Every number here comes from the same live feed as the rest
// of the app; panels with nothing to show say so instead of inventing values.
import { useCallback, useEffect, useMemo, useState } from "react";
import { handle } from "../../assistant/agent";
import { Hologram } from "../../assistant/Hologram";
import { useAyla, type Mode } from "../../assistant/store";
import * as voice from "../../assistant/voice";
import { bytes, duration, rate } from "../../design/format";
import { Icon } from "../../design/icons";
import { assistantApi, type AppEntry, type NowPlaying } from "../../ipc/assistant";
import { settingsApi } from "../../ipc/settings";
import { activeRemote, securityLevel } from "../../state/derive";
import { useGhost } from "../../state/store";
import "./lair.css";

const STATE_TEXT: Record<Mode, string> = {
  idle: "seni izliyor",
  listening: "dinliyor…",
  thinking: "düşünüyor…",
  speaking: "konuşuyor",
};

function Frame({ title, aside, className = "", children }: { title?: string; aside?: React.ReactNode; className?: string; children: React.ReactNode }) {
  return (
    <section className={`lair-frame ${className}`}>
      {title && (
        <header>
          <h2>{title}</h2>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

/** Filled sparkline of the last values, scaled to `max` (or the series peak). */
function Spark({ values, max }: { values: number[]; max?: number }) {
  const v = values.slice(-90);
  if (v.length < 2) return <div className="lair-spark lair-spark--empty" />;
  const top = Math.max(max ?? 0, ...v, 1e-9);
  const pts = v.map((y, i) => `${(i / (v.length - 1)) * 100},${30 - (y / top) * 28}`);
  return (
    <svg className="lair-spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true">
      <path d={`M0,30 L${pts.join(" L")} L100,30 Z`} className="fill" />
      <path d={`M${pts.join(" L")}`} className="line" />
    </svg>
  );
}

function Ring({ value, label }: { value: number | null; label: string }) {
  const p = value === null ? 0 : Math.max(0, Math.min(100, value));
  const c = 2 * Math.PI * 22;
  return (
    <div className="lair-ring">
      <svg viewBox="0 0 52 52" aria-hidden="true">
        <circle cx="26" cy="26" r="22" className="track" />
        <circle cx="26" cy="26" r="22" className="val" strokeDasharray={`${(p / 100) * c} ${c}`} transform="rotate(-90 26 26)" />
      </svg>
      <b>{value === null ? "—" : `${Math.round(p)}%`}</b>
      <span>{label}</span>
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  const uptime = useGhost((s) => s.metrics?.uptime);
  return (
    <Frame className="lair-clock">
      <time>{now.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
      <p>
        {now.toLocaleDateString("tr-TR", { day: "2-digit", month: "2-digit", year: "numeric" })}{" "}
        {now.toLocaleDateString("tr-TR", { weekday: "long" })}
      </p>
      {uptime !== undefined && <small>Bilgisayar {duration(uptime)} açık</small>}
    </Frame>
  );
}

function SystemPanel() {
  const m = useGhost((s) => s.metrics);
  const cpu = useGhost((s) => s.series.cpu);
  const disk = m?.disks.find((d) => d.mount.toUpperCase().startsWith("C:")) ?? m?.disks[0];
  const diskUsed = disk && disk.total > 0 ? ((disk.total - disk.available) / disk.total) * 100 : null;
  return (
    <Frame title="Sistem" aside={m && <span>{m.processCount} işlem</span>}>
      <Spark values={cpu} max={100} />
      <div className="lair-rings">
        <Ring value={m ? m.cpu : null} label="İşlemci" />
        <Ring value={m ? (m.memUsed / Math.max(1, m.memTotal)) * 100 : null} label={m ? `Bellek ${bytes(m.memUsed, 0)}` : "Bellek"} />
        <Ring value={diskUsed} label={disk ? `Disk ${disk.mount.replace("\\", "")}` : "Disk"} />
      </div>
    </Frame>
  );
}

function NetworkPanel() {
  const m = useGhost((s) => s.metrics);
  const rx = useGhost((s) => s.series.rx);
  const conns = useGhost((s) => s.connections);
  const remote = useMemo(() => activeRemote(conns).length, [conns]);
  const setModule = useGhost((s) => s.setModule);
  return (
    <Frame title="Ağ" aside={<button className="lair-link" onClick={() => setModule("network")}>Ağ Gözcüsü</button>}>
      <Spark values={rx} />
      <dl className="lair-net">
        <dt>İndirme</dt>
        <dd>{m ? rate(m.netRxRate) : "—"}</dd>
        <dt>Yükleme</dt>
        <dd>{m ? rate(m.netTxRate) : "—"}</dd>
        <dt>Dış bağlantı</dt>
        <dd>{remote}</dd>
      </dl>
    </Frame>
  );
}

function Conversation() {
  const lines = useAyla((s) => s.lines);
  const pending = useAyla((s) => s.pending);
  const setModule = useGhost((s) => s.setModule);
  const recent = lines.slice(-7);
  return (
    <Frame title="Konuşma" className="lair-talk" aside={lines.length > 0 && <span>{lines.length} satır</span>}>
      <div className="lair-talk__log">
        {recent.length === 0 && <p className="lair-muted">Henüz konuşmadık. Aşağıya yazın ya da Konuş'a basın.</p>}
        {recent.map((l) => (
          <p
            key={l.id}
            className={`is-${l.who}`}
            onClick={l.who === "alert" ? () => setModule("threat") : undefined}
          >
            {l.text}
          </p>
        ))}
      </div>
      {pending && (
        <div className="lair-confirm">
          <span>{pending.question}</span>
          <button className="btn btn--danger" onClick={() => handle("evet")}>
            Evet
          </button>
          <button className="btn" onClick={() => handle("hayır")}>
            Hayır
          </button>
        </div>
      )}
    </Frame>
  );
}

function Watch({ name }: { name: string }) {
  const findings = useGhost((s) => s.findings);
  const level = useMemo(() => securityLevel(findings), [findings]);
  const mode = useAyla((s) => s.mode);
  const setModule = useGhost((s) => s.setModule);
  const active = findings.filter((f) => f.severity !== "INFO").length;
  return (
    <button className={`lair-frame lair-watch tone-${level.tone}`} onClick={() => setModule("threat")} title="Tehdit ekranını aç">
      <Icon.threat width={26} height={26} />
      <span>
        <b>{name}</b>
        <i>{STATE_TEXT[mode]}</i>
      </span>
      <span className="lair-watch__lvl">
        <b>{level.word}</b>
        <i>{active ? `${active} etkin bulgu · indeks ${level.index}` : `indeks ${level.index}/100`}</i>
      </span>
    </button>
  );
}

function QuickAccess() {
  const setModule = useGhost((s) => s.setModule);
  const notify = useGhost((s) => s.notify);
  const launch = useCallback(
    async (name: string) => {
      try {
        const [hit] = await assistantApi.findApp(name);
        if (!hit) throw new Error(`${name} bulunamadı`);
        await assistantApi.launch(hit.target);
      } catch (e) {
        notify(String(e instanceof Error ? e.message : e), "bad");
      }
    },
    [notify],
  );
  const items: [string, (p: React.SVGProps<SVGSVGElement>) => React.ReactElement, () => void][] = [
    ["Komut İstemi", Icon.terminal, () => launch("Komut İstemi")],
    ["Dosya Gezgini", Icon.folder, () => launch("Dosya Gezgini")],
    ["Tarayıcı", Icon.sonar, () => void assistantApi.openUrl("https://www.google.com").catch((e) => notify(String(e), "bad"))],
    ["Görev Yöneticisi", Icon.lineage, () => launch("Görev Yöneticisi")],
    ["Tehditler", Icon.threat, () => setModule("threat")],
    ["Ayarlar", Icon.settings, () => setModule("settings")],
  ];
  return (
    <Frame title="Hızlı erişim">
      <ul className="lair-quick">
        {items.map(([label, Ico, run]) => (
          <li key={label}>
            <button onClick={run}>
              <Ico width={20} height={20} />
              {label}
            </button>
          </li>
        ))}
      </ul>
    </Frame>
  );
}

function appName(id: string) {
  const base = id.split("!")[0].split("\\").pop() ?? id;
  const clean = base.replace(/\.exe$/i, "").split("_")[0];
  return clean.split(".").pop() || clean;
}

const clock = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

function Media() {
  const [np, setNp] = useState<NowPlaying | null>(null);
  const [err, setErr] = useState(false);
  const [tick, setTick] = useState(0);
  const notify = useGhost((s) => s.notify);
  const refresh = useCallback(() => {
    assistantApi.mediaNow().then(
      (v) => {
        setNp(v);
        setErr(false);
        setTick(0);
      },
      () => setErr(true),
    );
  }, []);
  useEffect(() => {
    refresh();
    const poll = window.setInterval(refresh, 3000);
    const sec = window.setInterval(() => setTick((t) => t + 1), 1000);
    return () => {
      window.clearInterval(poll);
      window.clearInterval(sec);
    };
  }, [refresh]);
  const act = (a: "toggle" | "next" | "prev") =>
    assistantApi.mediaControl(a).then(
      () => window.setTimeout(refresh, 400),
      (e) => notify(String(e), "warn"),
    );
  const pos = np?.position != null && np.duration ? Math.min(np.duration, np.position + (np.playing ? tick : 0)) : null;
  return (
    <Frame title="Şimdi çalıyor" aside={np && <span>{appName(np.app)}</span>}>
      {!np ? (
        <p className="lair-muted">{err ? "Windows medya bilgisi okunamadı." : "Şu anda çalan bir şey yok."}</p>
      ) : (
        <div className="lair-media">
          <b title={np.title}>{np.title}</b>
          <span>{np.artist || "Sanatçı bilgisi yok"}</span>
          {pos !== null && np.duration ? (
            <div className="lair-media__bar">
              <i style={{ width: `${(pos / np.duration) * 100}%` }} />
              <small>
                {clock(pos)} / {clock(np.duration)}
              </small>
            </div>
          ) : null}
          <div className="lair-media__ctl">
            <button onClick={() => act("prev")} aria-label="Önceki">
              ⏮
            </button>
            <button onClick={() => act("toggle")} aria-label={np.playing ? "Duraklat" : "Oynat"} className="is-main">
              {np.playing ? "⏸" : "▶"}
            </button>
            <button onClick={() => act("next")} aria-label="Sonraki">
              ⏭
            </button>
          </div>
        </div>
      )}
    </Frame>
  );
}

/** Programs from the Start menu index that are worth a one-click launch, if installed. */
const LAUNCH_WANTED = ["Opera", "Chrome", "Firefox", "Discord", "Spotify", "Visual Studio Code", "Steam", "Not Defteri"];

function Launchers() {
  const [apps, setApps] = useState<AppEntry[]>([]);
  const notify = useGhost((s) => s.notify);
  useEffect(() => {
    let live = true;
    Promise.all(LAUNCH_WANTED.map((q) => assistantApi.findApp(q).then((r) => r[0], () => undefined))).then((hits) => {
      if (!live) return;
      const seen = new Set<string>();
      setApps(
        hits
          .filter((h): h is AppEntry => !!h && h.score >= 80)
          .filter((h) => (seen.has(h.target) ? false : (seen.add(h.target), true)))
          .slice(0, 7),
      );
    });
    return () => {
      live = false;
    };
  }, []);
  if (!apps.length) return null;
  return (
    <nav className="lair-launch" aria-label="Programlar">
      {apps.map((a) => (
        <button key={a.target} onClick={() => assistantApi.launch(a.target).catch((e) => notify(String(e), "bad"))} title={`${a.name} aç`}>
          {a.name}
        </button>
      ))}
    </nav>
  );
}

export default function Lair() {
  const { mode, alert, subtitle } = useAyla();
  const talk = useAyla((s) => s.talk);
  const [name, setName] = useState("Ayla");
  const [text, setText] = useState("");
  useEffect(() => {
    settingsApi.get().then((s) => setName(s.assistantName || "Ayla"), () => {});
  }, []);
  const level = useCallback(() => voice.level(), []);
  const submit = () => {
    const v = text.trim();
    setText("");
    if (v) void handle(v);
  };
  const tone = alert ? `is-${alert.toLowerCase()}` : `is-${mode}`;

  return (
    <div className={`lair ${tone}`}>
      <div className="lair-col">
        <Clock />
        <SystemPanel />
        <NetworkPanel />
        <Conversation />
      </div>

      <div className="lair-stage">
        <Hologram mode={mode} alert={alert} level={level} variant="stage" />
        {subtitle && <p className="lair-sub">{subtitle}</p>}
        <div className="lair-bottom">
          <Launchers />
          <form
            className="lair-input"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <button type="button" className={`lair-mic${mode === "listening" ? " is-on" : ""}`} onClick={talk} title="Konuşmak için basın (Ctrl+Boşluk)">
              {mode === "listening" ? "Bitir" : "Konuş"}
            </button>
            <input
              className="field"
              value={text}
              placeholder="Yazın ya da Ctrl+Boşluk ile konuşun…"
              onChange={(e) => setText(e.target.value)}
              aria-label="Mesaj"
            />
          </form>
        </div>
      </div>

      <div className="lair-col">
        <Watch name={name} />
        <QuickAccess />
        <Media />
      </div>
    </div>
  );
}
