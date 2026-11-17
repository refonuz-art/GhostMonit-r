// What the assistant does with a sentence: local Turkish commands first, Claude for the
// rest (when a key is configured). Every action that changes the system (block, freeze,
// close) waits for an explicit "evet".
import { api } from "../ipc/api";
import { assistantApi, type ClaudeBlock, type ClaudeMessage } from "../ipc/assistant";
import { guard } from "../ipc/guard";
import type { ProcessInfo, Severity } from "../ipc/types";
import { useGhost, type ModuleId } from "../state/store";
import { parse, MODULE_WORDS, type Intent } from "./intents";
import { useAyla } from "./store";
import * as voice from "./voice";

const SEV_RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const SEV_TR: Record<Severity, string> = { INFO: "bilgi", LOW: "düşük", MEDIUM: "orta", HIGH: "yüksek", CRITICAL: "kritik" };

let assistantName = "Ayla";
let claudeReady = false;

export function configureAgent(name: string, claude: boolean) {
  assistantName = name;
  claudeReady = claude;
}

export function fold(s: string): string {
  return s
    .toLocaleLowerCase("tr-TR")
    .replace(/ı/g, "i")
    .replace(/ş/g, "s")
    .replace(/ğ/g, "g")
    .replace(/ü/g, "u")
    .replace(/ö/g, "o")
    .replace(/ç/g, "c")
    .replace(/[^a-z0-9]/g, "");
}

/** Running processes named like `target` ("chrome" → chrome.exe), user programs first. */
export function findProcesses(target: string, all: ProcessInfo[]): ProcessInfo[] {
  const q = fold(target);
  if (q.length < 2) return [];
  const base = (p: ProcessInfo) => fold(p.name.replace(/\.exe$/i, ""));
  const exact = all.filter((p) => base(p) === q);
  const hits = exact.length ? exact : all.filter((p) => base(p).startsWith(q) || (q.startsWith(base(p)) && q.length - base(p).length <= 4 && base(p).length >= 3));
  return hits.filter((p) => p.pid > 4);
}

const IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;

const round = (n: number) => {
  const r = Math.round(n);
  return r < 0 ? `eksi ${-r}` : String(r);
};

/** Turkish locative suffix with vowel harmony: Ankara'da, İzmir'de, Paris'te. */
export function loc(word: string): string {
  const w = word.toLocaleLowerCase("tr-TR");
  const vowel = [...w].reverse().find((c) => "aıoueiöü".includes(c)) ?? "e";
  const v = "aıou".includes(vowel) ? "a" : "e";
  const c = "fstkçşhp".includes(w.slice(-1)) ? "t" : "d";
  return `${word}'${c}${v}`;
}

function greeting() {
  const h = new Date().getHours();
  return h < 6 ? "İyi geceler" : h < 11 ? "Günaydın" : h < 18 ? "İyi günler" : "İyi akşamlar";
}

function ask(question: string, run: () => Promise<string>): string {
  useAyla.getState().setPending({ question, run });
  return `${question} Onaylıyorsanız “evet”, vazgeçmek için “hayır” deyin.`;
}

async function weather(city: string | null, when: "now" | "tomorrow"): Promise<string> {
  const w = await assistantApi.weather(city);
  if (when === "tomorrow" && w.tomorrow) {
    const d = w.tomorrow;
    const rain = d.rainChance != null ? ` Yağış ihtimali yüzde ${round(d.rainChance)}.` : "";
    return `Yarın ${w.place} için hava ${d.sky}; sıcaklık ${round(d.min)} ile ${round(d.max)} derece arasında olacak.${rain}`;
  }
  let s = `${loc(w.place)} şu an ${round(w.temp)} derece, hava ${w.sky}.`;
  if (Number.isFinite(w.feels) && Math.abs(w.feels - w.temp) >= 2) s += ` Hissedilen ${round(w.feels)} derece.`;
  if (w.today) {
    s += ` Bugün en yüksek ${round(w.today.max)}, en düşük ${round(w.today.min)} derece`;
    s += w.today.rainChance != null && w.today.rainChance >= 30 ? `; yağış ihtimali yüzde ${round(w.today.rainChance)}, şemsiyenizi unutmayın.` : ".";
  }
  return s;
}

function status(): string {
  const st = useGhost.getState();
  const open = st.findings.filter((f) => f.status !== "dismissed");
  const worst = open.reduce<Severity | null>((w, f) => (!w || SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), null);
  const m = st.metrics;
  const parts: string[] = [];
  if (!open.length) parts.push("Her şey sakin görünüyor, açık bir bulgu yok.");
  else parts.push(`${open.length} açık bulgu var; en ciddisi ${SEV_TR[worst!]} seviyede.`);
  if (m) {
    const mem = (m.memUsed / Math.max(1, m.memTotal)) * 100;
    parts.push(`İşlemci yüzde ${round(m.cpu)}, bellek yüzde ${round(mem)} kullanımda.`);
  }
  parts.push(`${st.processes.length} işlem ve ${st.connections.length} ağ bağlantısı izleniyor.`);
  return parts.join(" ");
}

function alerts(): string {
  const day = Date.now() - 24 * 3600_000;
  const evs = useGhost.getState().liveEvents.filter((e) => e.ts >= day && SEV_RANK[e.severity] >= 2).slice(0, 3);
  if (!evs.length) return "Son yirmi dört saatte orta veya daha ciddi bir uyarı yok. Şüpheli bir durum görmüyorum.";
  const list = evs.map((e) => `${SEV_TR[e.severity]} seviyede: ${e.title}`).join(". ");
  return `Son uyarılar şunlar. ${list}.`;
}

async function health(): Promise<string> {
  const g = await guard.state();
  const h = g.health;
  if (!h) return "Sağlık kontrolleri henüz bitmedi, birazdan tekrar sorun.";
  const bad = h.checks.filter((c) => c.status === "bad").map((c) => c.label);
  const warn = h.checks.filter((c) => c.status === "warn").map((c) => c.label);
  let s = `Güvenlik puanınız yüzde ${h.score}, durum ${h.grade.toLocaleLowerCase("tr-TR")}.`;
  if (bad.length) s += ` Düzeltilmesi gerekenler: ${bad.slice(0, 3).join(", ")}.`;
  else if (warn.length) s += ` Dikkat edilmesi gerekenler: ${warn.slice(0, 3).join(", ")}.`;
  else s += " Tüm kontroller yolunda.";
  return s;
}

async function openTarget(target: string, site: string | null): Promise<string> {
  const apps = await assistantApi.findApp(target);
  const best = apps[0];
  if (best && best.score >= 60) {
    const name = await assistantApi.launch(best.target);
    return `${name} açılıyor.`;
  }
  if (site) {
    await assistantApi.openUrl(site);
    return `${target.charAt(0).toLocaleUpperCase("tr-TR") + target.slice(1)} tarayıcıda açılıyor.`;
  }
  return `“${target}” adında bir program bulamadım. Başlat menüsündeki adını söylerseniz açabilirim.`;
}

function blockAction(target: string): string {
  if (IP.test(target)) {
    return ask(`${target} adresiyle tüm bağlantıları güvenlik duvarından engelleyeyim mi? Windows izin isteyecek.`, async () => {
      const r = await guard.block("ip", target);
      return `${r.target} adresi engellendi. Kuralı Sağlık ekranındaki Engellenenler bölümünden kaldırabilirsiniz.`;
    });
  }
  const procs = findProcesses(target, useGhost.getState().processes).filter((p) => p.exe);
  if (!procs.length) return `Şu an “${target}” adında çalışan bir program görmüyorum. Engellemek için önce çalışıyor olması gerekiyor.`;
  const exe = procs[0].exe!;
  return ask(`${procs[0].name} programının internet erişimini keseyim mi? Windows izin isteyecek.`, async () => {
    await guard.block("program", exe);
    return `${procs[0].name} artık internete çıkamıyor.`;
  });
}

function freezeAction(target: string): string {
  const procs = findProcesses(target, useGhost.getState().processes).filter((p) => !p.critical);
  if (!procs.length) return `“${target}” adında dondurabileceğim bir işlem bulamadım.`;
  return ask(`${procs[0].name} için ${procs.length} işlemi dondurayım mı? Program kapanmaz, yalnızca durur.`, async () => {
    let ok = 0;
    for (const p of procs) await guard.suspend(p.pid, true).then(() => ok++, () => {});
    return ok ? `${ok} işlem donduruldu. İşlem Avcısı'ndan devam ettirebilirsiniz.` : "İşlemleri donduramadım; yönetici izni gerekebilir.";
  });
}

function killAction(target: string): string {
  const procs = findProcesses(target, useGhost.getState().processes);
  if (!procs.length) return `“${target}” adında çalışan bir program bulamadım.`;
  if (procs.some((p) => p.critical)) return `${procs[0].name} kritik bir sistem işlemi. Bunu sesli komutla kapatmayacağım; gerekirse İşlem Avcısı'ndan yapabilirsiniz.`;
  return ask(`${procs[0].name} programını kapatayım mı? Kaydedilmemiş işler kaybolabilir.`, async () => {
    let ok = 0;
    let msg = "";
    for (const p of procs) {
      const r = await api.killProcess(p.pid, false);
      if (r.ok) ok++;
      else msg = r.message;
    }
    return ok ? `${procs[0].name} kapatıldı.` : `Kapatamadım. ${msg}`;
  });
}

const HELP =
  "Şunları yapabilirim: program açmak, örneğin “Opera'yı aç”. Hava durumunu söylemek. Durum özeti vermek ve son uyarıları okumak. " +
  "Ağı taramak. Bir programın internetini kesmek, dondurmak ya da kapatmak; bunları onayınızla yaparım. " +
  "Google'da veya YouTube'da arama yapmak. Ekranlar arasında geçiş yapmak, örneğin “sağlık ekranını aç”.";

/** Run a parsed command; returns what to say. `null` = not a local command. */
export async function execute(i: Intent): Promise<string | null> {
  const st = useGhost.getState();
  const ay = useAyla.getState();
  switch (i.kind) {
    case "stop":
      voice.stop();
      return "";
    case "yes": {
      const p = ay.pending;
      if (!p) return "Tamam.";
      ay.setPending(null);
      try {
        return await p.run();
      } catch (e) {
        return `Yapamadım: ${String(e)}`;
      }
    }
    case "no":
      if (ay.pending) {
        ay.setPending(null);
        return "Peki, vazgeçtim. Hiçbir şey değiştirmedim.";
      }
      return "Peki.";
    case "mute":
      ay.setMuted(true);
      return "Uyarıları artık sesli okumayacağım, yalnızca ekranda göstereceğim.";
    case "unmute":
      ay.setMuted(false);
      return "Tamam, önemli uyarıları yeniden sesli bildireceğim.";
    case "time": {
      const d = new Date();
      return `Saat ${d.getHours()}.${String(d.getMinutes()).padStart(2, "0")}.`;
    }
    case "date":
      return `Bugün ${new Date().toLocaleDateString("tr-TR", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}.`;
    case "weather":
      return weather(i.city, i.when);
    case "status":
      return status();
    case "alerts":
      return alerts();
    case "health":
      return health();
    case "lanScan": {
      const n = await guard.lanSweep();
      return `Ağ taraması bitti; ${n} cihaz yanıt verdi. Ayrıntılar Sağlık ekranının Ağ bölümünde.`;
    }
    case "search": {
      const q = encodeURIComponent(i.query);
      await assistantApi.openUrl(i.engine === "youtube" ? `https://www.youtube.com/results?search_query=${q}` : `https://www.google.com/search?q=${q}`);
      return `${i.engine === "youtube" ? "YouTube'da" : "Google'da"} “${i.query}” için arama açıyorum.`;
    }
    case "quarantine":
      useGhost.setState({ healthTab: "quarantine" });
      st.setModule("health");
      return "Karantina listesini açtım. Bir dosyayı karantinaya almak için Tehdit ekranındaki “Karantinaya al” düğmesini kullanabilirsiniz.";
    case "block":
      return blockAction(i.target);
    case "freeze":
      return freezeAction(i.target);
    case "kill":
      return killAction(i.target);
    case "module":
      st.setModule(i.id);
      return `${i.label} ekranını açtım.`;
    case "open":
      return openTarget(i.target, i.site);
    case "greet":
      return `${greeting()}. Ben ${assistantName}. Sistemi izliyorum; şüpheli bir şey olursa hemen haber veririm.`;
    case "who":
      return `Ben ${assistantName}, Ghost Monitor'ün yapay zekâ asistanıyım. Bilgisayarınızı izliyor, şüpheli bir durumda sizi sesli uyarıyorum. Program açabilir, hava durumunu söyleyebilir, bir programın internetini kesebilirim.`;
    case "thanks":
      return "Rica ederim, buradayım.";
    case "help":
      return HELP;
    case "unknown":
      return null;
  }
}

// ---------------------------------------------------------------- Claude (optional)

const SCREENS = MODULE_WORDS.map(([, id]) => id).filter((v, i, a) => a.indexOf(v) === i);

const TOOLS = [
  {
    name: "open_program",
    description: "Bilgisayarda kurulu bir programı Başlat menüsündeki adıyla açar (ör. Opera, Spotify, Hesap Makinesi).",
    input_schema: { type: "object", properties: { name: { type: "string" } }, required: ["name"], additionalProperties: false },
    strict: true,
  },
  {
    name: "open_search",
    description: "Kullanıcının tarayıcısında Google veya YouTube araması açar.",
    input_schema: {
      type: "object",
      properties: { query: { type: "string" }, site: { type: "string", enum: ["google", "youtube"] } },
      required: ["query", "site"],
      additionalProperties: false,
    },
    strict: true,
  },
  {
    name: "go_to_screen",
    description: "Ghost Monitor'de bir ekrana geçer.",
    input_schema: {
      type: "object",
      properties: { screen: { type: "string", enum: SCREENS } },
      required: ["screen"],
      additionalProperties: false,
    },
    strict: true,
  },
  {
    name: "get_weather",
    description: "Hava durumunu getirir. Şehir verilmezse kullanıcının ayarlardaki şehri kullanılır.",
    input_schema: {
      type: "object",
      properties: { city: { type: ["string", "null"] }, day: { type: "string", enum: ["now", "tomorrow"] } },
      required: ["city", "day"],
      additionalProperties: false,
    },
    strict: true,
  },
  {
    name: "security_status",
    description: "Bilgisayarın anlık güvenlik durumu: açık bulgular, işlemci/bellek, son uyarılar ve güvenlik puanı.",
    input_schema: { type: "object", properties: {}, additionalProperties: false },
    strict: true,
  },
  {
    name: "protect",
    description:
      "Bir programa veya IP adresine güvenlik eylemi uygular: block = internetini keser, freeze = dondurur, close = kapatır. Uygulama kullanıcıdan sesli onay ister; onay gelmeden hiçbir şey yapılmaz.",
    input_schema: {
      type: "object",
      properties: { action: { type: "string", enum: ["block", "freeze", "close"] }, target: { type: "string" } },
      required: ["action", "target"],
      additionalProperties: false,
    },
    strict: true,
  },
  {
    name: "scan_network",
    description: "Ev ağındaki cihazları tarar ve kaç cihazın yanıt verdiğini söyler.",
    input_schema: { type: "object", properties: {}, additionalProperties: false },
    strict: true,
  },
  { type: "web_search_20260209", name: "web_search", max_uses: 3 },
];

function systemPrompt() {
  return (
    `Sen ${assistantName}'sın: Ghost Monitor adlı Windows güvenlik uygulamasının sesli yapay zekâ asistanısın. ` +
    "Sakin, kendinden emin, sıcak ve kibar bir kadın sesiyle konuşuyorsun; kullanıcıya “siz” diye hitap ediyorsun. " +
    "Yanıtların sesli okunacak: doğal, akıcı ve doğru Türkçeyle, çoğunlukla bir ila üç kısa cümle kur. " +
    "Madde işareti, başlık, emoji, kod bloğu ya da bağlantı adresi yazma; sayıları ve kısaltmaları okunacak gibi yaz. " +
    "Bilgisayarda bir şey yapmak gerektiğinde araçları kullan. Güncel bilgi gerektiren sorularda web aramasını kullan. " +
    "Güvenlik verisi uydurma; bilmediğin ya da ölçülmeyen bir şeyi bilmediğini söyle. " +
    "protect aracı kullanıcı onayı ister: onu çağırdıktan sonra kullanıcıdan “evet” ya da “hayır” demesini iste."
  );
}

let history: ClaudeMessage[] = [];

/** Keep the conversation bounded, cutting only at a plain user turn. */
function trim() {
  if (history.length <= 30) return;
  let i = history.length - 30;
  while (i < history.length && !(history[i].role === "user" && typeof history[i].content === "string")) i++;
  history = history.slice(i);
}

async function runTool(name: string, input: Record<string, unknown>): Promise<string> {
  const s = (k: string) => (typeof input[k] === "string" ? (input[k] as string) : "");
  switch (name) {
    case "open_program":
      return openTarget(s("name"), null);
    case "open_search":
      return (await execute({ kind: "search", engine: s("site") === "youtube" ? "youtube" : "google", query: s("query") }))!;
    case "go_to_screen": {
      const hit = MODULE_WORDS.find(([, id]) => id === s("screen"));
      if (!hit) return "Böyle bir ekran yok.";
      useGhost.getState().setModule(hit[1] as ModuleId);
      return `${hit[2]} ekranı açıldı.`;
    }
    case "get_weather":
      return weather(s("city") || null, s("day") === "tomorrow" ? "tomorrow" : "now");
    case "security_status":
      return `${status()} ${alerts()} ${await health().catch(() => "")}`;
    case "protect": {
      const t = s("target");
      const reply = s("action") === "block" ? blockAction(t) : s("action") === "freeze" ? freezeAction(t) : killAction(t);
      return useAyla.getState().pending ? `Onay bekleniyor: ${reply}` : reply;
    }
    case "scan_network":
      return (await execute({ kind: "lanScan" }))!;
    default:
      return "Bilinmeyen araç.";
  }
}

async function converse(text: string): Promise<string> {
  const now = new Date().toLocaleString("tr-TR", { dateStyle: "full", timeStyle: "short" });
  history.push({ role: "user", content: `(${now})\n${text}` });
  trim();
  for (let step = 0; step < 8; step++) {
    const res = await assistantApi.ask(systemPrompt(), history, TOOLS);
    history.push({ role: "assistant", content: res.content });
    if (res.stop_reason === "refusal") return "Bu konuda yardımcı olamıyorum.";
    if (res.stop_reason === "pause_turn") continue;
    const uses = res.content.filter((b): b is Extract<ClaudeBlock, { type: "tool_use" }> => b.type === "tool_use" && "input" in b);
    if (res.stop_reason === "tool_use" && uses.length) {
      const results = [];
      for (const u of uses) {
        let out: string;
        let isError = false;
        try {
          out = await runTool(u.name, u.input ?? {});
        } catch (e) {
          out = String(e);
          isError = true;
        }
        results.push({ type: "tool_result", tool_use_id: u.id, content: out, is_error: isError });
      }
      history.push({ role: "user", content: results });
      continue;
    }
    const said = res.content
      .filter((b): b is { type: "text"; text: string } => b.type === "text" && typeof b.text === "string")
      .map((b) => b.text)
      .join(" ")
      .trim();
    return said || "Tamam.";
  }
  return "Bu iş beklediğimden uzun sürdü, burada duruyorum.";
}

export function resetConversation() {
  history = [];
}

/** One user sentence in, one spoken answer out. */
export async function handle(text: string): Promise<void> {
  const ay = useAyla.getState();
  const clean = text.trim();
  if (!clean) return;
  ay.add("user", clean);
  ay.setMode("thinking");
  let reply: string | null;
  try {
    const intent = parse(clean, assistantName);
    // While a question is pending, only yes/no/stop are local; anything else cancels it.
    if (ay.pending && !["yes", "no", "stop"].includes(intent.kind)) ay.setPending(null);
    reply = await execute(intent);
    if (reply === null) {
      reply = claudeReady
        ? await converse(clean)
        : "Bunu henüz anlayamadım. Serbest sohbet için Ayarlar'dan Claude anahtarı ekleyebilirsiniz. Neler yapabildiğimi duymak için “yardım” deyin.";
    }
  } catch (e) {
    reply = `Bir sorun çıktı: ${String(e).replace(/^Error: /, "")}`;
  }
  ay.setMode("idle");
  if (reply) {
    ay.add("ayla", reply);
    void voice.say(reply);
  }
}
