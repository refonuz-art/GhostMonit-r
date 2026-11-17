// Turkish command understanding that works without any API key.
// Phrases are matched with rules ordered from most to least specific; anything else goes
// to Claude when a key is configured.
import type { ModuleId } from "../state/store";

export type Intent =
  | { kind: "stop" }
  | { kind: "yes" }
  | { kind: "no" }
  | { kind: "mute" }
  | { kind: "unmute" }
  | { kind: "time" }
  | { kind: "date" }
  | { kind: "weather"; city: string | null; when: "now" | "tomorrow" }
  | { kind: "status" }
  | { kind: "alerts" }
  | { kind: "health" }
  | { kind: "lanScan" }
  | { kind: "search"; engine: "google" | "youtube"; query: string }
  | { kind: "block"; target: string }
  | { kind: "freeze"; target: string }
  | { kind: "kill"; target: string }
  | { kind: "quarantine" }
  | { kind: "module"; id: ModuleId; label: string }
  | { kind: "open"; target: string; site: string | null }
  | { kind: "greet" }
  | { kind: "who" }
  | { kind: "thanks" }
  | { kind: "help" }
  | { kind: "unknown"; text: string };

const L = "a-zçğıöşüâîû0-9";

export function normalize(text: string, name = ""): string {
  let t = text
    .toLocaleLowerCase("tr-TR")
    .replace(/[’`´]/g, "'")
    // Dots inside numbers stay (IP addresses); sentence punctuation goes.
    .replace(/(?<![0-9])\.|\.(?![0-9])/g, " ")
    .replace(/[!?,;:"“”]+/g, " ")
    .replace(/\blütfen\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const n = name.toLocaleLowerCase("tr-TR").trim();
  for (const w of [n, "hey " + n, "selam " + n]) {
    if (n && t.startsWith(w + " ")) t = t.slice(w.length + 1).trim();
  }
  return t;
}

/** "chrome'u" → "chrome"; words without an apostrophe are left for fuzzy matching. */
export function stripSuffix(word: string): string {
  const i = word.indexOf("'");
  return i > 0 ? word.slice(0, i) : word;
}

export const SITES: Record<string, string> = {
  youtube: "https://www.youtube.com",
  google: "https://www.google.com",
  gmail: "https://mail.google.com",
  whatsapp: "https://web.whatsapp.com",
  instagram: "https://www.instagram.com",
  twitter: "https://x.com",
  facebook: "https://www.facebook.com",
  netflix: "https://www.netflix.com",
  spotify: "https://open.spotify.com",
  github: "https://github.com",
  "hava durumu": "https://www.mgm.gov.tr",
};

export const MODULE_WORDS: [string, ModuleId, string][] = [
  ["komuta", "command", "Komuta"],
  ["ana ekran", "command", "Komuta"],
  ["işlem", "process", "İşlem Avcısı"],
  ["ağ gözcüsü", "network", "Ağ Gözcüsü"],
  ["ağ", "network", "Ağ Gözcüsü"],
  ["bağlantı", "network", "Ağ Gözcüsü"],
  ["tehdit", "threat", "Tehdit"],
  ["dosya", "file", "Dosya"],
  ["açılış", "startup", "Açılış"],
  ["başlangıç", "startup", "Açılış"],
  ["zaman çizelgesi", "timeline", "Zaman Çizelgesi"],
  ["olay", "timeline", "Zaman Çizelgesi"],
  ["terminal", "terminal", "Terminal"],
  ["rapor", "report", "Rapor"],
  ["sağlık", "health", "Sağlık"],
  ["koruma", "health", "Sağlık"],
  ["ayar", "settings", "Ayarlar"],
];

/** A module named by `phrase` ("sağlık ekranını", "tehdit sekmesi", "ayarları"). */
export function moduleOf(phrase: string, loose: boolean): { id: ModuleId; label: string } | null {
  const p = phrase.replace(/\b(ekran|sekme|modül|sayfa|bölüm|kısm)\p{L}*/gu, "").trim();
  const screenWord = p !== phrase.trim();
  if (!loose && !screenWord) return null;
  for (const [w, id, label] of MODULE_WORDS) {
    const soft = w.replace(/k$/, "ğ");
    for (const base of [w, soft]) {
      if (p === base || (p.startsWith(base) && p.length - base.length <= 4 && !p.slice(base.length).includes(" ")))
        return { id, label };
    }
  }
  return null;
}

const CITY_STOP = new Set(["dışarı", "bura", "şura", "ora", "ev", "bugün", "yarın", "şimdi", "hava", "nasıl", "ne", "nedir", "söyle", "için", "ver", "kaç", "olacak", "durumu"]);

// Filler words around a program or address name. (JS \b doesn't understand Turkish letters,
// so words are compared whole instead of with regex boundaries.)
const DROP = new Set(
  "program programı programını programının uygulama uygulaması uygulamasını uygulamasının adres adresi adresini ip işlem işlemi işlemini internetini internet bağlantısını erişimini şu bu".split(
    " ",
  ),
);

function cleanTarget(t: string): string {
  return t
    .split(" ")
    .filter((w) => w && !DROP.has(w))
    .map(stripSuffix)
    .join(" ")
    .trim();
}

export function parse(input: string, name = ""): Intent {
  const t = normalize(input, name);
  if (!t) return { kind: "unknown", text: "" };
  let m: RegExpMatchArray | null;

  if (/^(sus|dur|yeter|kes|tamam yeter|sessiz)$/.test(t)) return { kind: "stop" };
  if (/^(evet|onaylıyorum|onayla|yap|tamam|olur|devam)(?=\s|$)/.test(t)) return { kind: "yes" };
  if (/^(hayır|iptal|vazgeç|yapma|istemiyorum|boş ver)(?=\s|$)/.test(t)) return { kind: "no" };
  if (/(uyarıları sustur|sessize al|sessiz ol|sesini kapat|sessiz mod)/.test(t)) return { kind: "mute" };
  if (/(uyarıları (aç|oku) ?$|sesini aç|konuşabilirsin|sessiz modu kapat)/.test(t)) return { kind: "unmute" };

  if (/(saat kaç|saati söyle|saat şu an)/.test(t)) return { kind: "time" };
  if (/(bugün(ün)? (tarih|günlerden|ayın kaçı|ne günü)|tarih(i)? (ne|söyle)|hangi gündeyiz|günlerden ne)/.test(t))
    return { kind: "date" };

  if (/\bhava\b|kaç derece|yağmur yağacak|şemsiye/.test(t) && !/^hava durumu (sitesini|sayfasını) aç/.test(t)) {
    const when = /\byarın/.test(t) ? "tomorrow" : "now";
    let city: string | null = null;
    m =
      t.match(new RegExp(`([${L}]+?)'?(?:da|de|ta|te|daki|deki) (?:hava|bugün|yarın|kaç)`)) ??
      t.match(new RegExp(`hava durumu ([${L}]+)`)) ??
      t.match(new RegExp(`([${L}]+?)'?(?:nın|nin|nun|nün|ın|in|un|ün)? için hava`));
    if (m && !CITY_STOP.has(m[1]) && m[1].length > 2) city = stripSuffix(m[1]);
    return { kind: "weather", city, when };
  }

  if (/(sağlık (puanı|skoru|durumu)|güvenlik (puanı|skoru|durumu)|puanım)/.test(t)) return { kind: "health" };
  if (/(ağı tara|ağ taraması|ağdaki cihaz|ağda kim|cihazları tara)/.test(t)) return { kind: "lanScan" };
  if (/(son (uyarı|olay|bulgu)|uyarıları (oku|söyle|göster)|ne oldu|tehdit var mı|şüpheli (bir şey|bir durum|durum) var mı)/.test(t))
    return { kind: "alerts" };
  if (
    /(durum(u|un)? (nasıl|ne)|sistem(in)? (nasıl|durumu)|bilgisayar(ım)? nasıl|durum raporu|genel durum|her şey yolunda mı|özet (ver|geç)|neler oluyor)/.test(
      t,
    )
  )
    return { kind: "status" };

  if ((m = t.match(/^youtube'?(?:da|de|ta) (.+?) (?:aç|ara|oynat|bul|izle)$/) ?? t.match(/^(.+?) youtube'?(?:da|de|ta) (?:aç|ara|oynat|bul)$/)))
    return { kind: "search", engine: "youtube", query: m[1] };
  if (
    (m =
      t.match(/^(?:google'?da|internette|webde) (.+?) (?:ara|arat|bul)$/) ??
      t.match(/^(.+?) (?:diye )?(?:google'?da|internette|webde) (?:ara|arat)$/))
  )
    return { kind: "search", engine: "google", query: m[1] };

  if (/karantina/.test(t)) return { kind: "quarantine" };

  if ((m = t.match(/^(.+?) (?:engelle|blokla|blokle|bloke et|internetini kes|bağlantısını kes)$/))) {
    const target = cleanTarget(m[1]);
    if (target) return { kind: "block", target };
  }
  if ((m = t.match(/^(.+?) (?:dondur|askıya al)$/))) {
    const target = cleanTarget(m[1]);
    if (target) return { kind: "freeze", target };
  }
  if ((m = t.match(/^(.+?) (?:kapat|sonlandır|öldür)$/)) && !/^(ses|kendi|asistan|pencere|seni)/.test(m[1])) {
    const target = cleanTarget(m[1]);
    if (target) return { kind: "kill", target };
  }

  if ((m = t.match(/^(.+?) (?:aç|başlat|çalıştır|göster|git|geç|gel)$/) ?? t.match(/^(?:aç|başlat|çalıştır) (.+)$/))) {
    const target = cleanTarget(m[1]);
    const mod = moduleOf(m[1], false) ?? moduleOf(target, true);
    if (mod) return { kind: "module", ...mod };
    const site = Object.entries(SITES).find(([k]) => target === k || target.startsWith(k))?.[1] ?? null;
    if (target) return { kind: "open", target, site };
  }

  if (/^(merhaba|selam|hey|günaydın|iyi akşamlar|iyi geceler|naber|nasılsın)/.test(t)) return { kind: "greet" };
  if (/(kimsin|adın ne|sen kimsin|kendini tanıt)/.test(t)) return { kind: "who" };
  if (/(teşekkür|sağ ol|eyvallah|çok iyisin)/.test(t)) return { kind: "thanks" };
  if (/(neler yapabilirsin|ne yapabiliyorsun|yardım|komutlar)/.test(t)) return { kind: "help" };
  return { kind: "unknown", text: t };
}
