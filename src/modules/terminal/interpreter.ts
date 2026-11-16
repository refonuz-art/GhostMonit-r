// Ghost Terminal command language. It never spawns a system shell: every command maps to
// a read-only query or a guarded Ghost Monitor action.
import { runCommand } from "../../app/commands";
import { SEV_LABEL } from "../../design/components";
import { bytes, duration, pct, stamp } from "../../design/format";
import { api } from "../../ipc/api";
import { intel } from "../../ipc/intel";
import { SEVERITIES, type Severity } from "../../ipc/types";
import { isListening, openPorts, securityLevel } from "../../state/derive";
import { useGhost } from "../../state/store";

export type Tone = "dim" | "ok" | "warn" | "bad" | "arc" | Severity;
export type Cell = string | { t: string; tone?: Tone };

export type Block =
  | { kind: "text"; text: string; tone?: Tone }
  | { kind: "table"; head: string[]; rows: Cell[][]; right?: number[] }
  | { kind: "kv"; rows: [string, Cell][] };

export interface Outcome {
  blocks: Block[];
  /** Ask the user to type "evet" to run this. */
  confirm?: { prompt: string; run: () => Promise<Outcome> };
  clear?: boolean;
}

interface Spec {
  names: string[];
  usage: string;
  help: string;
  run: (args: string[]) => Promise<Outcome> | Outcome;
}

const t = (text: string, tone?: Tone): Block => ({ kind: "text", text, tone });
const out = (...blocks: Block[]): Outcome => ({ blocks });
const fail = (text: string): Outcome => out(t(text, "bad"));
const sev = (s: Severity | null): Cell => (s ? { t: SEV_LABEL[s], tone: s } : { t: "—", tone: "dim" });
const lower = (s: string) => s.toLocaleLowerCase("tr-TR");

export function tokenize(line: string): string[] {
  const res: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) res.push(m[1] ?? m[2]);
  return res;
}

function procTable(list: ReturnType<typeof useGhost.getState>["processes"]): Block {
  return {
    kind: "table",
    head: ["PID", "AD", "CPU", "BELLEK", "İMZA", "RİSK"],
    right: [0, 2, 3],
    rows: list.map((p) => [
      String(p.pid),
      p.name,
      pct(p.cpu, 1),
      p.memory ? bytes(p.memory) : "—",
      p.signature.state === "signed"
        ? { t: p.signature.publisher ?? "imzalı", tone: "dim" }
        : p.signature.state === "unsigned"
          ? { t: "imzasız", tone: "warn" }
          : p.signature.state === "invalid"
            ? { t: "geçersiz", tone: "bad" }
            : { t: "—", tone: "dim" },
      sev(p.risk),
    ]),
  };
}

export const COMMANDS: Spec[] = [
  {
    names: ["yardım", "yardim", "help", "?"],
    usage: "yardım",
    help: "komutları listeler",
    run: () =>
      out(
        t("Ghost Terminal sistem kabuğu değildir; yalnızca aşağıdaki komutları çalıştırır.", "dim"),
        { kind: "table", head: ["KOMUT", "AÇIKLAMA"], rows: COMMANDS.map((c) => [{ t: c.usage, tone: "arc" }, c.help]) },
        t("↑/↓ geçmiş · Tab tamamlama · Ctrl+L temizle", "dim"),
      ),
  },
  {
    names: ["durum", "status"],
    usage: "durum",
    help: "güvenlik seviyesi ve özet",
    run: () => {
      const s = useGhost.getState();
      const lvl = securityLevel(s.findings);
      const counts = SEVERITIES.slice(1)
        .reverse()
        .map((k) => [k, s.findings.filter((f) => f.severity === k).length] as const)
        .filter(([, n]) => n > 0);
      return out({
        kind: "kv",
        rows: [
          ["seviye", { t: `${lvl.word} — indeks ${lvl.index}/100`, tone: lvl.severity ?? "ok" }],
          ["açıklama", lvl.note],
          ["bulgular", counts.length ? counts.map(([k, n]) => `${n} ${SEV_LABEL[k]}`).join(", ") : "yok"],
          ["işlem", String(s.processes.length)],
          ["bağlantı", String(s.connections.filter((c) => c.remoteAddr).length)],
          ["dinleyen port", String(openPorts(s.connections).length)],
        ],
      });
    },
  },
  {
    names: ["sistem", "sysinfo"],
    usage: "sistem",
    help: "donanım, işletim sistemi ve kaynak kullanımı",
    run: () => {
      const { host, metrics: m } = useGhost.getState();
      if (!host) return fail("Sistem bilgisi henüz yüklenmedi");
      const rows: [string, Cell][] = [
        ["bilgisayar", host.hostname],
        ["işletim sistemi", `${host.osName} ${host.osVersion} (çekirdek ${host.kernel})`],
        ["işlemci", `${host.cpuBrand} · ${host.cpuCount} mantıksal çekirdek`],
        ["bellek", bytes(host.memTotal)],
        ["yetki", host.elevated ? { t: "yönetici", tone: "ok" } : { t: "standart kullanıcı", tone: "warn" }],
      ];
      if (m) {
        rows.push(
          ["çalışma süresi", duration(m.uptime)],
          ["CPU", pct(m.cpu, 1)],
          ["RAM", `${bytes(m.memUsed)} / ${bytes(m.memTotal)} (${pct((m.memUsed / m.memTotal) * 100)})`],
          ...m.disks.map(
            (d) => [`disk ${d.mount}`, `${bytes(d.total - d.available)} / ${bytes(d.total)} dolu · ${d.fs}`] as [string, Cell],
          ),
        );
      }
      rows.push(["veri klasörü", { t: host.dataDir, tone: "dim" }]);
      return out({ kind: "kv", rows });
    },
  },
  {
    names: ["işlemler", "islemler", "ps"],
    usage: "işlemler [metin] [-n 20]",
    help: "CPU’ya göre sıralı işlem listesi; metinle süzer",
    run: (a) => {
      const nIdx = a.indexOf("-n");
      const n = nIdx >= 0 ? Number(a[nIdx + 1]) || 20 : 20;
      const needle = lower(a.filter((_, i) => i !== nIdx && i !== nIdx + 1).join(" "));
      const list = useGhost
        .getState()
        .processes.filter(
          (p) => !needle || lower(p.name).includes(needle) || String(p.pid) === needle || lower(p.exe ?? "").includes(needle),
        )
        .sort((x, y) => y.cpu - x.cpu || y.memory - x.memory);
      if (!list.length) return fail("Eşleşen işlem yok");
      return out(procTable(list.slice(0, n)), t(`${Math.min(n, list.length)} / ${list.length} işlem`, "dim"));
    },
  },
  {
    names: ["öldür", "oldur", "kill"],
    usage: "öldür <pid>",
    help: "işlemi sonlandırır (onay ister, kritik işlemler korunur)",
    run: (a) => {
      const pid = Number(a[0]);
      if (!Number.isInteger(pid) || pid <= 0) return fail("Kullanım: öldür <pid>");
      const p = useGhost.getState().processes.find((x) => x.pid === pid);
      if (!p) return fail(`PID ${pid} çalışmıyor`);
      if (p.critical)
        return out(
          t(`${p.name} (PID ${pid}) Windows için kritik bir işlem. Sonlandırmak sistemi çökertebilir.`, "bad"),
          t("Terminal kritik işlemleri sonlandırmaz. Gerekirse İşlem Avcısı’ndaki ayrıntı panelini kullanın.", "dim"),
        );
      return {
        blocks: [procTable([p]), t(p.exe ?? "", "dim")],
        confirm: {
          prompt: `${p.name} (PID ${pid}) sonlandırılsın mı? Onaylamak için “evet” yazın.`,
          run: async () => {
            const r = await api.killProcess(pid, true);
            if (r.ok) return out(t(r.message || `PID ${pid} sonlandırıldı`, "ok"));
            if (r.needs === "admin") return out(t(r.message, "warn"), t("“yönetici” komutuyla yetki yükseltebilirsiniz.", "dim"));
            return fail(r.message);
          },
        },
      };
    },
  },
  {
    names: ["netstat", "bağlantılar", "baglantilar"],
    usage: "netstat [metin]",
    help: "uzak adresli etkin bağlantılar",
    run: (a) => {
      const needle = lower(a.join(" "));
      const list = useGhost
        .getState()
        .connections.filter((c) => c.remoteAddr && !isListening(c))
        .filter(
          (c) =>
            !needle ||
            lower(c.processName ?? "").includes(needle) ||
            (c.remoteAddr ?? "").includes(needle) ||
            lower(c.hostname ?? "").includes(needle) ||
            String(c.remotePort) === needle,
        )
        .sort((x, y) => (x.processName ?? "").localeCompare(y.processName ?? "", "tr"));
      if (!list.length) return fail("Eşleşen bağlantı yok");
      return out(
        {
          kind: "table",
          head: ["PROTO", "YEREL", "UZAK", "DURUM", "İŞLEM", "ANA BİLGİSAYAR / ÜLKE"],
          rows: list.slice(0, 200).map((c) => [
            c.protocol.toUpperCase() + (c.ipv6 ? "6" : ""),
            `${c.localAddr}:${c.localPort}`,
            { t: `${c.remoteAddr}:${c.remotePort}`, tone: c.scope === "public" ? "arc" : undefined },
            c.state,
            `${c.processName ?? "?"} (${c.pid})`,
            { t: [c.hostname, c.country].filter(Boolean).join(" · ") || "—", tone: "dim" },
          ]),
        },
        t(`${list.length} bağlantı`, "dim"),
      );
    },
  },
  {
    names: ["portlar", "ports"],
    usage: "portlar",
    help: "dinleyen TCP portları ve sahibi",
    run: () => {
      const s = useGhost.getState();
      const list = openPorts(s.connections);
      if (!list.length) return out(t("Dinleyen port yok", "dim"));
      return out({
        kind: "table",
        head: ["PORT", "ADRES", "ERİŞİM", "İŞLEM"],
        right: [0],
        rows: list.map((c) => [
          String(c.localPort),
          c.localAddr,
          c.scope === "loopback" ? { t: "yalnız bu bilgisayar", tone: "dim" } : { t: "ağa açık", tone: "warn" },
          `${c.processName ?? "?"} (${c.pid})`,
        ]),
      });
    },
  },
  {
    names: ["ip"],
    usage: "ip <adres>",
    help: "ters DNS, ülke/ASN, canlı bağlantılar ve geçmiş",
    run: async (a) => {
      if (!a[0]) return fail("Kullanım: ip <adres>");
      const r = await intel.ipInfo(a[0]);
      const blocks: Block[] = [
        {
          kind: "kv",
          rows: [
            ["adres", { t: r.ip, tone: "arc" }],
            ["kapsam", r.scope],
            ["ana bilgisayar", r.hostname ?? { t: "ters DNS kaydı yok", tone: "dim" }],
            ["ülke", r.country ?? { t: "bilinmiyor (GeoIP veritabanı gerekebilir)", tone: "dim" }],
            ["ASN", r.asn ?? { t: "—", tone: "dim" }],
            [
              "geçmiş",
              r.seenCount
                ? `${r.seenCount} kayıt · ilk ${stamp(r.firstSeen!)} · son ${stamp(r.lastSeen!)}`
                : { t: "bu adresle kayıtlı bağlantı yok", tone: "dim" },
            ],
            ["işlemler", r.processes?.replace(/,/g, ", ") ?? "—"],
          ],
        },
      ];
      if (r.live.length)
        blocks.push({
          kind: "table",
          head: ["CANLI", "YEREL", "UZAK PORT", "DURUM", "İŞLEM"],
          rows: r.live.map((c) => [c.protocol.toUpperCase(), `${c.localAddr}:${c.localPort}`, String(c.remotePort), c.state, `${c.processName ?? "?"} (${c.pid})`]),
        });
      return { blocks };
    },
  },
  {
    names: ["bulgular", "findings"],
    usage: "bulgular",
    help: "etkin tehdit bulguları",
    run: () => {
      const f = [...useGhost.getState().findings].sort(
        (a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || b.score - a.score,
      );
      if (!f.length) return out(t("Etkin bulgu yok. Kurallar şüpheli davranış görmüyor.", "ok"));
      return out({
        kind: "table",
        head: ["SEVİYE", "PUAN", "BULGU", "ÖĞE"],
        right: [1],
        rows: f.map((x) => [sev(x.severity), String(x.score), x.title, { t: x.entity, tone: "dim" }]),
      });
    },
  },
  {
    names: ["olaylar", "events"],
    usage: "olaylar [n] [metin]",
    help: "son güvenlik olayları",
    run: async (a) => {
      const n = Number(a[0]);
      const limit = Number.isInteger(n) && n > 0 ? Math.min(n, 500) : 25;
      const search = (Number.isInteger(n) ? a.slice(1) : a).join(" ") || undefined;
      const ev = await api.events({ limit, search });
      if (!ev.length) return out(t("Kayıtlı olay yok", "dim"));
      return out({
        kind: "table",
        head: ["ZAMAN", "SEVİYE", "TÜR", "OLAY"],
        rows: ev.map((e) => [{ t: stamp(e.ts), tone: "dim" }, sev(e.severity), { t: e.kind, tone: "dim" }, e.title]),
      });
    },
  },
  {
    names: ["hash", "dosya"],
    usage: "hash <\"dosya yolu\">",
    help: "SHA-256, tür, imza ve yerel risk analizi",
    run: async (a) => {
      const path = a.join(" ");
      if (!path) return fail("Kullanım: hash \"C:\\yol\\dosya.exe\"");
      const r = await intel.analyzeFile(path);
      return out(
        {
          kind: "kv",
          rows: [
            ["dosya", r.path],
            ["boyut", bytes(r.size)],
            ["tür", r.detail ? `${r.kind} · ${r.detail}` : r.kind],
            ["SHA-256", { t: r.sha256, tone: "arc" }],
            ["SHA-1", r.sha1],
            ["MD5", r.md5],
            [
              "imza",
              r.signature.state === "signed"
                ? { t: r.signature.publisher ?? "imzalı", tone: "ok" }
                : { t: r.signature.state === "invalid" ? "geçersiz" : "imzasız", tone: "warn" },
            ],
            ["köken", r.motw ? `${r.motw.zoneName}${r.motw.hostUrl ? ` · ${r.motw.hostUrl}` : ""}` : "işaret yok"],
            ["hash veritabanı", r.knownBad ? { t: `eşleşme: ${r.knownBad}`, tone: "CRITICAL" } : "eşleşme yok"],
            ["sonuç", r.signals.length ? sev(r.severity) : { t: "yerel kurallarda sinyal yok", tone: "ok" }],
          ],
        },
        ...r.signals.map((s) => t(`  +${s.weight}  ${s.label}`, r.severity)),
      );
    },
  },
  {
    names: ["açılış", "acilis", "startup"],
    usage: "açılış [şüpheli]",
    help: "otomatik başlatma girdileri",
    run: async (a) => {
      const { items, scannedAt } = await intel.startupItems();
      if (!scannedAt) return out(t("İlk açılış taraması henüz bitmedi", "dim"));
      const only = !!a[0] && /^(şüph|suph)/.test(lower(a[0]));
      const list = items.filter((i) => (only ? i.risk : i.kind !== "service" || i.risk));
      if (!list.length) return out(t(only ? "Şüpheli sinyal taşıyan açılış girdisi yok" : "Girdi yok", "ok"));
      const KIND: Record<string, string> = {
        registry: "kayıt defteri",
        winlogon: "winlogon",
        folder: "başlangıç klasörü",
        service: "hizmet",
        task: "görev",
      };
      return out(
        {
          kind: "table",
          head: ["RİSK", "KAYNAK", "AD", "KOMUT"],
          rows: list.map((i) => [sev(i.risk), KIND[i.kind] ?? i.kind, i.name, { t: i.command, tone: "dim" }]),
        },
        t(`${list.length} girdi gösterildi (hizmetler yalnızca şüpheliyse) · toplam ${items.length}`, "dim"),
      );
    },
  },
  {
    names: ["tara", "scan"],
    usage: "tara",
    help: "açılış noktalarını yeniden tarar",
    run: async () => {
      await intel.rescanStartup();
      return out(t("Açılış taraması başlatıldı. Sonuç birkaç saniye içinde Açılış modülüne ve olaylara düşer.", "ok"));
    },
  },
  {
    names: ["git", "aç", "ac"],
    usage: "git <modül>",
    help: "modüle geçer (ör. git ağ)",
    run: async (a) => {
      const r = await runCommand(`git ${a.join(" ")}`);
      return out(t(r.text, r.ok ? "ok" : "bad"));
    },
  },
  {
    names: ["yönetici", "yonetici", "admin"],
    usage: "yönetici",
    help: "uygulamayı yönetici yetkisiyle yeniden başlatır",
    run: async () => {
      const r = await runCommand("yönetici");
      return out(t(r.text, r.ok ? "ok" : "bad"));
    },
  },
  {
    names: ["temizle", "clear", "cls"],
    usage: "temizle",
    help: "ekranı temizler",
    run: () => ({ blocks: [], clear: true }),
  },
];

export function findCommand(name: string): Spec | undefined {
  const n = lower(name);
  return COMMANDS.find((c) => c.names.includes(n));
}

export function complete(prefix: string): string[] {
  const p = lower(prefix);
  if (!p) return [];
  return COMMANDS.map((c) => c.names[0]).filter((n) => n.startsWith(p));
}

export async function execute(line: string): Promise<Outcome> {
  const [head, ...args] = tokenize(line);
  if (!head) return out();
  const spec = findCommand(head);
  if (!spec) {
    const near = complete(head.slice(0, 2));
    return fail(`Bilinmeyen komut: ${head}.${near.length ? ` Şunu mu demek istediniz: ${near.join(", ")}?` : " “yardım” yazın."}`);
  }
  try {
    return await spec.run(args);
  } catch (e) {
    return fail(String(e));
  }
}
