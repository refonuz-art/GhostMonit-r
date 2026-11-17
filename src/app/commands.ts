// Command interpreter shared by the Ghost Line (and later the full Terminal module).
import { handle } from "../assistant/agent";
import { useAyla } from "../assistant/store";
import { api } from "../ipc/api";
import { useGhost } from "../state/store";
import { MODULES } from "./modules";

export interface CommandResult {
  ok: boolean;
  text: string;
}

const norm = (s: string) => s.trim().toLocaleLowerCase("tr-TR");

export const HELP = [
  "<modül>            modüle git (ör. ağ, tehdit, işlem)",
  "ara <metin>        işlem ara (ad, PID, yol, yayıncı)",
  "pid <numara>       işlemin dosyasını aç",
  "yönetici           yönetici yetkisiyle yeniden başlat",
  "yardım             komutları göster",
];

export async function runCommand(input: string): Promise<CommandResult> {
  const raw = input.trim();
  if (!raw) return { ok: true, text: "" };
  const [head, ...rest] = raw.split(/\s+/);
  const cmd = norm(head);
  const arg = rest.join(" ");
  const st = useGhost.getState();

  if (cmd === "yardım" || cmd === "yardim" || cmd === "help" || cmd === "?") {
    return { ok: true, text: HELP.join("\n") };
  }

  const target = norm(cmd === "git" ? arg : raw);
  const mod = MODULES.find((m) => m.aliases.includes(target) || norm(m.label) === target);
  if (mod) {
    st.setModule(mod.id);
    return { ok: true, text: `${mod.label} açıldı` };
  }

  if (cmd === "ara" || cmd === "search") {
    if (!arg) return { ok: false, text: "Kullanım: ara <metin>" };
    st.searchProcesses(arg);
    return { ok: true, text: `İşlem araması: “${arg}”` };
  }

  if (cmd === "pid") {
    const pid = Number(arg);
    if (!Number.isInteger(pid)) return { ok: false, text: "Kullanım: pid <numara>" };
    if (!st.processes.some((p) => p.pid === pid)) return { ok: false, text: `PID ${pid} çalışmıyor` };
    st.focusProcess(pid);
    return { ok: true, text: `PID ${pid} dosyası açıldı` };
  }

  if (cmd === "yönetici" || cmd === "yonetici" || cmd === "admin") {
    if (st.host?.elevated) return { ok: true, text: "Zaten yönetici yetkisiyle çalışıyor" };
    try {
      await api.relaunchAdmin();
      return { ok: true, text: "Yönetici olarak yeniden başlatılıyor…" };
    } catch (e) {
      return { ok: false, text: String(e) };
    }
  }

  // Anything else is a sentence for the assistant ("opera'yı aç", "hava nasıl").
  if (useAyla.getState().enabled) {
    useAyla.getState().setOpen(true);
    void handle(raw);
    return { ok: true, text: "" };
  }
  return { ok: false, text: `Bilinmeyen komut: ${head}. “yardım” yazın.` };
}
