// Ready-made rules for common attack patterns. Picking one opens it in the editor as a new
// rule; nothing is saved until the user presses Kaydet.
import { newRule, type UserRule } from "../../ipc/v5";

export interface RuleTemplate {
  id: string;
  title: string;
  why: string;
  rule: Partial<UserRule>;
}

const OFFICE = "winword.exe|excel.exe|powerpnt.exe|outlook.exe|onenote.exe|msaccess.exe";
const SCRIPT_HOSTS = "wscript.exe|cscript.exe|mshta.exe|rundll32.exe|regsvr32.exe";

export const RULE_TEMPLATES: RuleTemplate[] = [
  {
    id: "office-shell",
    title: "Ofis belgesi komut satırı başlattı",
    why: "Makrolu Word/Excel belgeleriyle gelen saldırıların en tipik adımı: belge PowerShell ya da cmd açar.",
    rule: {
      name: "Ofis programı komut yorumlayıcısı başlattı",
      severity: "CRITICAL",
      namePat: "powershell.exe|pwsh.exe|cmd.exe|wscript.exe|cscript.exe|mshta.exe",
      parentPat: OFFICE,
    },
  },
  {
    id: "temp-internet",
    title: "Temp klasöründen internete çıkan program",
    why: "Kurulum dışında Temp'ten çalışıp internete bağlanan programlar çoğu zaman indirilmiş bir yükleyici ya da zararlıdır.",
    rule: { name: "Temp klasöründen internete çıkan program", severity: "HIGH", pathPat: "\\temp\\", internet: true },
  },
  {
    id: "downloads-unsigned",
    title: "İndirilenler'den çalışan imzasız program",
    why: "İnternetten indirilen imzasız programlar en sık bulaşma yoludur.",
    rule: { name: "İndirilenler'den imzasız program", severity: "HIGH", pathPat: "\\downloads\\", signer: "unsigned" },
  },
  {
    id: "ps-encoded",
    title: "Gizlenmiş PowerShell komutu",
    why: "-EncodedCommand ile verilen komut okunamaz hâle getirilmiştir; meşru araçlar bunu nadiren kullanır.",
    rule: { name: "Kodlanmış PowerShell komutu", severity: "HIGH", namePat: "powershell.exe|pwsh.exe", cmdContains: "-enc" },
  },
  {
    id: "script-internet",
    title: "Betik motoru internete çıkıyor",
    why: "wscript, mshta, rundll32 gibi Windows araçları saldırganlarca indirme yapmak için kötüye kullanılır.",
    rule: { name: "Betik motoru internete bağlandı", severity: "HIGH", namePat: SCRIPT_HOSTS, internet: true },
  },
  {
    id: "invalid-sig",
    title: "İmzası bozuk program",
    why: "Geçersiz imza, dosyanın imzalandıktan sonra değiştirildiğini gösterir.",
    rule: { name: "Geçersiz imzalı program", severity: "HIGH", signer: "invalid" },
  },
  {
    id: "remote-ports",
    title: "Uzak erişim portlarına bağlantı",
    why: "Uzak Masaüstü, VNC ve SSH portlarına giden bağlantılar, bilgisayarın uzaktan yönetildiğini ya da başka makinelere sızılmaya çalışıldığını gösterebilir.",
    rule: { name: "Uzak erişim portuna bağlantı", severity: "MEDIUM", remotePorts: "22, 3389, 5900, 5938" },
  },
  {
    id: "unsigned-listener",
    title: "Port dinleyen imzasız program",
    why: "Dışarıdan bağlantı bekleyen imzasız bir program arka kapı olabilir.",
    rule: { name: "Port dinleyen imzasız program", severity: "MEDIUM", signer: "unsigned", listens: true },
  },
];

export function fromTemplate(t: RuleTemplate): UserRule {
  return { ...newRule(), ...t.rule, note: t.why };
}
