import { Icon } from "../design/icons";
import type { ModuleId } from "../state/store";

export interface ModuleDef {
  id: ModuleId;
  label: string;
  /** Words the command line accepts to open this module. */
  aliases: string[];
  icon: (p: React.SVGProps<SVGSVGElement>) => React.ReactElement;
  ready: boolean;
}

export const MODULES: ModuleDef[] = [
  { id: "command", label: "Komuta", aliases: ["komuta", "ana", "home"], icon: Icon.core, ready: true },
  { id: "process", label: "İşlem Avcısı", aliases: ["işlem", "islem", "avcı", "process"], icon: Icon.lineage, ready: true },
  { id: "network", label: "Ağ Gözcüsü", aliases: ["ağ", "ag", "network", "net"], icon: Icon.sonar, ready: true },
  { id: "threat", label: "Tehdit", aliases: ["tehdit", "threat", "bulgu"], icon: Icon.threat, ready: true },
  { id: "file", label: "Dosya", aliases: ["dosya", "file"], icon: Icon.file, ready: true },
  { id: "startup", label: "Açılış", aliases: ["açılış", "acilis", "startup"], icon: Icon.startup, ready: true },
  { id: "timeline", label: "Zaman Çizelgesi", aliases: ["zaman", "olay", "timeline"], icon: Icon.timeline, ready: true },
  { id: "terminal", label: "Terminal", aliases: ["terminal", "konsol"], icon: Icon.terminal, ready: true },
  { id: "report", label: "Rapor", aliases: ["rapor", "report"], icon: Icon.report, ready: true },
  { id: "health", label: "Sağlık", aliases: ["sağlık", "saglik", "health", "koruma"], icon: Icon.shield, ready: true },
  { id: "ayla", label: "Ayla", aliases: ["ayla", "hologram", "asistan"], icon: Icon.horns, ready: true },
];
