import { invoke } from "@tauri-apps/api/core";

export interface AssistantStatus {
  azure: boolean;
  azureRegion: string | null;
  claude: boolean;
  localStt: boolean;
}
export interface InstallProgress {
  stage: "program" | "model" | "done";
  done: number;
  total: number;
}
export interface NowPlaying {
  title: string;
  artist: string;
  app: string;
  playing: boolean;
  position: number | null;
  duration: number | null;
}
export interface AppEntry {
  name: string;
  target: string;
  score: number;
}
export interface WeatherDay {
  min: number;
  max: number;
  rainChance: number | null;
  sky: string;
}
export interface Weather {
  place: string;
  temp: number;
  feels: number;
  humidity: number | null;
  wind: number | null;
  sky: string;
  today: WeatherDay | null;
  tomorrow: WeatherDay | null;
}

/** Minimal shapes of the Claude Messages API that the assistant loop reads. */
export type ClaudeBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: string; [k: string]: unknown };
export interface ClaudeMessage {
  role: "user" | "assistant";
  content: string | ClaudeBlock[] | Record<string, unknown>[];
}
export interface ClaudeResponse {
  content: ClaudeBlock[];
  stop_reason: string | null;
}

export const assistantApi = {
  status: () => invoke<AssistantStatus>("assistant_status"),
  setAzure: (key: string | null, region: string | null) => invoke<AssistantStatus>("assistant_set_azure", { key, region }),
  setClaude: (key: string | null) => invoke<AssistantStatus>("assistant_set_claude", { key }),
  tts: (text: string) => invoke<ArrayBuffer>("assistant_tts", { text }),
  stt: (wav: Uint8Array) => invoke<string>("assistant_stt", wav),
  findApp: (query: string) => invoke<AppEntry[]>("assistant_find_app", { query }),
  launch: (target: string) => invoke<string>("assistant_launch", { target }),
  openUrl: (url: string) => invoke<void>("assistant_open_url", { url }),
  weather: (city?: string | null) => invoke<Weather>("assistant_weather", { city: city ?? null }),
  mediaNow: () => invoke<NowPlaying | null>("media_now"),
  mediaControl: (action: "toggle" | "next" | "prev") => invoke<void>("media_control", { action }),
  installStt: () => invoke<AssistantStatus>("assistant_install_stt"),
  ask: (system: unknown, messages: ClaudeMessage[], tools: unknown[]) =>
    invoke<ClaudeResponse>("assistant_ask", { system, messages, tools }),
};
