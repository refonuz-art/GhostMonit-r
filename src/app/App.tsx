import { Component, lazy, Suspense, useEffect, useState, type ReactNode } from "react";
import { isTauri } from "../ipc/api";
import { useGhost, type ModuleId } from "../state/store";
import { Boot } from "./Boot";
import { useBridge } from "./bridge";
import { GhostLine } from "./GhostLine";
import { MODULES } from "./modules";
import { TitleBar } from "./TitleBar";

const CommandCenter = lazy(() => import("../modules/command/CommandCenter"));
const ProcessHunter = lazy(() => import("../modules/process/ProcessHunter"));
const NetworkWatch = lazy(() => import("../modules/network/NetworkWatch"));
const ThreatCenter = lazy(() => import("../modules/threat/ThreatCenter"));
const Timeline = lazy(() => import("../modules/timeline/Timeline"));
const FileIntel = lazy(() => import("../modules/file/FileIntel"));
const StartupMonitor = lazy(() => import("../modules/startup/StartupMonitor"));
const Terminal = lazy(() => import("../modules/terminal/Terminal"));
const Reports = lazy(() => import("../modules/report/Reports"));
const Health = lazy(() => import("../modules/health/Health"));
const Settings = lazy(() => import("../modules/settings/Settings"));

class ModuleBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error)
      return (
        <div className="empty">
          <strong>Bu modül yüklenemedi</strong>
          <span className="mono selectable">{String(this.state.error.message || this.state.error)}</span>
          <button className="btn" onClick={() => this.setState({ error: null })}>
            Yeniden dene
          </button>
        </div>
      );
    return this.props.children;
  }
}

function ModuleView({ id }: { id: ModuleId }) {
  switch (id) {
    case "command":
      return <CommandCenter />;
    case "process":
      return <ProcessHunter />;
    case "network":
      return <NetworkWatch />;
    case "threat":
      return <ThreatCenter />;
    case "timeline":
      return <Timeline />;
    case "file":
      return <FileIntel />;
    case "startup":
      return <StartupMonitor />;
    case "terminal":
      return <Terminal />;
    case "report":
      return <Reports />;
    case "health":
      return <Health />;
    case "settings":
      return <Settings />;
    default:
      return null;
  }
}

export function App() {
  useBridge();
  const module = useGhost((s) => s.module);
  const setModule = useGhost((s) => s.setModule);
  const toast = useGhost((s) => s.toast);
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === ",") {
        e.preventDefault();
        setModule("settings");
        return;
      }
      if (e.ctrlKey && /^[0-9]$/.test(e.key)) {
        const m = MODULES[e.key === "0" ? 9 : Number(e.key) - 1];
        if (m) {
          e.preventDefault();
          setModule(m.id);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setModule]);

  return (
    <div className="shell">
      <TitleBar />
      <main className="viewport" key={module}>
        {!isTauri ? (
          <div className="empty">
            <strong>Masaüstü çalışma ortamı bulunamadı</strong>
            <span>Ghost Monitor sistem verisini yalnızca Tauri penceresi içinde okuyabilir. `pnpm app:dev` ile başlatın.</span>
          </div>
        ) : (
          <ModuleBoundary>
            <Suspense fallback={<div className="module-loading" />}>
              <ModuleView id={module} />
            </Suspense>
          </ModuleBoundary>
        )}
      </main>
      <GhostLine />
      {toast && (
        <div className={`toast toast--${toast.tone}`} role="status">
          {toast.text}
        </div>
      )}
      {!booted && <Boot onDone={() => setBooted(true)} />}
    </div>
  );
}
