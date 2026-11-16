import { useEffect, useRef } from "react";
import uPlot from "uplot";
import type { Severity, SignatureInfo } from "../ipc/types";
import { SEVERITIES } from "../ipc/types";

export const SEV_LABEL: Record<Severity, string> = {
  INFO: "bilgi",
  LOW: "düşük",
  MEDIUM: "orta",
  HIGH: "yüksek",
  CRITICAL: "kritik",
};

export const SEV_COLOR: Record<Severity, string> = {
  INFO: "#6f8796",
  LOW: "#22b8ff",
  MEDIUM: "#ffb547",
  HIGH: "#ff7a3d",
  CRITICAL: "#ff3d4e",
};

/** Bars + label; fill count encodes level so it doesn't rely on colour alone. */
export function Sev({ level, label = true }: { level: Severity; label?: boolean }) {
  const n = SEVERITIES.indexOf(level) + 1;
  return (
    <span className={`sev sev--${level}`} title={`Risk: ${SEV_LABEL[level]}`}>
      <span className="sev__bars">
        {SEVERITIES.map((s, i) => (
          <i key={s} className={i < n ? "on" : ""} />
        ))}
      </span>
      {label && SEV_LABEL[level]}
    </span>
  );
}

const SIG_TEXT: Record<SignatureInfo["state"], string> = {
  pending: "doğrulanıyor",
  signed: "imzalı",
  unsigned: "imzasız",
  invalid: "geçersiz imza",
  unknown: "erişilemedi",
};

export function SigMark({ sig, showPublisher = true }: { sig: SignatureInfo; showPublisher?: boolean }) {
  return (
    <span
      className={`sig sig--${sig.state}`}
      title={
        sig.state === "unknown"
          ? "Dosyaya erişilemedi. Korumalı sistem işlemleri için yönetici yetkisi gerekir."
          : (sig.publisher ?? SIG_TEXT[sig.state])
      }
    >
      <i />
      {showPublisher && sig.state === "signed" && sig.publisher ? sig.publisher : SIG_TEXT[sig.state]}
    </span>
  );
}

export function sigText(s: SignatureInfo["state"]) {
  return SIG_TEXT[s];
}

/** Small uPlot wrapper that keeps one plot instance and pushes data into it. */
export function Plot({
  data,
  series,
  height,
  scales,
  axes = true,
  yFormat,
  y2Format,
}: {
  data: uPlot.AlignedData;
  series: uPlot.Series[];
  height: number;
  scales?: uPlot.Scales;
  axes?: boolean;
  yFormat?: (v: number) => string;
  y2Format?: (v: number) => string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);

  useEffect(() => {
    const el = host.current!;
    const grid = { stroke: "#1a242c", width: 1 };
    const font = "10px JetBrains Mono";
    const axisBase = { stroke: "#4a5762", grid, ticks: { show: false }, font, gap: 4 } as uPlot.Axis;
    const opts: uPlot.Options = {
      width: el.clientWidth,
      height,
      legend: { show: false },
      cursor: { show: true, x: true, y: false, points: { size: 5 }, drag: { x: false, y: false } },
      scales: { x: { time: true }, ...scales },
      series: [{}, ...series.map((s) => ({ points: { show: false }, ...s }))],
      axes: axes
        ? [
            { ...axisBase, space: 80, values: (_u, v) => v.map((x) => new Date(x * 1000).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })) },
            { ...axisBase, scale: series[0]?.scale ?? "y", size: 52, values: (_u, v) => v.map((x) => (yFormat ? yFormat(x) : String(x))) },
            ...(y2Format
              ? [{ ...axisBase, side: 1, scale: "y2", grid: { show: false }, size: 64, values: (_u: uPlot, v: number[]) => v.map(y2Format) } as uPlot.Axis]
              : []),
          ]
        : [{ show: false }, { show: false }],
    };
    plot.current = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() => plot.current?.setSize({ width: el.clientWidth, height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.current?.destroy();
      plot.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [height]);

  useEffect(() => {
    plot.current?.setData(data);
  }, [data]);

  return <div ref={host} className="plot" />;
}

/** Thin horizontal gauge. */
export function Meter({ value, max = 100, tone = "phosphor" }: { value: number; max?: number; tone?: "phosphor" | "arc" | "warn" | "bad" }) {
  const p = Math.max(0, Math.min(1, value / Math.max(1e-9, max)));
  return (
    <span className={`meter meter--${tone}`}>
      <i style={{ width: `${p * 100}%` }} />
    </span>
  );
}
