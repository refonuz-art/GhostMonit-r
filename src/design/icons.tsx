// Custom line icon set — 1.5px stroke, square caps, 20px grid. Drawn for Ghost Monitor.
import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement>;

function Svg(props: P & { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 20 20"
      width={18}
      height={18}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="square"
      aria-hidden="true"
      {...props}
    />
  );
}

export const Icon = {
  core: (p: P) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="7.25" strokeDasharray="9 2.4" />
      <circle cx="10" cy="10" r="3.25" />
      <path d="M10 1v2.5M10 16.5V19M1 10h2.5M16.5 10H19" />
    </Svg>
  ),
  lineage: (p: P) => (
    <Svg {...p}>
      <rect x="3" y="2.5" width="4" height="4" />
      <rect x="13" y="8" width="4" height="4" />
      <rect x="13" y="14" width="4" height="4" />
      <path d="M5 6.5V16h8M5 10h8" />
    </Svg>
  ),
  sonar: (p: P) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="1.5" fill="currentColor" stroke="none" />
      <path d="M10 10 16 4M10 10l-6.5 2.5M10 10l2 7" />
      <rect x="15" y="2.5" width="2.5" height="2.5" />
      <rect x="2" y="11.5" width="2.5" height="2.5" />
      <rect x="11.2" y="16.5" width="2.5" height="2.5" />
    </Svg>
  ),
  threat: (p: P) => (
    <Svg {...p}>
      <path d="M10 2 18 10 10 18 2 10Z" />
      <path d="M10 6.5v4.5M10 13.2v.6" />
    </Svg>
  ),
  file: (p: P) => (
    <Svg {...p}>
      <path d="M4 2h8l4 4v12H4Z" />
      <path d="M12 2v4h4M7 10h6M7 13h6M7 16h3" />
    </Svg>
  ),
  startup: (p: P) => (
    <Svg {...p}>
      <path d="M6 5.2A6.5 6.5 0 1 0 14 5.2" />
      <path d="M10 2v7" />
      <path d="M7.5 4.5 10 2l2.5 2.5" />
    </Svg>
  ),
  timeline: (p: P) => (
    <Svg {...p}>
      <path d="M5 2v16" />
      <path d="M5 4.5h3M5 9h9M5 13.5h6M5 17h11" />
    </Svg>
  ),
  terminal: (p: P) => (
    <Svg {...p}>
      <path d="M2.5 3h15v14h-15Z" />
      <path d="m6 8 2.5 2L6 12M10.5 13H14" />
    </Svg>
  ),
  report: (p: P) => (
    <Svg {...p}>
      <path d="M5 2h11v14H5Z" />
      <path d="M3 5v13h11" />
      <path d="M8 12V9M10.5 12V6M13 12v-2" />
    </Svg>
  ),
  close: (p: P) => (
    <Svg {...p}>
      <path d="m5 5 10 10M15 5 5 15" />
    </Svg>
  ),
  minimize: (p: P) => (
    <Svg {...p}>
      <path d="M5 10h10" />
    </Svg>
  ),
  maximize: (p: P) => (
    <Svg {...p}>
      <path d="M5 5h10v10H5Z" />
    </Svg>
  ),
  shield: (p: P) => (
    <Svg {...p}>
      <path d="M10 2 16.5 4.5V10c0 4-3 6.5-6.5 8C6.5 16.5 3.5 14 3.5 10V4.5Z" />
      <path d="m7 10 2.2 2.2L13.5 8" />
    </Svg>
  ),
  bolt: (p: P) => (
    <Svg {...p}>
      <path d="M11 2 4.5 11H10l-1 7 6.5-9H10Z" />
    </Svg>
  ),
  kill: (p: P) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="7" />
      <path d="M5 15 15 5" />
    </Svg>
  ),
  folder: (p: P) => (
    <Svg {...p}>
      <path d="M2.5 4.5h5l1.5 2h8.5v9.5h-15Z" />
    </Svg>
  ),
  trust: (p: P) => (
    <Svg {...p}>
      <path d="m4 10.5 4 4L16 6" />
    </Svg>
  ),
  dismiss: (p: P) => (
    <Svg {...p}>
      <path d="M4 10h12" />
    </Svg>
  ),
  search: (p: P) => (
    <Svg {...p}>
      <circle cx="8.5" cy="8.5" r="5" />
      <path d="m12.5 12.5 4.5 4.5" />
    </Svg>
  ),
  chevron: (p: P) => (
    <Svg {...p}>
      <path d="m7 5 5 5-5 5" />
    </Svg>
  ),
  settings: (p: P) => (
    <Svg {...p}>
      <path d="M2 5h16M2 10h16M2 15h16" strokeOpacity={0.45} />
      <path d="M6 3v4M13 8v4M8 13v4" />
    </Svg>
  ),
  horns: (p: P) => (
    <Svg {...p}>
      <path d="M5.5 8.5C3.5 6.5 3 4 4 1.5c.8 2.6 2.4 4 4.2 4.6M14.5 8.5c2-2 2.5-4.5 1.5-7-.8 2.6-2.4 4-4.2 4.6" />
      <path d="M10 6.2c3 0 4.6 2.4 4.6 5.4S12.6 18 10 18.5C7.4 18 5.4 14.6 5.4 11.6S7 6.2 10 6.2Z" />
      <path d="M7.8 11.5l1.4.6M12.2 11.5l-1.4.6" />
    </Svg>
  ),
  ghost: (p: P) => (
    <Svg {...p} strokeWidth={1.6}>
      <circle cx="10" cy="10" r="7.5" strokeDasharray="10.5 1.5" />
      <path d="M10 5.2c2.2 2.1 2.2 7.5 0 9.6-2.2-2.1-2.2-7.5 0-9.6Z" fill="currentColor" stroke="none" />
    </Svg>
  ),
};
