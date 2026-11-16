import { describe, expect, it } from "vitest";
import { basename, bytes, dirname, duration } from "../design/format";
import type { ConnectionInfo, Finding, Severity } from "../ipc/types";
import { openPorts, securityLevel, topSeverity } from "./derive";

const f = (severity: Severity, key: string = severity): Finding => ({
  key,
  entityKind: "process",
  entity: "x",
  title: "x",
  severity,
  score: 0,
  signals: [],
  firstSeen: 0,
  lastSeen: 0,
  pid: null,
  pids: [],
  status: "open",
});

const c = (port: number, scope: ConnectionInfo["scope"], state = "LISTEN"): ConnectionInfo => ({
  id: `${port}${scope}`,
  protocol: "tcp",
  ipv6: false,
  localAddr: scope === "loopback" ? "127.0.0.1" : "0.0.0.0",
  localPort: port,
  remoteAddr: null,
  remotePort: null,
  state,
  pid: 1,
  processName: "x",
  started: 0,
  scope,
  hostname: null,
  country: null,
  asn: null,
  risk: null,
});

describe("security level", () => {
  it("is clean with no findings or only INFO", () => {
    expect(securityLevel([]).index).toBe(100);
    expect(securityLevel([f("INFO")]).severity).toBeNull();
  });

  it("weak signals barely move the index", () => {
    const lvl = securityLevel([f("LOW", "a"), f("LOW", "b"), f("LOW", "c")]);
    expect(lvl.word).toBe("İzleniyor");
    expect(lvl.index).toBe(94);
  });

  it("one critical dominates the wording and costs most", () => {
    const lvl = securityLevel([f("LOW"), f("CRITICAL")]);
    expect(lvl.tone).toBe("bad");
    expect(lvl.index).toBe(53);
  });

  it("never drops below zero", () => {
    expect(securityLevel(Array.from({ length: 10 }, (_, i) => f("CRITICAL", String(i)))).index).toBe(0);
  });

  it("top severity ignores INFO", () => {
    expect(topSeverity([f("INFO"), f("MEDIUM"), f("LOW")])).toBe("MEDIUM");
    expect(topSeverity([f("INFO")])).toBeNull();
  });
});

describe("open ports", () => {
  it("dedupes per port and prefers the exposed binding", () => {
    const ports = openPorts([c(445, "loopback"), c(445, "unspecified"), c(80, "unspecified", "ESTABLISHED"), c(22, "loopback")]);
    expect(ports.map((p) => p.localPort)).toEqual([22, 445]);
    expect(ports[1].scope).toBe("unspecified");
  });
});

describe("format", () => {
  it("bytes", () => {
    expect(bytes(0)).toBe("0 B");
    expect(bytes(1536)).toBe("1.5 KB");
    expect(bytes(15 * 1024 ** 3)).toBe("15 GB");
  });
  it("duration uses unambiguous Turkish units", () => {
    expect(duration(59)).toBe("0dk");
    expect(duration(3600 + 42 * 60)).toBe("1sa 42dk");
    expect(duration(2 * 86400 + 5 * 3600)).toBe("2g 5sa");
  });
  it("paths", () => {
    expect(basename(String.raw`C:\Windows\System32\notepad.exe`)).toBe("notepad.exe");
    expect(dirname(String.raw`C:\Windows\notepad.exe`)).toBe(String.raw`C:\Windows`);
    expect(basename(null)).toBe("");
  });
});
