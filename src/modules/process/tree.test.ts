import { describe, expect, it } from "vitest";
import type { ProcessInfo } from "../../ipc/types";
import { buildTree } from "./tree";

const p = (pid: number, ppid: number | null, startTime: number): ProcessInfo => ({
  pid,
  ppid,
  name: `p${pid}`,
  exe: null,
  cmd: null,
  cpu: 0,
  memory: 0,
  startTime,
  user: null,
  signature: { state: "signed", publisher: null },
  connections: 0,
  critical: false,
  risk: null,
});

describe("buildTree", () => {
  it("nests children under parents in start order", () => {
    const rows = buildTree([p(1, null, 1), p(3, 1, 5), p(2, 1, 3), p(4, 2, 6)]);
    expect(rows.map((r) => [r.p.pid, r.depth])).toEqual([
      [1, 0],
      [2, 1],
      [4, 2],
      [3, 1],
    ]);
  });

  it("does not attach a child to a reused PID that started later", () => {
    const rows = buildTree([p(10, null, 100), p(11, 10, 50)]);
    expect(rows.every((r) => r.depth === 0)).toBe(true);
  });

  it("survives cycles", () => {
    const rows = buildTree([p(1, 2, 1), p(2, 1, 1)]);
    expect(rows.length).toBeLessThanOrEqual(2);
  });
});
