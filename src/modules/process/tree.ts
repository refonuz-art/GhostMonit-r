import type { ProcessInfo } from "../../ipc/types";

/** Anything with a parent link and a start time can be laid out as a lineage tree. */
export interface TreeNode {
  pid: number;
  ppid: number | null;
  startTime: number;
}

export interface Row<T extends TreeNode = ProcessInfo> {
  p: T;
  depth: number;
  /** For each ancestor level: does that ancestor have siblings below it? (draws lineage rails) */
  rails: boolean[];
  last: boolean;
  hasKids: boolean;
}

/** Parent links are only trusted when the parent started no later than the child (PIDs get reused). */
export function buildTree<T extends TreeNode>(procs: T[]): Row<T>[] {
  const byPid = new Map(procs.map((p) => [p.pid, p]));
  const kids = new Map<number, T[]>();
  const roots: T[] = [];
  for (const p of procs) {
    const parent = p.ppid != null && p.ppid !== p.pid ? byPid.get(p.ppid) : undefined;
    if (parent && parent.startTime <= p.startTime) {
      const arr = kids.get(parent.pid) ?? [];
      arr.push(p);
      kids.set(parent.pid, arr);
    } else roots.push(p);
  }
  const order = (a: T, b: T) => a.startTime - b.startTime || a.pid - b.pid;
  const out: Row<T>[] = [];
  const seen = new Set<number>();
  const walk = (p: T, depth: number, rails: boolean[], last: boolean) => {
    if (seen.has(p.pid)) return;
    seen.add(p.pid);
    const ch = (kids.get(p.pid) ?? []).sort(order);
    out.push({ p, depth, rails, last, hasKids: ch.length > 0 });
    ch.forEach((c, i) => walk(c, depth + 1, depth === 0 ? [] : [...rails, !last], i === ch.length - 1));
  };
  roots.sort(order).forEach((r, i, arr) => walk(r, 0, [], i === arr.length - 1));
  return out;
}
