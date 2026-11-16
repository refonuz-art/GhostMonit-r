import { describe, expect, it } from "vitest";
import { explainSignals, KNOWN_RULES } from "./explain";

const sources = import.meta.glob("../../src-tauri/src/**/*.rs", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

describe("explanations", () => {
  it("cover every rule id the backend can emit", () => {
    const ids = new Set<string>();
    for (const src of Object.values(sources)) {
      for (const m of src.split("#[cfg(test)]")[0].matchAll(/sig\(\s*"([a-z]+\.[a-z_]+)"/g)) ids.add(m[1]);
    }
    expect(ids.size).toBeGreaterThan(20);
    expect([...ids].filter((r) => !KNOWN_RULES.includes(r))).toEqual([]);
  });

  it("dedupes by rule, strongest first", () => {
    const s = (rule: string, weight: number) => ({ rule, weight, label: "", evidence: "" });
    const out = explainSignals([s("sig.unsigned", 5), s("ps.cmdline", 15), s("ps.cmdline", 25), s("nope", 99)]);
    expect(out.map((e) => e.rule)).toEqual(["ps.cmdline", "sig.unsigned"]);
  });
});
