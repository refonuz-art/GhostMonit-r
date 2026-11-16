import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

const { tokenize, complete, findCommand, execute } = await import("./interpreter");

describe("ghost terminal", () => {
  it("tokenizes quoted paths", () => {
    expect(tokenize('hash "C:/Program Files/a b.exe" x')).toEqual(["hash", "C:/Program Files/a b.exe", "x"]);
  });

  it("resolves Turkish and ASCII aliases", () => {
    expect(findCommand("öldür")).toBe(findCommand("kill"));
    expect(findCommand("İŞLEMLER".toLocaleLowerCase("tr-TR"))).toBeDefined();
  });

  it("completes by prefix", () => {
    expect(complete("ne")).toEqual(["netstat"]);
  });

  it("rejects unknown commands without throwing", async () => {
    const r = await execute("rm -rf /");
    expect(r.blocks[0]).toMatchObject({ kind: "text", tone: "bad" });
  });

  it("kill requires a valid pid", async () => {
    const r = await execute("öldür abc");
    expect(r.confirm).toBeUndefined();
  });
});
