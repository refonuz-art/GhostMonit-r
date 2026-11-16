import { useEffect, useRef, useState } from "react";
import { clock } from "../../design/format";
import { useGhost } from "../../state/store";
import { complete, execute, type Block, type Cell, type Outcome } from "./interpreter";
import "./terminal.css";

interface Entry {
  id: number;
  ts: number;
  input: string;
  blocks: Block[];
  running?: boolean;
  prompt?: string;
}

const HIST_KEY = "gm.terminal.history";
let seq = 0;

function loadHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem(HIST_KEY) ?? "[]");
  } catch {
    return [];
  }
}

function C({ c }: { c: Cell }) {
  if (typeof c === "string") return <>{c}</>;
  return <span className={c.tone ? `tt-${c.tone}` : undefined}>{c.t}</span>;
}

function Render({ b }: { b: Block }) {
  switch (b.kind) {
    case "text":
      return <div className={`tb-text${b.tone ? ` tt-${b.tone}` : ""}`}>{b.text}</div>;
    case "kv":
      return (
        <dl className="tb-kv">
          {b.rows.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>
                <C c={v} />
              </dd>
            </div>
          ))}
        </dl>
      );
    case "table":
      return (
        <div className="tb-table">
          <table>
            <thead>
              <tr>
                {b.head.map((h, i) => (
                  <th key={h} className={b.right?.includes(i) ? "r" : undefined}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {b.rows.map((r, i) => (
                <tr key={i}>
                  {r.map((c, j) => (
                    <td key={j} className={b.right?.includes(j) ? "r" : undefined}>
                      <C c={c} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
  }
}

export default function Terminal() {
  const host = useGhost((s) => s.host);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [line, setLine] = useState("");
  const [history, setHistory] = useState<string[]>(loadHistory);
  const [hIdx, setHIdx] = useState(-1);
  const [pending, setPending] = useState<Outcome["confirm"] | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    input.current?.focus();
    if (!entries.length)
      execute("durum").then((o) =>
        setEntries([
          {
            id: ++seq,
            ts: Date.now(),
            input: "",
            blocks: [
              { kind: "text", text: "Ghost Terminal — sistem kabuğu değil, Ghost Monitor’ün komut dili. “yardım” ile başlayın.", tone: "dim" },
              ...o.blocks,
            ],
          },
        ]),
      );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [entries]);

  function remember(cmd: string) {
    setHistory((h) => {
      const next = [cmd, ...h.filter((x) => x !== cmd)].slice(0, 100);
      try {
        localStorage.setItem(HIST_KEY, JSON.stringify(next));
      } catch {
        /* history is a convenience only */
      }
      return next;
    });
  }

  async function submit() {
    const cmd = line.trim();
    setLine("");
    setHIdx(-1);
    if (!cmd) return;
    const id = ++seq;

    if (pending) {
      const p = pending;
      setPending(null);
      const yes = ["evet", "e", "yes"].includes(cmd.toLocaleLowerCase("tr-TR"));
      setEntries((e) => [...e, { id, ts: Date.now(), input: cmd, blocks: [], running: yes }]);
      const o: Outcome = yes ? await p.run() : { blocks: [{ kind: "text", text: "İptal edildi", tone: "dim" }] };
      setEntries((e) => e.map((x) => (x.id === id ? { ...x, blocks: o.blocks, running: false } : x)));
      return;
    }

    remember(cmd);
    setEntries((e) => [...e, { id, ts: Date.now(), input: cmd, blocks: [], running: true }]);
    const o = await execute(cmd);
    if (o.clear) {
      setEntries([]);
      return;
    }
    setEntries((e) => e.map((x) => (x.id === id ? { ...x, blocks: o.blocks, running: false, prompt: o.confirm?.prompt } : x)));
    if (o.confirm) setPending(o.confirm);
  }

  function onKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      submit();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const i = Math.min(hIdx + 1, history.length - 1);
      if (i >= 0) {
        setHIdx(i);
        setLine(history[i]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const i = hIdx - 1;
      setHIdx(Math.max(i, -1));
      setLine(i >= 0 ? history[i] : "");
    } else if (e.key === "Tab") {
      e.preventDefault();
      const [head, ...rest] = line.split(" ");
      if (rest.length) return;
      const c = complete(head);
      if (c.length === 1) setLine(c[0] + " ");
      else if (c.length > 1)
        setEntries((x) => [...x, { id: ++seq, ts: Date.now(), input: line, blocks: [{ kind: "text", text: c.join("   "), tone: "dim" }] }]);
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setEntries([]);
    } else if (e.key === "Escape" && pending) {
      setPending(null);
      setEntries((x) => [...x, { id: ++seq, ts: Date.now(), input: "", blocks: [{ kind: "text", text: "İptal edildi", tone: "dim" }] }]);
    }
  }

  const promptHost = host?.hostname.toLocaleLowerCase("tr-TR") ?? "ghost";

  return (
    <div className="term" onMouseUp={() => !window.getSelection()?.toString() && input.current?.focus()}>
      <div className="term__scroll selectable" ref={scroller}>
        {entries.map((en) => (
          <section key={en.id} className="term__entry">
            {en.input && (
              <div className="term__in">
                <span className="term__ps">
                  {promptHost}
                  <b>›</b>
                </span>
                <span>{en.input}</span>
                <time>{clock(en.ts)}</time>
              </div>
            )}
            {en.running && <div className="term__run" />}
            {en.blocks.map((b, i) => (
              <Render key={i} b={b} />
            ))}
            {en.prompt && <div className="tb-text tt-warn term__confirm">{en.prompt}</div>}
          </section>
        ))}
      </div>
      <label className={`term__line${pending ? " is-confirm" : ""}`}>
        <span className="term__ps">
          {pending ? "onay" : promptHost}
          <b>›</b>
        </span>
        <input
          ref={input}
          value={line}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => setLine(e.target.value)}
          onKeyDown={onKey}
          placeholder={pending ? "evet / hayır (Esc iptal)" : "komut yazın — yardım"}
        />
      </label>
    </div>
  );
}
