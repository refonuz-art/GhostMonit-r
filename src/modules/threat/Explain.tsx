import { useState } from "react";
import type { Severity, Signal } from "../../ipc/types";
import { explainSignals, verdictAdvice } from "../../state/explain";

/** "Bu ne demek?" — plain-language reading of the evidence, open by default for serious cases. */
export function Explain({ signals, severity }: { signals: Signal[]; severity: Severity }) {
  const items = explainSignals(signals);
  const serious = severity === "HIGH" || severity === "CRITICAL";
  const [open, setOpen] = useState(serious);
  if (items.length === 0) return null;
  return (
    <section className={`explain${open ? " is-open" : ""}`}>
      <button className="explain__head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span>Bu ne demek, ne yapmalıyım?</span>
        <i aria-hidden="true">{open ? "−" : "+"}</i>
      </button>
      {open && (
        <div className="explain__body">
          <p className={`explain__verdict sevtx--${severity}`}>{verdictAdvice({ severity })}</p>
          <ol>
            {items.map((e) => (
              <li key={e.rule}>
                <p>{e.why}</p>
                <p className="explain__todo">{e.todo}</p>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
