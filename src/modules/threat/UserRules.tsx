import { useEffect, useState } from "react";
import { SEV_LABEL, Sev } from "../../design/components";
import type { Severity } from "../../ipc/types";
import { newRule, v5, type RuleMatch, type UserRule } from "../../ipc/v5";
import { useGhost } from "../../state/store";
import { RULE_TEMPLATES, fromTemplate } from "./ruleTemplates";

const SIGNER: [UserRule["signer"], string][] = [
  ["any", "fark etmez"],
  ["unsigned", "imzasız"],
  ["invalid", "geçersiz imza"],
  ["signed", "imzalı"],
];
const LEVELS: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Shared state for the rule list (left column) and the editor (right column). */
export function useUserRules() {
  const [rules, setRules] = useState<UserRule[] | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [draft, setDraft] = useState<UserRule | null>(null);
  useEffect(() => {
    v5.rules().then(setRules, () => setRules([]));
  }, []);
  return { rules, setRules, sel, setSel, draft, setDraft };
}
type RulesState = ReturnType<typeof useUserRules>;

function summary(r: UserRule): string {
  const parts: string[] = [];
  if (r.namePat) parts.push(`ad ${r.namePat}`);
  if (r.pathPat) parts.push(`yol ${r.pathPat}`);
  if (r.parentPat) parts.push(`üst ${r.parentPat}`);
  if (r.cmdContains) parts.push(`komut “${r.cmdContains}”`);
  if (r.signer !== "any") parts.push(SIGNER.find(([k]) => k === r.signer)![1]);
  if (r.publisherContains) parts.push(`yayıncı ${r.publisherContains}`);
  if (r.internet) parts.push("internete bağlanıyor");
  if (r.remotePorts) parts.push(`port ${r.remotePorts}`);
  if (r.listens) parts.push("port dinliyor");
  return parts.join(" · ") || "koşul yok";
}

export function RuleList({ st }: { st: RulesState }) {
  const { rules, sel, setSel, setDraft } = st;
  if (!rules) return <div className="module-loading" />;
  return (
    <>
      <div className="ur-new">
        <button
          className="btn"
          onClick={() => {
            const r = newRule();
            setDraft(r);
            setSel(r.id);
          }}
        >
          + Yeni kural
        </button>
        <select
          className="field ur-tpl"
          value=""
          aria-label="Hazır kural şablonu"
          onChange={(e) => {
            const t = RULE_TEMPLATES.find((x) => x.id === e.target.value);
            if (!t) return;
            const r = fromTemplate(t);
            setDraft(r);
            setSel(r.id);
          }}
        >
          <option value="">Hazır şablondan…</option>
          {RULE_TEMPLATES.map((t) => (
            <option key={t.id} value={t.id} title={t.why}>
              {t.title}
            </option>
          ))}
        </select>
      </div>
      {rules.length === 0 && (
        <div className="empty">
          <strong>Henüz kendi kuralınız yok</strong>
          <span>“İndirilenler'den çalışan imzasız program = Yüksek” ya da “D:\Oyunlar altındakileri yok say” gibi kurallar ekleyebilirsiniz.</span>
        </div>
      )}
      {rules.map((r) => (
        <button
          key={r.id}
          className={`case ur-row${sel === r.id ? " is-on" : ""}${r.enabled ? "" : " is-off"} risk-${r.action === "ignore" ? "INFO" : r.severity}`}
          onClick={() => {
            setSel(r.id);
            setDraft({ ...r });
          }}
        >
          {r.action === "ignore" ? <span className="ur-tag mono">yok say</span> : <Sev level={r.severity} label={false} />}
          <span className="case__t">{r.name}</span>
          <span className="case__e mono">{summary(r)}</span>
          <span className="case__m mono">{r.enabled ? "etkin" : "kapalı"}</span>
        </button>
      ))}
    </>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="ur-field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

export function RuleEditor({ st }: { st: RulesState }) {
  const notify = useGhost((s) => s.notify);
  const { rules, setRules, draft, setDraft, setSel } = st;
  const [matches, setMatches] = useState<RuleMatch[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setMatches(null);
    setErr(null);
  }, [draft?.id]);

  if (!draft || !rules)
    return (
      <div className="ur-help">
        <h3>Kendi kurallarınız</h3>
        <p>Bir kural, dolu bıraktığınız koşulların <em>hepsi</em> tuttuğunda çalışır.</p>
        <ul>
          <li>
            <b>Uyar:</b> Eşleşen işlem için seçtiğiniz seviyede bulgu açılır. Bu sizin açık kararınız olduğundan tek sinyal sınırı uygulanmaz.
          </li>
          <li>
            <b>Yok say:</b> Eşleşen işlemler hiçbir kurala göre değerlendirilmez. Dikkatli kullanın: geniş bir desen zararlı bir dosyayı da gizleyebilir.
          </li>
          <li>
            Desenlerde <code>*</code> herhangi bir metin, <code>?</code> tek bir karakter demektir. Yol deseninde joker yoksa “içeriyor” olarak aranır; ad deseninde tam eşleşme gerekir. Büyük-küçük harf fark etmez.
          </li>
        </ul>
        <p className="dim">Kaydetmeden önce “Şimdi dene” ile kuralın şu an çalışan hangi işlemleri yakaladığını görebilirsiniz.</p>
      </div>
    );

  const set = <K extends keyof UserRule>(k: K, v: UserRule[K]) => {
    setDraft({ ...draft, [k]: v });
    setMatches(null);
  };
  const exists = rules.some((r) => r.id === draft.id);

  const persist = async (next: UserRule[], msg: string) => {
    setSaving(true);
    setErr(null);
    try {
      await v5.saveRules(next);
      setRules(next);
      notify(msg);
      return true;
    } catch (e) {
      setErr(String(e));
      return false;
    } finally {
      setSaving(false);
    }
  };

  const text = (k: "namePat" | "pathPat" | "parentPat" | "cmdContains" | "publisherContains" | "remotePorts", ph: string) => (
    <input className="field mono" value={draft[k]} placeholder={ph} spellCheck={false} onChange={(e) => set(k, e.target.value)} />
  );

  return (
    <div className="ur-editor">
      <header>
        <input className="field ur-name" value={draft.name} placeholder="Kural adı" onChange={(e) => set("name", e.target.value)} />
        <label className="ur-switch">
          <input type="checkbox" checked={draft.enabled} onChange={(e) => set("enabled", e.target.checked)} /> etkin
        </label>
      </header>

      <div className="ur-grid">
        <Field label="Ne yapılsın">
          <div className="seg">
            <button className={draft.action === "alert" ? "is-on" : ""} onClick={() => set("action", "alert")}>
              Uyar
            </button>
            <button className={draft.action === "ignore" ? "is-on" : ""} onClick={() => set("action", "ignore")}>
              Yok say
            </button>
          </div>
        </Field>
        {draft.action === "alert" && (
          <Field label="Seviye">
            <div className="seg">
              {LEVELS.map((l) => (
                <button key={l} className={draft.severity === l ? "is-on" : ""} onClick={() => set("severity", l)}>
                  {SEV_LABEL[l]}
                </button>
              ))}
            </div>
          </Field>
        )}
        <Field label="İşlem adı" hint="ör. *.exe, svch?st.exe">
          {text("namePat", "fark etmez")}
        </Field>
        <Field label="Dosya yolu" hint={"ör. C:\\Users\\*\\Downloads\\*"}>
          {text("pathPat", "fark etmez")}
        </Field>
        <Field label="Üst işlem adı" hint="ör. winword.exe">
          {text("parentPat", "fark etmez")}
        </Field>
        <Field label="Komut satırı içeriyor" hint="ör. -enc">
          {text("cmdContains", "fark etmez")}
        </Field>
        <Field label="İmza">
          <div className="seg">
            {SIGNER.map(([k, l]) => (
              <button key={k} className={draft.signer === k ? "is-on" : ""} onClick={() => set("signer", k)}>
                {l}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Yayıncı içeriyor">{text("publisherContains", "fark etmez")}</Field>
        <Field label="Uzak port" hint="virgülle: 4444, 1337">
          {text("remotePorts", "fark etmez")}
        </Field>
        <Field label="Ağ">
          <div className="ur-checks">
            <label>
              <input type="checkbox" checked={draft.internet} onChange={(e) => set("internet", e.target.checked)} /> internete bağlanıyor
            </label>
            <label>
              <input type="checkbox" checked={draft.listens} onChange={(e) => set("listens", e.target.checked)} /> dışa açık port dinliyor
            </label>
          </div>
        </Field>
        <Field label="Not">
          <input className="field" value={draft.note} placeholder="neden bu kural?" onChange={(e) => set("note", e.target.value)} />
        </Field>
      </div>

      {err && <p className="ur-err">{err}</p>}

      <div className="case-actions">
        <button
          className="btn"
          onClick={() =>
            v5.testRule(draft).then(
              (m) => {
                setMatches(m);
                setErr(null);
              },
              (e) => setErr(String(e)),
            )
          }
        >
          Şimdi dene
        </button>
        <button
          className="btn"
          disabled={saving}
          onClick={() => persist(exists ? rules.map((r) => (r.id === draft.id ? draft : r)) : [...rules, draft], "Kural kaydedildi; birkaç saniye içinde uygulanır")}
        >
          {saving ? "Kaydediliyor…" : "Kaydet"}
        </button>
        {exists && (
          <button
            className="btn btn--quiet"
            disabled={saving}
            onClick={async () => {
              if (await persist(rules.filter((r) => r.id !== draft.id), "Kural silindi")) {
                setDraft(null);
                setSel(null);
              }
            }}
          >
            Sil
          </button>
        )}
      </div>

      {matches && (
        <section className="ur-matches">
          <h3>
            Şu an eşleşen işlemler <span className="mono dim">{matches.length}</span>
          </h3>
          {matches.length === 0 ? (
            <p className="dim">Çalışan hiçbir işlem bu kurala uymuyor.</p>
          ) : (
            <ul>
              {matches.map((m) => (
                <li key={m.pid}>
                  <b>{m.name}</b> <span className="mono dim">PID {m.pid}</span>
                  <code className="mono">{m.evidence}</code>
                </li>
              ))}
            </ul>
          )}
          {draft.action === "ignore" && matches.length > 0 && (
            <p className="ur-warn">Bu işlemler kaydettiğinizde hiçbir kurala göre değerlendirilmeyecek.</p>
          )}
        </section>
      )}
    </div>
  );
}
