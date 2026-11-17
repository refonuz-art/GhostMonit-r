import { useEffect, useState, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api } from "../../ipc/api";
import { guard } from "../../ipc/guard";
import { assistantApi, type AssistantStatus, type InstallProgress } from "../../ipc/assistant";
import * as voice from "../../assistant/voice";
import { intel } from "../../ipc/intel";
import { settingsApi, type AppSettings, type UpdateInfo } from "../../ipc/settings";
import { on } from "../../ipc/api";
import type { Severity } from "../../ipc/types";
import { useGhost } from "../../state/store";
import "./settings.css";

function Switch({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button role="switch" aria-checked={on} aria-label={label} className={`st-switch${on ? " is-on" : ""}`} onClick={() => onChange(!on)}>
      <i />
    </button>
  );
}

function Seg<T extends string | number>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: [T, string][];
  onChange: (v: T) => void;
}) {
  return (
    <div className="seg">
      {options.map(([v, l]) => (
        <button key={String(v)} className={v === value ? "is-on" : ""} onClick={() => onChange(v)}>
          {l}
        </button>
      ))}
    </div>
  );
}

/** abuse.ch Auth-Key: stored DPAPI-encrypted by the backend, never shown again. */
function FeedKey({ hasKey, onChange }: { hasKey: boolean; onChange: (v: boolean) => void }) {
  const notify = useGhost((s) => s.notify);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const saveKey = async (k: string | null) => {
    try {
      await intel.abuseSetKey(k);
      setKey("");
      onChange(k !== null);
      notify(k ? "Anahtar şifrelenerek kaydedildi" : "Anahtar silindi");
    } catch (e) {
      notify(String(e), "bad");
    }
  };
  const updateNow = async () => {
    setBusy(true);
    try {
      const r = await intel.feedUpdateNow();
      notify(`${r.seen} hash indirildi, ${r.added} yeni · toplam ${r.total}`);
    } catch (e) {
      notify(String(e), "bad");
    } finally {
      setBusy(false);
    }
  };
  return hasKey ? (
    <>
      <button className="btn" disabled={busy} onClick={updateNow}>
        {busy ? "İndiriliyor…" : "Şimdi güncelle"}
      </button>
      <button className="btn btn--quiet" onClick={() => saveKey(null)}>
        Anahtarı sil
      </button>
    </>
  ) : (
    <form
      className="st-key"
      onSubmit={(e) => {
        e.preventDefault();
        if (key.trim()) saveKey(key.trim());
      }}
    >
      <input className="field" type="password" placeholder="abuse.ch Auth-Key" value={key} onChange={(e) => setKey(e.target.value)} />
      <button className="btn" disabled={!key.trim()}>
        Kaydet
      </button>
    </form>
  );
}


/** Azure Speech and Claude keys for the assistant; DPAPI-encrypted, never shown again. */
function AssistantKeys({ status, onChange }: { status: AssistantStatus | null; onChange: (s: AssistantStatus) => void }) {
  const notify = useGhost((s) => s.notify);
  const [azKey, setAzKey] = useState("");
  const [region, setRegion] = useState("westeurope");
  const [cKey, setCKey] = useState("");
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<AssistantStatus>, ok: string) => {
    setBusy(true);
    try {
      onChange(await fn());
      window.dispatchEvent(new Event("gm-assistant-keys"));
      setAzKey("");
      setCKey("");
      notify(ok);
    } catch (e) {
      notify(String(e), "bad");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="st-phone">
      {status?.azure ? (
        <div className="st-phone__row">
          <span className="st-ok">Azure Speech bağlı ({status.azureRegion})</span>
          <button className="btn btn--quiet" disabled={busy} onClick={() => run(() => assistantApi.setAzure(null, null), "Azure anahtarı silindi")}>
            Kaldır
          </button>
        </div>
      ) : (
        <form
          className="st-key"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => assistantApi.setAzure(azKey, region), "Azure Speech anahtarı şifrelenerek kaydedildi");
          }}
        >
          <input className="field" type="password" placeholder="Azure Speech anahtarı" value={azKey} onChange={(e) => setAzKey(e.target.value)} />
          <input className="field" placeholder="bölge" value={region} onChange={(e) => setRegion(e.target.value)} style={{ width: 100 }} />
          <button className="btn" disabled={busy || !azKey.trim() || !region.trim()}>
            Kaydet
          </button>
        </form>
      )}
      {status?.claude ? (
        <div className="st-phone__row">
          <span className="st-ok">Claude bağlı</span>
          <button className="btn btn--quiet" disabled={busy} onClick={() => run(() => assistantApi.setClaude(null), "Claude anahtarı silindi")}>
            Kaldır
          </button>
        </div>
      ) : (
        <form
          className="st-key"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => assistantApi.setClaude(cKey), "Claude anahtarı şifrelenerek kaydedildi");
          }}
        >
          <input className="field" type="password" placeholder="Claude API anahtarı (sk-ant-…)" value={cKey} onChange={(e) => setCKey(e.target.value)} />
          <button className="btn" disabled={busy || !cKey.trim()}>
            Kaydet
          </button>
        </form>
      )}
    </div>
  );
}

/** One-time download of the offline Turkish recogniser, with progress. */
function SttInstall({ status, onChange }: { status: AssistantStatus | null; onChange: (s: AssistantStatus) => void }) {
  const notify = useGhost((s) => s.notify);
  const [prog, setProg] = useState<InstallProgress | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const u = on<InstallProgress>("assistant-install", setProg);
    return () => {
      u.then((f) => f());
    };
  }, []);
  if (status?.localStt) return <span className="st-ok">kurulu</span>;
  const pct = prog && prog.total ? Math.round((prog.done / prog.total) * 100) : null;
  return (
    <button
      className="btn"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          onChange(await assistantApi.installStt());
          window.dispatchEvent(new Event("gm-assistant-keys"));
          notify("Konuşma tanıma kuruldu; Ctrl+Boşluk ile konuşabilirsiniz");
        } catch (e) {
          notify(String(e), "bad");
        } finally {
          setBusy(false);
          setProg(null);
        }
      }}
    >
      {!busy
        ? "Konuşma tanımayı kur (≈580 MB)"
        : prog?.stage === "model"
          ? `Model indiriliyor… ${pct ?? 0}%`
          : "Program indiriliyor…"}
    </button>
  );
}

/** City field that saves on blur / Enter rather than on every keystroke. */
function CityField({ value, onSave }: { value: string | null; onSave: (v: string | null) => void }) {
  const [v, setV] = useState(value ?? "");
  useEffect(() => setV(value ?? ""), [value]);
  const commit = () => {
    const t = v.trim();
    if (t !== (value ?? "")) onSave(t || null);
  };
  return (
    <input
      className="field"
      placeholder="ör. İstanbul"
      value={v}
      onChange={(e) => setV(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === "Enter" && commit()}
      style={{ width: 160 }}
    />
  );
}

/** Telegram bot / Discord webhook credentials, stored DPAPI-encrypted; never shown again. */
function PhoneSetup({ status, onChange }: { status: { telegram: boolean; discord: boolean }; onChange: () => void }) {
  const notify = useGhost((s) => s.notify);
  const [token, setToken] = useState("");
  const [chat, setChat] = useState("");
  const [hook, setHook] = useState("");
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      notify(ok);
      onChange();
    } catch (e) {
      notify(String(e), "bad");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="st-phone">
      {status.telegram ? (
        <div className="st-phone__row">
          <span className="st-ok">Telegram bağlı</span>
          <button className="btn btn--quiet" onClick={() => run(() => guard.setTelegram(null, null), "Telegram bağlantısı silindi")}>
            Kaldır
          </button>
        </div>
      ) : (
        <form
          className="st-key"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => guard.setTelegram(token.trim(), chat.trim()), "Telegram şifrelenerek kaydedildi").then(() => {
              setToken("");
              setChat("");
            });
          }}
        >
          <input className="field" type="password" placeholder="Telegram bot anahtarı" value={token} onChange={(e) => setToken(e.target.value)} />
          <input className="field" placeholder="Sohbet kimliği" value={chat} onChange={(e) => setChat(e.target.value)} />
          <button className="btn" disabled={busy || !token.trim() || !chat.trim()}>
            Kaydet
          </button>
        </form>
      )}
      {status.discord ? (
        <div className="st-phone__row">
          <span className="st-ok">Discord bağlı</span>
          <button className="btn btn--quiet" onClick={() => run(() => guard.setDiscord(null), "Discord bağlantısı silindi")}>
            Kaldır
          </button>
        </div>
      ) : (
        <form
          className="st-key"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => guard.setDiscord(hook.trim()), "Discord şifrelenerek kaydedildi").then(() => setHook(""));
          }}
        >
          <input className="field" type="password" placeholder="Discord webhook adresi" value={hook} onChange={(e) => setHook(e.target.value)} />
          <button className="btn" disabled={busy || !hook.trim()}>
            Kaydet
          </button>
        </form>
      )}
      {(status.telegram || status.discord) && (
        <button className="btn" disabled={busy} onClick={() => run(() => guard.remoteTest(), "Test bildirimi gönderildi")}>
          Test bildirimi gönder
        </button>
      )}
    </div>
  );
}

function UpdateBox({ current }: { current: string }) {
  const notify = useGhost((s) => s.notify);
  const [state, setState] = useState<"idle" | "checking" | "none" | "installing">("idle");
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [pct, setPct] = useState<number | null>(null);
  useEffect(() => {
    const a = on<UpdateInfo>("update", setInfo);
    const b = on<{ downloaded: number; total: number | null }>("update-progress", (p) =>
      setPct(p.total ? Math.round((p.downloaded / p.total) * 100) : null),
    );
    return () => {
      a.then((f) => f());
      b.then((f) => f());
    };
  }, []);
  const check = async () => {
    setState("checking");
    try {
      const u = await settingsApi.checkUpdate();
      setInfo(u);
      setState(u ? "idle" : "none");
    } catch (e) {
      setState("idle");
      notify(String(e), "bad");
    }
  };
  const install = async () => {
    setState("installing");
    try {
      await settingsApi.installUpdate();
    } catch (e) {
      setState("idle");
      notify(String(e), "bad");
    }
  };
  if (info)
    return (
      <div className="st-update">
        <p>
          <b className="st-ok">Ghost Monitor {info.version}</b> yayımlandı (kurulu: {current}).
        </p>
        {info.notes && <pre className="selectable">{info.notes}</pre>}
        <button className="btn" disabled={state === "installing"} onClick={install}>
          {state === "installing" ? (pct !== null ? `İndiriliyor… %${pct}` : "Kuruluyor…") : "İndir, kur ve yeniden başlat"}
        </button>
      </div>
    );
  return (
    <button className="btn" disabled={state === "checking"} onClick={check}>
      {state === "checking" ? "Denetleniyor…" : state === "none" ? "Güncel ✓ — tekrar denetle" : "Şimdi denetle"}
    </button>
  );
}

function Row({ title, hint, children, note }: { title: string; hint: ReactNode; children: ReactNode; note?: ReactNode }) {
  return (
    <div className="st-row">
      <div className="st-row__text">
        <b>{title}</b>
        <span>{hint}</span>
        {note && <em>{note}</em>}
      </div>
      <div className="st-row__ctl">{children}</div>
    </div>
  );
}

const SEVERITIES: [Severity, string][] = [
  ["LOW", "Düşük"],
  ["MEDIUM", "Orta"],
  ["HIGH", "Yüksek"],
  ["CRITICAL", "Kritik"],
];

export default function Settings() {
  const host = useGhost((s) => s.host);
  const notify = useGhost((s) => s.notify);
  const [s, setS] = useState<AppSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedKey, setFeedKey] = useState(false);
  const [phone, setPhone] = useState({ telegram: false, discord: false });
  const loadPhone = () => guard.remoteStatus().then(setPhone, () => {});
  const [asst, setAsst] = useState<AssistantStatus | null>(null);

  useEffect(() => {
    intel.abuseHasKey().then(setFeedKey, () => {});
    loadPhone();
    assistantApi.status().then(setAsst, () => {});
    settingsApi.get().then(setS, (e) => notify(`Ayarlar okunamadı: ${e}`, "bad"));
  }, [notify]);

  const save = async (patch: Partial<AppSettings>) => {
    if (!s) return;
    const prev = s;
    const next = { ...s, ...patch };
    setS(next);
    setBusy(true);
    try {
      setS(await settingsApi.save(next));
    } catch (e) {
      setS(prev);
      notify(`Kaydedilemedi: ${e}`, "bad");
    } finally {
      setBusy(false);
    }
  };

  if (!s) return <div className="module-loading" />;

  const pickDir = async () => {
    const dir = await open({ directory: true, title: "Raporların kaydedileceği klasör" });
    if (typeof dir === "string") save({ autoReportDir: dir });
  };

  return (
    <div className="st">
      <aside className="st-side">
        <h2>Ayarlar</h2>
        <p className="st-side__lead">Değişiklikler anında kaydedilir ve yeniden başlatma gerektirmez.</p>
        <dl className="facts">
          <dt>Windows ile</dt>
          <dd className={s.autostart ? "st-ok" : ""}>{s.autostart ? "başlıyor (tepside)" : "başlamıyor"}</dd>
          <dt>Kapat düğmesi</dt>
          <dd>{s.closeToTray ? "tepsiye indirir" : "uygulamayı kapatır"}</dd>
          <dt>Bildirim</dt>
          <dd>{s.notify ? `${SEVERITIES.find(([v]) => v === s.notifyMinSeverity)?.[1].toLowerCase()} ve üzeri` : "kapalı"}</dd>
          <dt>Yetki</dt>
          <dd className={host?.elevated ? "st-ok" : ""}>{host?.elevated ? "yönetici" : "standart kullanıcı"}</dd>
        </dl>
        {host && (
          <div className="st-data">
            <span>Veri klasörü</span>
            <code className="selectable">{host.dataDir}</code>
            <button className="btn btn--quiet" onClick={() => api.reveal(host.dataDir)}>
              Klasörü aç
            </button>
          </div>
        )}
        <div className="st-side__end">
          <button className="btn btn--danger" onClick={() => settingsApi.quit()}>
            İzlemeyi durdur ve çık
          </button>
          <span>Pencereyi kapatmak izlemeyi durdurmaz; tamamen kapatmak için bunu kullanın.</span>
        </div>
      </aside>

      <div className="st-main" aria-busy={busy}>
        <section>
          <h3>Güncelleme</h3>
          <Row
            title={`Sürüm ${host?.appVersion ?? ""}`}
            hint="Yeni sürümler GitHub'daki Ghost Monitor sayfasından alınır. Her paketin imzası uygulamanın içindeki anahtarla doğrulanır; imzası tutmayan paket kurulmaz."
          >
            <UpdateBox current={host?.appVersion ?? ""} />
          </Row>
          <Row title="Yeni sürümleri kendiliğinden denetle" hint="Günde iki kez bakılır, yeni sürüm varsa bildirim gelir. Kurulum her zaman sizin onayınızla yapılır.">
            <Switch label="Güncelleme denetimi" on={s.updateCheck} onChange={(v) => save({ updateCheck: v })} />
          </Row>
        </section>

        <section>
          <h3>Arka planda çalışma</h3>
          <Row
            title="Windows açılışında başlat"
            hint="Oturum açtığınızda Ghost Monitor pencere açmadan tepside başlar ve izlemeye hemen başlar."
            note="Kullanıcı Run anahtarına tek bir girdi yazar; yönetici izni gerekmez."
          >
            <Switch label="Windows açılışında başlat" on={s.autostart} onChange={(v) => save({ autostart: v })} />
          </Row>
          <Row title="Kapatınca tepsiye indir" hint="Pencereyi kapatmak izlemeyi durdurmaz. Tepsi simgesine tıklayarak geri açabilirsiniz.">
            <Switch label="Kapatınca tepsiye indir" on={s.closeToTray} onChange={(v) => save({ closeToTray: v })} />
          </Row>
        </section>

        <section>
          <h3>Bildirimler</h3>
          <Row
            title="Windows bildirimleri"
            hint="Uygulama ön planda değilken önemli bulgular sağ altta bildirim olarak görünür. En fazla 20 saniyede bir; arada kalanlar sonraki bildirimde toplanır."
          >
            <Switch label="Windows bildirimleri" on={s.notify} onChange={(v) => save({ notify: v })} />
          </Row>
          <Row title="En düşük önem" hint="Bunun altındaki olaylar yalnızca zaman çizelgesinde kalır.">
            <Seg value={s.notifyMinSeverity} options={SEVERITIES} onChange={(v) => save({ notifyMinSeverity: v })} />
          </Row>
        </section>

        <section>
          <h3>İzleme</h3>
          <Row title="Açılış girdisi tarama aralığı" hint="Run anahtarları, başlangıç klasörü, zamanlanmış görevler ve hizmetler bu aralıkla yeniden okunur.">
            <Seg
              value={s.startupScanMinutes}
              options={[
                [5, "5 dk"],
                [10, "10 dk"],
                [30, "30 dk"],
                [60, "1 sa"],
              ]}
              onChange={(v) => save({ startupScanMinutes: v })}
            />
          </Row>
          <Row title="Olay geçmişini sakla" hint="Daha eski olaylar saatte bir silinir. Bulgular ve güven listesi silinmez.">
            <Seg
              value={s.retentionDays}
              options={[
                [7, "7 gün"],
                [30, "30 gün"],
                [90, "90 gün"],
                [365, "1 yıl"],
              ]}
              onChange={(v) => save({ retentionDays: v })}
            />
          </Row>
          <Row
            title="İndirilenler ve Masaüstü izleme"
            hint="Bu klasörlere yeni bir çalıştırılabilir dosya veya betik düştüğünde otomatik analiz edilir."
          >
            <Switch label="Dosya izleme" on={s.fileWatch} onChange={(v) => save({ fileWatch: v })} />
          </Row>
          <Row title="USB sürücü izleme" hint="Takılan her sürücü kaydedilir; kökünde otomatik çalışan dosya veya program varsa işaretlenir.">
            <Switch label="USB izleme" on={s.usbWatch} onChange={(v) => save({ usbWatch: v })} />
          </Row>
        </section>

        <section>
          <h3>Koruma</h3>
          <Row
            title="Fidye yazılımı kalkanı"
            hint="Belgeler, Masaüstü ve Resimler klasörlerine gizli tuzak dosyalar koyar ve bu klasörlerde saniyeler içinde çok sayıda dosyanın yeniden adlandırılmasını veya yeniden yazılmasını izler. Bir şey olursa diske en çok yazan programları gösterir; hiçbir şeyi kendiliğinden kapatmaz."
            note="Kapatınca tuzak dosyalar silinir."
          >
            <Switch label="Fidye yazılımı kalkanı" on={s.ransomShield} onChange={(v) => save({ ransomShield: v })} />
          </Row>
          <Row
            title="Windows olay günlüğü"
            hint="Başarısız oturum açma denemeleri, yeni kullanıcı hesabı, yönetici grubuna ekleme, günlük temizleme, yeni hizmet kurulumu ve Defender algılamaları izlenir."
            note={host?.elevated ? undefined : "Oturum ve hesap olayları (Security günlüğü) yalnızca yönetici olarak çalışırken okunabilir."}
          >
            <Switch label="Olay günlüğü" on={s.eventlogWatch} onChange={(v) => save({ eventlogWatch: v })} />
          </Row>
          <Row title="Ev ağı cihazları" hint="Windows'un zaten bildiği ağ komşuları dakikada bir okunur; ağa yeni bir cihaz katılınca zaman çizelgesine yazılır. Ağa paket gönderilmez.">
            <Switch label="Ev ağı izleme" on={s.lanWatch} onChange={(v) => save({ lanWatch: v })} />
          </Row>
        </section>

        <section>
          <h3>Telefon bildirimleri</h3>
          <Row
            title="Telegram veya Discord"
            hint="Önemli bir olay olduğunda telefonunuza mesaj gelir. Telegram için @BotFather'dan bot oluşturup anahtarını ve sohbet kimliğinizi, Discord için kanal ayarlarından webhook adresini girin."
            note="Bilgiler bu Windows kullanıcısına bağlı olarak şifreli saklanır. Dakikada en fazla bir mesaj gider."
          >
            <PhoneSetup status={phone} onChange={loadPhone} />
          </Row>
          <Row title="Telefona gönder" hint="Kapalıyken hiçbir mesaj gönderilmez.">
            <Switch
              label="Telefon bildirimleri"
              on={s.remoteNotify && (phone.telegram || phone.discord)}
              onChange={(v) => (phone.telegram || phone.discord ? save({ remoteNotify: v }) : notify("Önce Telegram veya Discord bağlayın", "warn"))}
            />
          </Row>
          <Row title="En düşük önem" hint="Telefona yalnızca bu düzey ve üstü gider.">
            <Seg value={s.remoteMinSeverity} options={SEVERITIES.slice(1)} onChange={(v) => save({ remoteMinSeverity: v })} />
          </Row>
          <Row
            title="Ayrıntıları da gönder"
            hint="Kapalıyken yalnızca olay başlığı ve bilgisayar adı gider. Açıkken dosya yolları ve IP adresleri de mesaja eklenir."
          >
            <Switch label="Ayrıntıları gönder" on={s.remoteDetails} onChange={(v) => save({ remoteDetails: v })} />
          </Row>
        </section>

        <section>
          <h3>Asistan</h3>
          <Row
            title={`Sesli asistan (${s.assistantName})`}
            hint="Önemli uyarıları sesli ve ekranda bildirir, komutlarınızı yerine getirir. Ekranın sağ altındaki figüre tıklayın ya da Ctrl+Boşluk'a basıp konuşun."
          >
            <Switch label="Sesli asistan" on={s.assistantEnabled} onChange={(v) => save({ assistantEnabled: v })} />
          </Row>
          <Row title="Figürü ekranda göster" hint="Kapalıyken asistan yine konuşur; panel Ctrl+Boşluk ile açılır.">
            <Switch label="Figür" on={s.assistantFloat} onChange={(v) => save({ assistantFloat: v })} />
          </Row>
          <Row title="Uyarıları sesli oku" hint="Seçilen düzey ve üstündeki yeni olaylar sesli okunur. Arka arkaya gelen uyarılar tek cümlede toplanır.">
            <Switch label="Sesli uyarı" on={s.assistantSpeakAlerts} onChange={(v) => save({ assistantSpeakAlerts: v })} />
          </Row>
          <Row title="Sesli uyarı düzeyi" hint="Daha düşük düzeyler yalnızca panelde görünür.">
            <Seg value={s.assistantMinSeverity} options={SEVERITIES.slice(1)} onChange={(v) => save({ assistantMinSeverity: v })} />
          </Row>
          <Row
            title="Ses"
            hint="Windows sesi bilgisayarda yüklü Türkçe sesi kullanır ve internetsiz çalışır. Azure sesi çok daha doğal bir kadın (Emel) ya da erkek (Ahmet) sesidir; Azure Speech anahtarı ister ve okunacak metni Microsoft'a gönderir."
            note={asst?.azure ? undefined : "Azure sesi için önce aşağıdan anahtar ekleyin."}
          >
            <Seg
              value={s.assistantVoice}
              options={[
                ["windows", "Windows"],
                ["azure", "Azure (doğal)"],
              ]}
              onChange={(v) => (v === "azure" && !asst?.azure ? notify("Önce Azure Speech anahtarını ekleyin", "warn") : save({ assistantVoice: v }))}
            />
            {s.assistantVoice === "azure" && (
              <Seg
                value={s.assistantAzureVoice}
                options={[
                  ["tr-TR-EmelNeural", "Emel"],
                  ["tr-TR-AhmetNeural", "Ahmet"],
                ]}
                onChange={(v) => save({ assistantAzureVoice: v })}
              />
            )}
          </Row>
          <Row title="Konuşma hızı" hint="Sesi denemek için yandaki düğmeyi kullanın.">
            <Seg
              value={s.assistantRate}
              options={[
                [0.9, "Yavaş"],
                [1, "Normal"],
                [1.15, "Hızlı"],
              ]}
              onChange={(v) => save({ assistantRate: v })}
            />
            <button
              className="btn"
              onClick={() => {
                voice.configure(s.assistantVoice === "azure" && asst?.azure ? "azure" : "windows", s.assistantRate);
                void voice.say(`Merhaba, ben ${s.assistantName}. Bilgisayarınızı izliyorum; şüpheli bir durum olursa sizi hemen uyaracağım.`, true);
              }}
            >
              Sesi dene
            </button>
          </Row>
          <Row title="Şehir" hint="“Hava nasıl?” sorusu için. Yalnızca hava durumu sorulduğunda şehir adı Open-Meteo servisine gönderilir.">
            <CityField value={s.assistantCity} onSave={(v) => save({ assistantCity: v })} />
          </Row>
          <Row
            title="Konuşma tanıma (internetsiz)"
            hint="Sesli komutlar bilgisayarınızda Whisper modeliyle yazıya çevrilir; ses hiçbir yere gönderilmez. Bir kez indirilir, imzası doğrulanır."
          >
            <SttInstall status={asst} onChange={setAsst} />
          </Row>
          <Row
            title="Azure Speech (isteğe bağlı)"
            hint="Doğal kadın sesi (Emel) için Azure Speech kullanılır (portal.azure.com → Speech hizmeti; ücretsiz katman ayda 5 saat tanıma ve 500 bin karakter ses içerir). Anahtar yoksa asistan yazılı komutlarla ve Windows sesiyle çalışır."
            note="Konuşma yalnızca Konuş düğmesine ya da Ctrl+Boşluk'a bastığınızda kaydedilir; sürekli dinleme yoktur."
          >
            <AssistantKeys status={asst} onChange={setAsst} />
          </Row>
          <Row
            title="Serbest sohbet (Claude)"
            hint="Yerel komutların dışındaki her soru (genel bilgi, güncel haberler, açıklamalar) Claude'a gönderilir. Anahtar yoksa bu özellik kapalıdır; yerel komutlar yine çalışır."
            note="Gönderilen: sorunuz, konuşma geçmişi ve istendiğinde güvenlik durumu özeti."
          >
            <span className="dim">{asst?.claude ? "açık" : "anahtar bekleniyor"}</span>
          </Row>
        </section>

        <section>
          <h3>Tehdit istihbaratı</h3>
          <Row
            title="abuse.ch anahtarı"
            hint={
              feedKey
                ? "Anahtar bu Windows kullanıcısına bağlı olarak şifreli saklanıyor."
                : "MalwareBazaar listesi ücretsiz bir anahtar istiyor. auth.abuse.ch adresinden hesap açıp anahtarınızı buraya yapıştırın."
            }
          >
            <FeedKey hasKey={feedKey} onChange={setFeedKey} />
          </Row>
          <Row
            title="Kötü amaçlı yazılım listesini günlük güncelle"
            hint="MalwareBazaar'ın son 48 saatte eklenen örneklerinin SHA-256 listesi günde bir indirilir ve yerel hash veritabanına eklenir. Çalışan programlar ve indirilen dosyalar bu listeyle karşılaştırılır."
            note="Açıkken günde bir kez mb-api.abuse.ch adresine yalnızca anahtarınızla istek gider. Dosyalarınızdan veya sisteminizden hiçbir bilgi gönderilmez."
          >
            <Switch label="Liste güncelleme" on={s.feedAutoUpdate && feedKey} onChange={(v) => (feedKey ? save({ feedAutoUpdate: v }) : notify("Önce abuse.ch anahtarını kaydedin", "warn"))} />
          </Row>
        </section>

        <section>
          <h3>Otomatik rapor</h3>
          <Row title="Sıklık" hint="Günlük rapor her gece 00:05'te, haftalık rapor pazartesi 00:05'te bir önceki dönem için yazılır.">
            <Seg
              value={s.autoReport}
              options={[
                ["off", "Kapalı"],
                ["daily", "Günlük"],
                ["weekly", "Haftalık"],
              ]}
              onChange={(v) => save({ autoReport: v })}
            />
          </Row>
          <Row title="Biçim" hint="PDF okumak için, JSON başka araçlara aktarmak için.">
            <Seg
              value={s.autoReportFormat}
              options={[
                ["pdf", "PDF"],
                ["json", "JSON"],
              ]}
              onChange={(v) => save({ autoReportFormat: v })}
            />
          </Row>
          <Row
            title="Klasör"
            hint={
              <code className="selectable">{s.autoReportDir ?? "Belgeler\\Ghost Monitor Raporları (varsayılan)"}</code>
            }
          >
            <button className="btn" onClick={pickDir}>
              Değiştir
            </button>
            {s.autoReportDir && (
              <button className="btn btn--quiet" onClick={() => save({ autoReportDir: null })}>
                Varsayılan
              </button>
            )}
          </Row>
        </section>
      </div>
    </div>
  );
}
