# GHOST MONITOR — Proje Son Durum

> Yeni oturumda önce bu dosyayı oku. Gereksinimler: `prompt.md`. Kullanıcı tüm onayları verdi; fazları sırayla ilerlet.

## Durum özeti
**Güncel: 0.6.0 — ayrıntı en altta (0.5.0 ve 0.6.0 bölümleri).** 0.4.0, 0.5.0 ve 0.6.0 GitHub'da TASLAK; kullanıcı test edince yayımlanacak.
**Faz 1–10 + v0.2.0 eklentileri tamam.** Sürüm 0.2.0 GitHub'da: https://github.com/refonuz-art/GhostMonit-r/releases (yalnızca yükleyici + latest.json; kaynak kod depoya YÜKLENMEDİ). Kullanıcının makinesinde kurulu (`%LOCALAPPDATA%\Ghost Monitor`), Windows açılışında tepside başlıyor.

## Çalıştırma
- Geliştirme: `pnpm app:dev` (Vite 1420 + Tauri). Rust MSVC toolchain `src-tauri/rust-toolchain.toml` ile sabit.
- Testler: `cd src-tauri && cargo test` (53 test; motor uçtan uca senaryoları, açılış yaşam döngüsü, canlı imza/TCP/hizmet/görev, DPAPI, PDF dahil) · `pnpm test` (vitest, 19 test; `state/explain.test.ts` Rust'taki her kural kimliğinin açıklaması olduğunu denetler)
- Tip kontrol: `pnpm typecheck`
- Veri: `%APPDATA%\com.nexusghost.monitor\ghost.db` (SQLite), GeoIP: `...\geo\*.mmdb`
- PDF'i incelemek için saklamak: `GM_PDF_OUT=<yol> cargo test pdf_survives`

## Yeni sürüm yayımlama (adım adım)

Kurulu Ghost Monitor'ler GitHub'daki son sürümü günde iki kez denetler. Yeni sürüm görürlerse bildirim gösterirler, kullanıcı Ayarlar → Güncelleme'den tek tıkla kurar. Yayımlamak için:

**Hangi bilgiler nerede**
| Ne | Nerede |
|---|---|
| GitHub deposu (herkese açık) | https://github.com/refonuz-art/GhostMonit-r — kaynak kod `main` dalında, yükleyiciler "Releases" sayfasında |
| Güncelleme adresi (uygulamaya gömülü) | `https://github.com/refonuz-art/GhostMonit-r/releases/latest/download/latest.json` (`src-tauri/tauri.conf.json` → `plugins.updater`) |
| Yayımlama betiği | `scripts/release.ps1` |
| Sürüm notları | `docs/releases/<sürüm>.md` (UTF-8, Türkçe yazılabilir) |
| **Güncelleme imza anahtarı (GİZLİ)** | `C:\Users\user\.tauri\ghostmonitor-updater.key` |
| Anahtarın parolası | `C:\Users\user\.tauri\ghostmonitor-updater.pw` — DPAPI ile şifreli, yalnızca bu Windows kullanıcısı açabilir |
| Açık anahtar | `ghostmonitor-updater.key.pub` + `tauri.conf.json` içindeki `pubkey` |

**1. Sürüm numarasını artır** — üç dosyada aynı numara olmalı (ör. 0.2.0 → 0.2.1):
- `src-tauri/tauri.conf.json` → `"version"`
- `src-tauri/Cargo.toml` → `version = "..."`
- `package.json` → `"version"`

Kural: küçük düzeltme → son hane (0.2.1), yeni özellik → orta hane (0.3.0). Numara mutlaka **büyümeli**; aynı veya küçük numarayı uygulamalar güncelleme saymaz.

**2. Testleri çalıştır**
```
cd src-tauri && cargo test
cd .. && pnpm test && pnpm typecheck
```

**3. Sürüm notunu yaz** — `docs/releases/0.2.1.md` dosyası oluştur. Kısa madde listesi yeterli; bu metin hem GitHub sayfasında hem uygulamanın güncelleme kutusunda görünür.

**4. Kaynak kodu GitHub'a gönder** (etiket bu commit'ten oluşturulur, bu yüzden betikten ÖNCE):
```
git add -A
git commit -m "Ghost Monitor 0.2.1"
git push origin main
```

**5. Derle, imzala, yayımla** — tek komut (PowerShell'de, proje klasöründe):
```
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -NotesFile docs\releases\0.2.1.md
```
Betiğin yaptıkları:
- İmza anahtarını ve parolayı okur, `pnpm app:build` çalıştırır (~5 dk).
- Yükleyiciyi `GhostMonitor_<sürüm>_x64-setup.exe` adıyla kopyalar; adı boşluksuz olmalı çünkü GitHub boşlukları noktaya çevirir.
- Yükleyicinin `.sig` imzasından `latest.json` dosyasını üretir.
- `gh release create v<sürüm>` ile ikisini GitHub'a yükler.

Seçenekler:
- `-Draft`: taslak olarak yükler. Taslak, kullanıcılara görünmez ve güncelleme olarak sunulmaz; GitHub'da "Publish" denince yayına girer.
- `-NoBuild`: derlemeyi atlar, var olan çıktıyı yükler.

**6. Doğrula**
```
gh release view v0.2.1 -R refonuz-art/GhostMonit-r
curl -sL https://github.com/refonuz-art/GhostMonit-r/releases/latest/download/latest.json
```
`latest.json` içinde yeni sürüm numarası görünmeli. Kurulu uygulamada Ayarlar → "Şimdi denetle" yeni sürümü göstermeli.

**Sorun çıkarsa**
- `gh` oturumu yoksa: `gh auth login` (hesap: refonuz-art).
- "installer for X not found": sürüm numarası üç dosyada aynı değil ya da derleme başarısız; `pnpm app:build` çıktısına bak.
- Yanlış sürüm yayımlandıysa: GitHub'da release'i sil (`gh release delete v0.2.1 -R refonuz-art/GhostMonit-r --cleanup-tag`). Ardından numarayı yine **artırarak** tekrar yayımla. Kullanıcılar aynı numarayı ikinci kez almaz.
- Uygulama güncellemeyi "imza doğrulanamadı" diye reddediyorsa: yanlış anahtarla imzalanmış demektir. `tauri.conf.json` içindeki `pubkey` değiştirilmemeli.

**ANAHTAR UYARISI**
- `ghostmonitor-updater.key` kaybolursa veya yeniden üretilirse, kurulu tüm Ghost Monitor'ler yeni sürümleri reddeder. O durumda kullanıcıların yeni sürümü elle indirip kurması gerekir.
- Anahtarı ve parolayı güvenli bir yere (şifreli USB, parola yöneticisi) yedekle. Parola `.pw` dosyasında DPAPI ile şifreli; Windows yeniden kurulursa açılamaz. Bu yüzden parolanın kendisini de yedekle:
  ```
  $s = Get-Content $env:USERPROFILE\.tauri\ghostmonitor-updater.pw | ConvertTo-SecureString
  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
  ```
- Anahtar dosyaları asla depoya eklenmez; `.gitignore` `*.key` ve `*.pw` dosyalarını dışlar.

**Bilinen durum:** `v0.2.0` etiketi ilk README commit'ini gösteriyor; etiketi taşımak için gereken zorla gönderime (force-push) izin verilmedi. Bu yüzden o sürümün "Source code" arşivi eksik; yükleyici ve güncelleme etkilenmiyor. Sonraki sürümlerde adım 4 önce yapıldığı için sorun olmaz.

**Kod imzalama yok:** Yükleyici bir kod imzalama sertifikasıyla imzalı değil, bu yüzden Windows SmartScreen ilk indirmede "tanınmayan uygulama" uyarısı gösterebilir ("Ek bilgi → Yine de çalıştır"). Güncelleme imzası (minisign) bundan ayrıdır ve çalışır.

## Tamamlanan
- **Altyapı:** Tauri 2 + React 19 + TS + Vite 8, özel pencere çerçevesi (decorations:false), ikonlar, CSP, dialog eklentisi (yalnız open/save izinleri)
- **Tasarım sistemi "Optik Hücre":** `src/design/tokens.css`, `base.css` (ortak `.seg/.facts/.evidence/.case-actions` burada), özel ikon seti, Sev/SigMark/Meter/Plot
- **Kabuk:** Başlık çubuğu = modül şeridi (kayan iz, ResizeObserver ile ölçülür), Ghost Line komut satırı, Ctrl+1..9, açılış sekansı, toast, modül hata sınırı (ModuleBoundary)
- **Backend toplayıcılar:** sysinfo, işlemler, GetExtendedTcp/UdpTable OWNER_MODULE
- **İmza doğrulama:** WinVerifyTrust gömülü + katalog, arka plan işçisi + önbellek
- **Yetki:** is_elevated, UAC "runas" ile yeniden başlatma
- **SQLite deposu:** events, findings, trust, baseline, conn_history, startup_items, bad_hashes, settings, secrets
- **Tehdit motoru:** taklit, imza/konum, soy, PowerShell, LOLBin, ağ, yeni port, CPU, **zararlı hash**. Tek sinyal ≤ ORTA, KRİTİK ≥ 2 bağımsız sinyal veya hash eşleşmesi.
- **Port baseline, ters DNS, GeoIP/ASN** (DB-IP Lite, butonla indirme)
- **Faz 8 backend:**
  - `intel/file.rs`: SHA-256/SHA-1/MD5, sihirli bayt ile tür tespiti (PE ayrıntısı: mimari, alt sistem, DLL, deterministik damga), Zone.Identifier (MOTW), çift uzantı, içerik-uzantı uyuşmazlığı, RTLO, WSH betikleri
  - `intel/hashdb.rs`: txt/CSV içe aktarma (her 64 hex = SHA-256), istatistik, temizleme; `ExeHashes` çalışan exe'leri arka planda hash'ler (yalnızca DB doluyken), motor `bad_hash_hits` alır
  - `intel/providers.rs`: `IntelProvider` trait + VirusTotal (yalnızca hash gönderilir, yalnızca kullanıcı tıklayınca)
  - `winapi/dpapi.rs`: API anahtarı CryptProtectData ile şifrelenip `secrets` tablosuna yazılır
  - `collectors/startup.rs`: Run/RunOnce (HKCU/HKLM/WOW64) + StartupApproved, Winlogon sapması, Başlangıç klasörleri (.lnk hedefi IShellLinkW ile çözülür), hizmetler (EnumServicesStatusExW + QueryServiceConfigW), zamanlanmış görevler (ITaskService COM, Exec eylemleri)
  - `startup_scan.rs`: 10 dk'da bir (veya istekle) tarama, imza doğrulama, değişiklik geçmişi (startup.new/changed/removed; ilk tarama temel durum), bulgular → monitor döngüsünde ana bulgularla birleşir
  - `report/mod.rs`: günlük/haftalık veri derleme; JSON + PDF (genpdf, Segoe UI sistem fontu → Türkçe karakter)
  - `commands_intel.rs`: tüm Faz 8 IPC komutları
- **Modüller (9/9):** Komuta, İşlem Avcısı, Ağ Gözcüsü, Tehdit, **Dosya** (sürükle-bırak/seç, örnek kartı, hash tablosu, köken, VirusTotal kutusu, hash DB paneli), **Açılış** (kaynak şeridi, gruplu defter, açılır ayrıntı, güvenilir say, değişiklik geçmişi), Zaman Çizelgesi, **Terminal** (kendi komut dili: durum, sistem, işlemler, öldür+onay, netstat, portlar, ip, bulgular, olaylar, hash, açılış, tara, git, yönetici, temizle; geçmiş ↑↓, Tab tamamlama), **Rapor** (uygulama içi önizleme, PDF/JSON kaydetme penceresi)

- **v0.2.0 (2026-11-16):**
  - `settings.rs` (tek JSON belge, eksik alan → varsayılan), `shell.rs` (tepsi, kapatınca gizle, bildirim + 20 sn hız sınırı), tek örnek kilidi (`--wait-pid` ile yönetici yeniden başlatma yarışı çözüldü), `--hidden` ile otomatik başlama (HKCU Run)
  - `winapi/msix.rs`: WindowsApps altındaki dosya + `GetPackagePathByFullName` ile kayıtlı paket eşleşmesi → "İmzalı (MSIX paketi)"
  - `watchers.rs`: İndirilenler/Masaüstü yoklama (3 sn, yazma bitince; `file_watch_mark` ile kapalıyken gelenler de yakalanır), sürücü takma/çıkarma (USB/harici/ISO: autorun.inf, kök .lnk, programlar), MalwareBazaar günlük güncelleme, zamanlanmış rapor (00:05, `Belgeler\Ghost Monitor Raporları`)
  - `updater.rs`: GitHub Releases, minisign doğrulama, 12 sa'de bir denetim + bildirim, kurulum yalnızca kullanıcı tıklayınca
  - Ön yüz: Ayarlar modülü (Ctrl+, / başlıktaki düğme), Dosya ekranında "Takılı sürücüler" + "Otomatik analizler", `state/explain.ts` + `Explain.tsx` ("Bu ne demek, ne yapmalıyım?")
  - Ghost Monitor kendi işlemi ve kendi açılış girdisi için bulgu üretmez; bulgular önem sırasıyla sabit sıralanır

## Başlanmamış
- Kod imzalama sertifikası (yükleyici SmartScreen uyarısı verebilir)
- abuse.ch anahtarı kullanıcı tarafından girilmedi → liste güncellemesi kapalı

## Bilinen hatalar / sınırlamalar
- Standart yetkide korumalı işlemlerin yolu/belleği okunamaz ("erişilemedi", "—") — bilinçli, sahte veri yok
- Bağlantı başına trafik (byte) yok; yalnızca toplam arabirim hızı
- Ghost Monitor açılış girdilerini değiştirmez/silmez (yalnızca izler) — bilinçli
- Açılış envanteri yetkiye bağlı: yönetici olmadan bazı sistem görevleri/hizmet komutları okunamaz; bunlar `scope='admin'` ile izlenir, standart taramada "kaldırıldı" sayılmaz
- 2026-11-16 21:08–21:09 arasındaki 35 "yeni" + 35 "kaldırıldı" olayı yetki dalgalanmasından kaynaklı yanlış alarmdı; girdiler v2 geçişiyle onarıldı, olay geçmişi olduğu gibi bırakıldı
- Komuta ekranı açık+odakta WebView ≈ tek çekirdeğin %20'si (32 çekirdekte toplamın ~%0,6'sı; canvas bileşimi); diğer modüllerde ≈ %3, gizliyken çizim yok
- USB/ISO izleme canlı bir sürücüyle denenmedi (bu oturumda takılacak sürücü yoktu); ayrıştırma ve puanlama birim testli
- MalwareBazaar dışa aktarımı artık anahtar istiyor (eski anonim adresler 410); yeni adres biçimi `mb-api.abuse.ch/v2/files/exports/<anahtar>/recent.csv` 401 ile doğrulandı, gerçek anahtarla denenmedi
- PDF görsel düzeni yalnızca testle (geçerli PDF, uzun yollar/80 satır) doğrulandı; ekranda açılıp incelenmedi (PDF render aracı yok)

## Teknik kararlar
| Konu | Karar | Gerekçe |
|---|---|---|
| Kabuk | Tauri 2 (kararlı 2.x) | WebView2, küçük kurulum |
| Frontend | React 19 + TS 5.9 + Vite 8, Zustand | |
| Görselleştirme | Canvas 2D (Ghost Core, Sonar), uPlot | Performans |
| Windows API | `windows` 0.62 | Catalog + Sip + Environment özellikleri gerekli |
| sysinfo | 0.40 — kurucular `Result` döndürüyor | |
| Veritabanı | rusqlite bundled, WAL | |
| GeoIP | DB-IP Lite mmdb, maxminddb 0.33 | Hesapsız, çevrimdışı |
| PDF | genpdf 0.2 + `C:\Windows\Fonts\segoeui*.ttf` | Türkçe glif, font gömmeye gerek yok |
| Gizli anahtar | DPAPI (kullanıcıya bağlı) + sabit entropi | Düz metin yok |
| Olay kanalı | `gm://metrics|processes|connections|findings|event|startup|update|update-progress` | |
| Güncelleme | tauri-plugin-updater, GitHub Releases `latest.json` | Ücretsiz, imzalı |

## Notlar (araç tuzakları)
- Bash heredoc/sed/python -c ile `\` içeren kod yazma → Write/Edit kullan (3 kez derleme hatası)
- `ipc/api.ts` içindeki `on(channel)` başına `gm://` ekler — kanal adını öneksiz ver
- Modül CSS'i yalnızca modül yüklenince gelir; birden fazla modülün kullandığı sınıflar `base.css`'e
- Ekran görüntüsü: scratchpad `shot.ps1 -Keys "^2" -Wait N` — **`-Wait` MİLİSANİYE** (ör. 3000). Önceki "boş modül" gözlemleri kısa beklemeden kaynaklıydı, uygulama hatası değil
- Sürüm ölçümü: `target/release/ghost-monitor.exe` doğrudan çalıştırılabilir; WebView süreçleri komut satırında `com.nexusghost.monitor` içerir

## Son değişiklikler
- 2026-11-16: v0.2.0 — 11 özellik (otomatik başlama/tepsi/bildirim, Ayarlar, MSIX, dosya izleme, USB, MalwareBazaar, zamanlanmış rapor, açıklamalar, güncelleme). Canlı doğrulanan: tek örnek, Run anahtarı, tepsiye gizle/geri aç, İndirilenler'e bırakılan çift uzantılı test dosyası → ORTA bulgu → silinince bulgu kalktı
- 2026-11-16: Faz 1–7 uygulandı, görsel kontrol, bulgu birleştirme + indeks formülü
- 2026-11-16: Faz 10 — NSIS yükleyici (yayıncı/açıklama/simge/dil seçici), sessiz kur→çalıştır→kaldır doğrulandı. Performans: canvas 24/8 fps sınırı (`viz/frameGate.ts`), Ghost Core statik katman önbelleği + toplu çizim (36% → 20% tek çekirdek). Açılış envanteri yetki farkındalıklı (`reconcile(.., elevated)`, DB v2 `scope` sütunu + onarım), boş hizmet komutu "değişti" sayılmıyor; 2 yeni test
- 2026-11-16: Faz 9 — motor senaryo testleri (kimlik avı zinciri, sahte svchost dropper, normal masaüstü sessizliği, güven, port öğrenme, CPU, birleştirme), açılış `reconcile()` saf fonksiyona ayrıldı + yaşam döngüsü testi; "yeni kayıt" sinyali artık 24 sa sürüyor, geri gelen girdi ayrı mesajla raporlanıyor; `duration()` saat birimi "sa"; derive/format testleri
- 2026-11-16: "Yeni uzak adres" olayları incelendi (139 olay, hepsi BİLGİ): tümü imzalı/bilinen uygulamalar (Microsoft, Discord, Gameforge/Metin2, Overwolf, Riot, Anthropic, OpenJS, WireGuard). İmzasızlar yalnızca rustup cargo.exe ve MSIX WhatsApp (Store paket imzası, Authenticode değil). Risk yok.
- 2026-11-16: Faz 8 tamam — Dosya İstihbaratı, hash DB, DPAPI + VirusTotal, Açılış İzleyici + değişiklik geçmişi, Ghost Terminal, Raporlama (JSON/PDF). LNK hedef çözümü ile Başlangıç klasörü yanlış pozitifi giderildi; başlık izi kayması düzeltildi; ölü kod uyarıları sıfırlandı.

## Sonraki adım
Olası işler: kod imzalama sertifikası, abuse.ch anahtarı girilince liste güncellemesini canlı doğrulama, USB izlemeyi gerçek sürücüyle deneme.


## 0.3.0 — tamamlandı (2026-11-17)
Yeni klasör `src-tauri/src/guard/` (hepsi `guard::spawn` ile tek iş parçacığında zamanlanır; fidye kalkanının kendi izleyicileri var):
- `canary.rs` fidye kalkanı: Belgeler/Masaüstü/Resimler'e gizli tuzak dosya (`!!GhostMonitor-tuzak-dosya.docx`, `zz GhostMonitor-tuzak-dosya.xlsx`) + ReadDirectoryChangesW ile toplu yeniden adlandırma (20/20 sn) ve *önceden var olan* belgelerin yeniden yazılması (40/20 sn). Alarmda en çok diske yazan 3 işlem. Kaldırırken `ghost-monitor.exe --cleanup` (NSIS hook `src-tauri/windows/hooks.nsh`) tuzakları siler.
- `defender.rs` gizli PowerShell (10 dk): Get-MpComputerStatus, dışlamalar (standart kullanıcıya "N/A" → bilinmiyor), SecurityCenter2, firewall profilleri, son hotfix.
- `browser.rs` Chromium (Chrome/Edge/Brave/Vivaldi/Opera/Opera GX) + Firefox uzantıları, izin sinyalleri, yeni uzantı olayı (`ext_seen` ayarı).
- `netconf.rs` hosts / DNS (Tcpip arayüzleri) / WinINet proxy+PAC, değişiklik olayı (`netconf_fp`).
- `eventlog.rs` EvtQuery: Security (yönetici gerekir), System, Defender/Operational. İlk çalıştırmada geçmişi oynatmaz (`evt_last:<kanal>`).
- `firewall.rs` netsh + ShellExecuteEx runas; kurallar "Ghost Monitor - …", listesi `fw_rules` ayarında; giriş doğrulaması (IP parse, var olan mutlak .exe).
- `netstats.rs` EStats ile program başına TCP baytları (yalnızca yönetici).
- `lan.rs` GetIpNetTable2 + kullanıcı tetiklemeli SendARP taraması; modem MAC değişimi bulgusu.
- `quarantine.rs` SHA-256 sayaç modlu XOR, anahtar DPAPI ile, tablo `quarantine` (migration v3).
- `remote.rs` Telegram/Discord (DPAPI, URL/anahtar doğrulama, dakikada 1, varsayılan HIGH, ayrıntı kapalı).
- `health.rs` puan + kontrol listesi.
- IPC: `commands_guard.rs`; ön yüz `src/ipc/guard.ts`, `src/modules/health/` (Ctrl+0). Ayarlar'a "Koruma" ve "Telefon bildirimleri"; Dossier'e Dondur/İnterneti engelle, Ağ'a "Bu adresi engelle", Tehdit'e "Karantinaya al"/"Şüphelileri dondur".
Güvenlik denetimi düzeltmeleri: reveal yolunu tırnaklı `raw_arg`, export_report uzantı/mutlak yol kontrolü, hash içe aktarma 2 GB sınırı.
Testler: 73 Rust (+1 ignored canlı Defender), 19 vitest. Canlı doğrulanan: DNS, ARP komşuları, Defender betiği, olay günlüğü (Security standart kullanıcıda erişim reddi beklendiği gibi), tarayıcı uzantıları.
Doğrulanmayanlar: uygulamanın 0.3.0 olarak gerçekten açılıp Sağlık ekranının görüntüsü (eski yönetici örneği PID 42236 çalıştığı için yeni sürüm başlatılamadı/kurulamadı), güvenlik duvarı kuralının UAC ile eklenmesi, Telegram/Discord gerçek gönderim, fidye alarmının gerçek tetiklenmesi.

## 0.4.0 — sesli asistan (2026-11-17, TASLAK sürüm)
Kullanıcı Resident Evil'deki hologram yapay zekâ gibi bir asistan istedi → özgün karakter: varsayılan ad **Ayla** (ayardan değişir), nokta bulutu hologram (resim yok, prosedürel), renk uygulamanın arc/phosphor/önem renkleri.
- Ön yüz `src/assistant/`: `Hologram.tsx` (canvas, ~4.5k nokta: baş/yüz kabartması, saç telleri, boyun/omuz; göz kırpma, bakış, nefes, ses seviyesine göre dudak, uyarıda renk + glitch, tarama bandı), `voice.ts` (kuyruk; Windows sesi = speechSynthesis Tolga, Azure = backend mp3 + WebAudio analyser), `mic.ts` (16 kHz WAV, sessizlikte otomatik bitiş, bas-konuş), `intents.ts` (+test, anahtarsız Türkçe komutlar), `agent.ts` (eylemler, onay akışı, Claude araç döngüsü), `Assistant.tsx` (köşe figürü + panel, uyarıları 1,5 sn toplayıp sesli okur), `store.ts`.
- Arka uç `src-tauri/src/assistant/`: `apps.rs` (Başlat menüsü/masaüstü .lnk/.url dizini + Türkçe ek toleranslı eşleştirme, yalnızca dizindeki hedef başlatılır, https dışı URL reddi), `weather.rs` (Open-Meteo, anahtarsız), `speech.rs` (Azure TTS/STT, anahtar+bölge DPAPI), `brain.rs` (Claude: raw HTTP çünkü Rust SDK yok; model `claude-opus-5-5`, effort low, `fallbacks: default` + beta `server-side-fallback-2026-07-01`, `anthropic-version: 2026-10-21`; webview yalnızca system/messages/tools verir). IPC `commands_assistant.rs`. Ayarlar `assistant_*` alanları.
- Ayarlar → "Asistan" bölümü; Ctrl+Boşluk konuş; GhostLine'da tanınmayan cümle asistana gider; Sağlık sekmesine derin bağlantı (`healthTab`).
- Güvenlik: engelle/dondur/kapat her zaman "evet" ister; kritik işlem sesle kapatılmaz; sürekli dinleme yok.
- Doğrulanan: 85 Rust testi (+canlı hava durumu), 24 vitest, tsc temiz, hologram Edge'de önizleme ekran görüntüsüyle görüldü (yüz/saç/omuz okunuyor, uyarı turuncusu çalışıyor).
- DOĞRULANMAYAN: uygulama içinde çalışma (eski yönetici örneği PID 42236 yüzünden kurulamadı), WebView2 mikrofon izni, Windows sesinin WebView2'de Tolga'yı bulması, Azure/Claude gerçek çağrı (anahtar yok).
- GitHub'da v0.4.0 **taslak** olarak duruyor (otomatik güncellemeye düşmez). Kullanıcı test edince yayımla: `gh release edit v0.4.0 --draft=false -R refonuz-art/GhostMonit-r`.
- 2026-11-17 (devam): Eski yönetici örneği UAC ile kapatıldı, 0.4.0 kuruldu ve açıldı; panel + Windows sesi (Tolga) uygulama içinde çalıştı. **İnternetsiz konuşma tanıma** eklendi: `assistant/whisper.rs` (whisper.cpp b5454 `whisper-bin-x64.zip` + `ggml-large-v3-turbo-q5_0.bin`, ikisi de SHA-256 sabitli, `%APPDATA%\com.nexusghost.monitor\whisper`). STT: Azure anahtarı varsa Azure, yoksa yerel whisper. Ayarlar'da "Konuşma tanımayı kur" (kullanıcının makinesinde kuruldu). Hata düzeltmesi: anahtar/kurulum olayı ayarları boşaltıp asistanı gizliyordu. Azure hesabı kullanıcıya ait olmalı (açılamadı); Claude sonra.
- 2026-11-17: Hologram kullanıcı isteğiyle yeniden tasarlandı (mavi hâli "tipsiz" bulundu): koyu kırmızı, çatık kaşlar, çökük yanaklar, beyaz yanan yarık göz bebekleri, gözlerden akan ışık izleri, gövdeden yükselen kıvılcımlar, ani kafa seğirmesi, renk kayması (glitch). Özgün karakter; film karakterinin kopyası değil. **HATIRLAT:** kullanıcı eve gidince Azure Speech anahtarı birlikte kurulacak.
- 2026-11-17: Kullanıcının `hologram.jpeg` örneğinden esinlenen (birebir kopya değil) **Ayla sekmesi** eklendi: `src/modules/ayla/Lair.tsx` + `lair.css`, ModuleId "ayla" (sekme listesinin sonunda, Ctrl kısayolu yok). Hologram `variant="stage"`: boynuz, gerdanlık/zincir, uzanan pençeli el, ters yıldızlı dönen mühür; köşedeki figür de boynuzlu (dock 156x208). Medya paneli gerçek: `assistant/media.rs` (WinRT GlobalSystemMediaTransportControls; `media_now`, `media_control`; Cargo windows özellikleri `Foundation`, `Media_Control`). GPU/ping/dünya haritası gösterilmiyor (veri yok, uydurulmadı). Konuşma: `useAyla.talk` (Assistant bileşeni sağlar); Ayla ekranındayken köşe figürü/panel gizli. Uygulamada denendi: yazılı konuşma + ses + ağız hareketi çalışıyor.
- 2026-11-17: **Canlı görsel modu** (Ayla sekmesi, Hologram/Görsel geçişi, tercih localStorage `gm.ayla.view`). `src/assistant/Portrait.tsx`: WebGL parça gölgelendiricisiyle kullanıcının görseli gerçek zamanlı bükülüyor — nefes, kafa eğilmesi/seğirme, göz kırpma + göz parlaması, ağız (dudak çizgisi boyunca açılır, diş/ağız içi; Windows sesinde gerçek ses seviyesi olmadığı için hece ritmi eklenir), omuz etrafında kol ve parmak hareketi, saç dalgası, neon nabzı, kıvılcımlar, uyarıda glitch. Yer işaretleri yalnızca 1672x941 görsel için tanımlı (`PRESETS`); başka görselde yalnızca ışık efektleri (UI bunu söylüyor). Görselin kenarlarındaki sahte paneller kırpılıyor (crop 395,0,940,866). Görsel `%APPDATA%\com.nexusghost.monitor\ayla-portrait.img` (komutlar `portrait_get/set/clear`, JPEG/PNG/WebP, ≤25 MB); `hologram.jpeg` .gitignore'da, depoya girmez.
- 2026-11-17: **Video görünümü** (Ayla sekmesinde Hologram/Görsel/Video; varsayılan Video). `src/assistant/AylaVideo.tsx`: bekleme döngüsü hep oynar, konuşma videosu varsa konuşurken 220 ms geçişle üstüne gelir; sessiz (ses TTS). Ses seviyesi parlaklık/kızıl ışıma sürer, uyarıda sarsıntı. `AylaFigure`: köşedeki küçük Ayla ve yan panel video varsa onu (yüze odaklı kırpım), yoksa hologramı gösterir. Komutlar `ayla_video_get/set/clear` (yuva `idle`|`talk`, set gövdesi ham bayt + `slot` başlığı, MP4 `ftyp`/WebM imzası, ≤200 MB), dosyalar `%APPDATA%\com.nexusghost.monitor\ayla-idle.vid` / `ayla-talk.vid`. Kullanıcının Kling videosu ffmpeg ile ileri+geri döngüye çevrildi, filigran kırpıldı (crop 1100x720); `kling_*.mp4` .gitignore'da. **Bekleyen:** konuşma videosu (kullanıcının Kling kredisi bitti, yarın "Edit video" ile ağız hareketli sürüm).
- 2026-11-17: **Ayarlar güncellemede korunuyor** — doğrulandı: ayarlar `ghost.db` `settings` tablosunda (JSON, `#[serde(default)]`), Telegram/Discord anahtarları `secrets` tablosunda DPAPI ile; ikisi de `%APPDATA%` altında, NSIS sessiz kurulum bunlara dokunmuyor (bugünkü 3 yeniden kurulumdan sonra bot ve `remoteNotify` yerindeydi). Ek güvenlik: `AppSettings::parse_lenient` — kayıtlı JSON'da tek bir alan okunamazsa yalnızca o alan varsayılana döner, diğerleri korunur (test `one_bad_field_does_not_reset_the_rest`). **Telegram mesajı gelmeme nedeni:** eşik `remoteMinSeverity=HIGH`, son 7 günde HIGH/CRITICAL olay yok (95.879 bilgi, 63 düşük, 5 orta). Kullanıcı isteğiyle eşik ORTA'ya çekildi (kodda alt sınır zaten ORTA; gönderimler dakikada en fazla 1).
- Doğrulanmayan: gerçek sesle tanıma (WebView2 mikrofon izni penceresi çıktı, kullanıcı "İzin ver" demeli), turbo modelin işlemcide hızı, Ctrl+Boşluk (SendKeys ile tetiklenmedi; IME çakışması olabilir, gerçek klavyede denenmeli).
- Fikir listesi: uyanma kelimesi ("Ayla") ile sürekli dinleme, çevrimdışı Türkçe tanıma (whisper.cpp), Piper ile çevrimdışı doğal ses (Türkçe kadın sesi yok, yalnızca erkek).

## 0.5.0 — müdahale, kurallar, DNS, zaman makinesi, haftalık fark (2026-11-18)
Kullanıcı öneri listesindeki ilk 5 maddeyi istedi. DB migration v4: `proc_history`, `dns_log`, `health_history`. IPC hepsi `commands_v5.rs`, ön yüz `src/ipc/v5.ts`.
1. **Müdahale paneli** — `src/modules/threat/Incident.tsx`, komut `incident_context(key)`: çalışan işlemler, güvenlik duvarı kuralı var mı, açılış kayıtları (image/komut eşleşmesi), 7 günlük bağlantılar (`conn_history`) ve DNS adları, soy zinciri (`proc_history`), karantina durumu. Adımlar: dondur → interneti kes → kalıcılık (yalnızca gösterir) → kapat+karantina (iki aşamalı onay) → izler. "Hızlı sınırla" = dondur + engelle. Eski tekil "Karantinaya al" düğmesi kaldırıldı (panelde).
2. **Kurallarım** — `engine/user_rules.rs` (ayar anahtarı `user_rules`, `Shared.user_rules`), Tehdit → Kurallarım sekmesi (`UserRules.tsx`). Koşullar VE: ad/yol/üst işlem (joker `*` `?`; yol jokersizse "içerir"), komut satırı, imza, yayıncı, uzak port listesi, internet, dinleme. `alert` sinyal ekler + bulgu en az kural seviyesine çıkar (tek sinyal sınırını aşar, kullanıcı kararı); `ignore` işlemi tüm kurallardan muaf tutar. Sinyal kimliği `user.<id>`, `explain.ts` genel açıklama verir. `user_rule_test` kaydetmeden canlı eşleşmeleri döner. YARA eklenmedi.
3. **DNS geçmişi** — `guard/dnslog.rs`. Yönetici: ETW gerçek zamanlı oturum "GhostMonitor-DNS", Microsoft-Windows-DNS-Client olay 3008 (pid ile), aynı (pid, ad) dakikada bir. Standart: `DnsGetCacheDataTable` (dnsapi, GetProcAddress) 15 sn'de bir; program, adresin canlı/son 10 dk bağlantısından tahmin. Ters sorgular (`*.arpa`) ve kendi PID'imiz atlanır. **Not:** `DnsQuery_W` + `DNS_QUERY_NO_WIRE_QUERY` bu Windows'ta 9701 döndü, adresler `to_socket_addrs` ile (önbellekten) alınıyor; tek etiketli adlar (wpad) çözülmez. `--cleanup` ETW oturumunu da durdurur. Ağ Gözcüsü → "DNS sorguları".
4. **Zaman makinesi** — `history.rs` `ProcTracker` (monitor döngüsü, anahtar (pid, başlangıç ms); imza sonradan çözülünce satır güncellenir), açılışta kapanmamış eski satırlar `ended_approx=1`. Kayıt başlangıcı ayar `proc_history_since`. İşlem Avcısı → "Zaman makinesi": kaydırıcı (1 sa/24 sa/7 gün), adım düğmeleri, tarih seçici, ±15 dk başlangıç/bitiş listesi, ayrıntı + soy. `tree.ts` artık genel tipli.
5. **Haftalık fark** — `weekly.rs`, Sağlık → "Haftalık fark": bulgular, açılış olayları, uzantılar, ilk kez çalışan programlar (kayıt başlangıcı +1 sa sonrası), yeni uzak adresler (programa göre), yeni alan adları (+ NXDOMAIN sayısı), ayar değişiklikleri, LAN cihazları, kullanıcı müdahaleleri; sağlık puanı günlük `health_history` ile karşılaştırılır. Geçmiş kısaysa bölüm notu bunu söyler.
- Testler: 90 Rust (+2 ignored), 25 vitest, tsc temiz. Canlı (dev) doğrulanan: müdahale panelinde PythonForge'un Run kaydı + soy zinciri, kural "Şimdi dene" 8 eşleşme, DNS önbellek modu gerçek kayıtlar (svchost, backgroundTaskHost, node), zaman makinesi gerçek başla/kapandı olayları, haftalık fark gerçek verilerle.
- DOĞRULANMAYAN: ETW modu (yönetici gerekiyor, bu oturumda yönetici örneği açılmadı), müdahale panelinden gerçek dondur/engelle/karantina (kullanıcının programlarına dokunmamak için denenmedi; alttaki komutlar 0.3'ten beri var).
- Dev sürümde kurulu Ghost Monitor'ün açılış kaydı "imzasız dosya" bulgusu olarak görünür (kendini hariç tutma `current_exe` ile; kurulu sürümde sorun yok).

## 0.6.0 — Ayla müdahalesi, sabah özeti, uyanma kelimesi, DNS uyarıları, USB kalkanı, telefondan müdahale (2026-11-19)
Kullanıcı öneri listesinin 1–10. maddelerini istedi (11 abuse.ch anahtarı ve 12 kod imzalama sertifikası **şimdilik yapılmayacak**).
1. **Ayla bulgu anlatır + sesli müdahale** — `agent.ts` `explainFinding` / `respondToFinding` / `talkThrough`; intent `explain` ("bu bulgu ne", "neden uyardın"), `respond` ("müdahale et", "sınırla"). Odak bulgu `useAyla.focus` (ThreatCenter seçili bulguyu yazar; yoksa en ciddi açık bulgu). Akış: dondur+interneti kes onayı → (zincirleme `ask`) kapat+karantina onayı; açılış kaydı varsa sözlü not. Claude araçları `explain_finding`, `respond_to_finding`. Müdahale panelinde "Ayla ile ilerle".
2. **Sabah özeti** — `morningSummary()`; Assistant.tsx her gün 05–12 arası ilk çalışmada (localStorage `gm.morning` + bellek). Son 12 saat orta+ olaylar, açık bulgular, puan (haftalık fark ile), hava (şehir varsa). Ayar `assistantMorning` (varsayılan açık). Intent `morning`.
3. **Uyanma kelimesi** — `mic.ts` `wakeLoop` (sürekli VAD, 0.4–8 sn parçalar, Ayla konuşurken/bas-konuş/çözümleme sırasında duraklar) + `wakeMatch` (aila/eyla/hayla varyantları, ilk 3 kelimede). Yalnız yerel whisper: yeni komut `assistant_stt_local` (Azure ayarlı olsa bile buluta ses gitmez). Ayar `assistantWake` varsayılan KAPALI, yerel tanıma kurulu değilse açılamaz. **Canlı denenmedi** (gece mikrofon/ses testi yapmadım).
4. **Azure sesi** — kod 0.4.0'dan beri hazır; yalnızca kullanıcının Azure Speech anahtarı + bölgesi gerekiyor (Ayarlar → Asistan). Hâlâ bekliyor.
5. **Şüpheli alan adı** — `guard/dnsrisk.rs`, `dnslog::write` sonrası her kayıt için. Kayıtlı etiket (registrable label; com.tr/co.uk dahil) üzerinde: rastgele görünüm (≥12 karakter, entropi ≥3.5 + az ünlü/uzun ünsüz dizisi/rakam karışımı) → Orta; + riskli TLD → Yüksek; aynı programdan 5 dk'da 25+ farklı NXDOMAIN (9003) → Yüksek; tarayıcı dışı riskli TLD → Düşük. CDN/bulut sonekleri hariç. Bulgular `watch_findings` (anahtar `domain:` / `dnsburst:`), olay `dns.suspicious`. Ayar `dnsAlerts`. Gerçek DNS geçmişindeki 116 adda 0 yanlış alarm (`real_data` ignored testi, `GM_NAMES=dosya`).
6. **Kural şablonları** — `src/modules/threat/ruleTemplates.ts` (8 şablon), Kurallarım'da "Hazır şablondan…" seçici; şablon düzenleyiciye açılır, kaydedilmez. Kalıplarda `|` = veya (`glob` → `glob_one`).
7. **Telegram'dan müdahale** — `guard/remotecmd.rs`: uyarıya inline düğmeler (Dondur / İnterneti kes, sonra Devam ettir), `getUpdates` uzun sorgu (25 sn, port açılmaz). Yalnız ayarlı sohbet; jetonlar bellekte (yeniden başlatınca eski düğmeler geçersiz). İnternet kesme yalnızca yönetici modunda (yoksa UAC ekranda beklerdi; mesaj bunu söyler). `remote.rs` `send_with(markup)`. Ayar `remoteActions`. **Canlı denenmedi** (kullanıcının Telegram'ı bağlı değil/denenmedi).
8. **Zaman makinesinde izler** — komut `proc_traces(exe, since, until)`; RunDetail'de bağlantılar (`conn_history`) ve DNS adları. Canlı doğrulandı (OneDrive: 8 adres + sharepoint adları). Not: `conn_history` her (program, adres) çiftinin oturumdaki ilk görülmesini kaydeder.
9. **USB kalkanı** — `guard/usbshield.rs`: yeni işlemin exe'si çıkarılabilir sürücüdeyse (`GetDriveTypeW`==2 veya `shared.drives`) `commands_guard::suspend_pid` ile dondurulur, bulgu `usbrun:` + olay `usb.exec` (Yüksek). Devam ettirilen exe oturum boyunca muaf (`allow`). Ayar `usbShield` varsayılan AÇIK. **Gerçek USB ile denenmedi.**
10. **Haftalık özet telefona** — `remotecmd::weekly_due` 10 dk'da bir: son geçen Pazar 20:00 dilimi, 36 saat içinde ve ayar `remote_weekly_sent` farklıysa gönderir. `remote_weekly_now` komutu + Ayarlar'da "Şimdi gönder". Ayar `remoteWeekly`.
- `commands_guard::suspend_pid` artık ortak (UI, USB kalkanı, Telegram).
- Testler: 96 Rust (+3 ignored), 27 vitest, tsc temiz. Canlı (dev): şablon seçici + düzenleyici, zaman makinesi izleri, yeni ayar satırları.
