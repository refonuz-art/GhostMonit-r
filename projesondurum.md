# GHOST MONITOR — Proje Son Durum

> Yeni oturumda önce bu dosyayı oku. Gereksinimler: `prompt.md`. Kullanıcı tüm onayları verdi; fazları sırayla ilerlet.

## Durum özeti
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
