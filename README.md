# Ghost Monitor

Windows 10/11 için yerel çalışan güvenlik ve tehdit istihbaratı izleyicisi. İşlemleri, ağ bağlantılarını, açılış girdilerini, indirilen dosyaları ve takılan sürücüleri izler. Şüpheli davranışları açıklanabilir sinyallerle ve sade Türkçe açıklamalarla raporlar.

**İndir:** [Son sürüm](https://github.com/refonuz-art/GhostMonit-r/releases/latest) — `GhostMonitor_<sürüm>_x64-setup.exe`. Yönetici izni gerekmez; yalnızca kullanıcı hesabına kurulur. Kurulduktan sonra kendini güncelleyebilir.

## Neler yapar

- **Komuta:** Canlı sistem görünümü ve güvenlik indeksi
- **İşlem Avcısı:** İşlem ağacı, dijital imza ve konum
- **Ağ Gözcüsü:** Bağlantılar, ters DNS, ülke ve ASN
- **Tehdit:** Ağırlıklı kural motoru. Tek sinyal en fazla "orta" olur; "kritik" için iki bağımsız kanıt ya da bilinen zararlı hash gerekir.
- **Dosya:** SHA-256 ile gerçek dosya türü, imza ve internetten indirilme kökeni. Ayrıca çift uzantı ve RTLO gibi gizleme hilelerini yakalar.
- **Açılış:** Run anahtarları, Winlogon, başlangıç klasörü, zamanlanmış görevler ve hizmetler, değişiklik geçmişiyle birlikte
- **Arka planda:** Uygulama Windows ile birlikte tepside başlar ve bildirim gönderir.
  - İndirilenler ve Masaüstü'ne gelen dosyaları otomatik analiz eder.
  - USB, harici disk ve ISO bağlandığında denetler.
  - MalwareBazaar listesini isteğe bağlı olarak günceller.
  - Zamanlanmış rapor üretir.
- **Terminal:** Kendi komut dili
- **Rapor:** PDF ve JSON

## Gizlilik

Tüm analiz yerel olarak yapılır. Ağa yalnızca iki durumda istek gider:

1. İsteğe bağlı VirusTotal sorgusu: yalnızca hash gönderilir, siz tıklayınca.
2. MalwareBazaar listesi: yalnızca anahtar gönderilir, siz açarsanız.

API anahtarları Windows DPAPI ile şifrelenir.

## Geliştirme

Gerekenler: Rust (MSVC toolchain), Node 20+, pnpm, WebView2.

```
pnpm install
pnpm app:dev        # geliştirme
pnpm test           # arayüz testleri
cd src-tauri && cargo test
pnpm app:build      # NSIS yükleyici
```

Sürüm yayımlamak için önce `tauri.conf.json`, `Cargo.toml` ve `package.json` içindeki sürüm numarasını artırın. Ardından şunu çalıştırın:

```
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -NotesFile docs\releases\<sürüm>.md
```

Güncelleme imza anahtarı depoda değildir; yalnızca yayımlayan makinede `%USERPROFILE%\.tauri` içinde durur.

Teknoloji: Tauri 2, React 19, TypeScript, Rust, SQLite.
