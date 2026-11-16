# GHOST MONITOR
### Advanced Desktop Threat Intelligence & System Surveillance

Sıfırdan, profesyonel seviyede bir Windows masaüstü uygulaması geliştiriyoruz.

Ghost Monitor, bilgisayardaki çalışan işlemleri, ağ bağlantılarını, şüpheli aktiviteleri, açık portları ve sistem davranışlarını gerçek zamanlı izleyen bir güvenlik ve tehdit analiz yazılımı olacak.

Bu proje sıradan bir antivirüs değil. Kullanıcıya bilgisayarında neler olup bittiğini görsel olarak anlatan, şüpheli durumları tespit eden ve analiz eden gelişmiş bir güvenlik merkezi olacak.

## 1. EN ÖNEMLİ KONU: TASARIM

Tasarım konusunda özellikle özgün olmanı istiyorum.

Alışılmış AI tarafından üretilmiş dashboard tasarımlarını KESİNLİKLE istemiyorum.

Şunları istemiyorum:
- Her yerde bulunan standart sidebar tasarımı.
- Birbirinin aynısı kartlardan oluşan dashboard.
- Mor-mavi gradient kullanan sıradan AI arayüzü.
- Gereksiz yuvarlak köşeler.
- Her bölümde aynı tablo tasarımı.
- Sıradan Admin Panel görünümü.

### Görsel kimlik

Ghost Monitor, sanki profesyonel bir siber güvenlik operasyon merkezinin masaüstü terminaliymiş gibi görünmeli.

Tasarım referansı olarak:
- Cyberpunk atmosferi.
- Ghost in the Shell.
- Watch Dogs.
- Profesyonel SOC (Security Operations Center) sistemleri.
- Askerî istihbarat terminalleri.
- Fütüristik sistem izleme ekranları.

Ancak bunları birebir kopyalama. Kendine özgü bir tasarım dili oluştur.

### Renk paleti
- Ana arka plan: Çok koyu siyah (#080B0E).
- İkincil yüzeyler: Antrasit.
- Ana vurgu: Fosforlu yeşil.
- İkincil vurgu: Elektrik mavisi.
- Kritik uyarılar: Kırmızı.
- Normal metin: Açık gri.

### Arayüz detayları

- Animasyonlu ve canlı sistem görselleştirmeleri.
- Gerçek zamanlı hareket eden ağ bağlantı çizgileri.
- Canlı tehdit radar animasyonu.
- İşlem aktivitelerini gösteren dinamik grafikler.
- Terminal benzeri log ekranları.
- Özel tasarlanmış ikonlar.
- Akıcı geçiş animasyonları.
- İnteraktif grafikler.
- Özgün açılış animasyonu.
- Profesyonel sesli/görsel bildirim sistemi (isteğe bağlı).

Arayüzün her bölümü farklı bir deneyim sunmalı.

Örneğin Network bölümünde ağ haritası, Process bölümünde canlı işlem listesi, Threat Intelligence bölümünde tehdit analiz merkezi kullanılmalı.

## 2. ANA EKRAN – GHOST COMMAND CENTER

Uygulama açıldığında kullanıcıyı etkileyici bir operasyon merkezi karşılamalı.

Ana ekranda:

- SYSTEM STATUS
- SECURITY LEVEL
- ACTIVE PROCESSES
- ACTIVE CONNECTIONS
- SUSPICIOUS ACTIVITIES
- OPEN PORTS
- CPU / RAM / DISK kullanımı
- Son güvenlik olayları
- Gerçek zamanlı aktivite grafiği

Ekranın merkezinde bilgisayarın güvenlik durumunu temsil eden özgün bir görselleştirme bulunmalı.

Kullanıcı bilgisayarının o anki durumunu tek bakışta anlayabilmeli.

## 3. PROCESS HUNTER

Bilgisayardaki bütün çalışan işlemleri izle.

Özellikler:

- İşlem adı.
- PID.
- Dosya konumu.
- CPU kullanımı.
- RAM kullanımı.
- İşlem başlangıç zamanı.
- Dijital imza durumu.
- Yayıncı bilgisi.
- İşlemin ağ bağlantıları.
- Ebeveyn işlem bilgisi.

Şüpheli işlemleri işaretle.

Bir işleme tıklandığında ayrıntılı analiz ekranı açılmalı.

İşlemi sonlandırma özelliği bulunmalı ancak sistem işlemleri için koruma mekanizması olmalı. Kritik işlemler kullanıcı onayı olmadan sonlandırılmamalı.

## 4. NETWORK WATCH

Bilgisayarın bütün aktif ağ bağlantılarını takip et.

Gösterilecek bilgiler:

- Yerel IP.
- Uzak IP.
- Uzak port.
- Protokol.
- Bağlantı durumu.
- Bağlantıyı oluşturan işlem.
- DNS bilgileri.
- Bağlantı başlangıç zamanı.

Ek özellikler:

- Aktif bağlantı haritası.
- Gelen ve giden trafik.
- Bilinmeyen IP tespiti.
- Şüpheli bağlantı uyarıları.
- Ülke ve ASN bilgisi (harici servis veya yerel veri tabanı kullanılarak).
- Bağlantı geçmişi.

## 5. THREAT DETECTION

Şüpheli davranışları tespit eden bir analiz motoru oluştur.

Kontrol edilecek durumlar:

- Şüpheli işlem davranışları.
- Beklenmeyen ağ bağlantıları.
- Bilinmeyen çalıştırılabilir dosyalar.
- Şüpheli başlangıç programları.
- Beklenmeyen açık portlar.
- Olağan dışı CPU/RAM kullanımı.
- Şüpheli PowerShell aktiviteleri.
- Bilinen zararlı dosya hash değerleri.

Her bulguya bir risk seviyesi ata:

- INFO
- LOW
- MEDIUM
- HIGH
- CRITICAL

Yanlış pozitifleri azaltmak için tek bir bulguya dayanarak kesin zararlı kararı verme.

## 6. FILE INTELLIGENCE

Dosyaları analiz et.

- SHA256 hash hesaplama.
- Dosya boyutu.
- Oluşturulma ve değiştirilme tarihi.
- Dijital imza.
- Dosya konumu.
- Dosya türü.
- Şüpheli dosya uzantıları.

İleride VirusTotal API entegrasyonu yapılabilecek bir mimari oluştur.

API anahtarı olmadan da yerel analiz çalışabilmeli.

## 7. STARTUP MONITOR

Windows açılışında otomatik çalışan programları takip et.

- Başlangıç uygulamaları.
- Windows servisleri.
- Zamanlanmış görevler.
- Şüpheli otomatik başlatma kayıtları.

Değişiklikleri geçmişe kaydet.

## 8. EVENT TIMELINE

Bilgisayarda meydana gelen güvenlik olaylarını kronolojik olarak göster.

Örneğin:

19:20 - Yeni işlem başlatıldı.
19:21 - Bilinmeyen IP ile bağlantı kuruldu.
19:22 - Yeni başlangıç girdisi tespit edildi.
19:23 - Şüpheli işlem davranışı algılandı.

Her olayın ayrıntılarına girilebilmeli.

## 9. GHOST TERMINAL

Uygulama içerisinde özel bir terminal ekranı oluştur.

Bu ekran üzerinden:

- Güvenlik taraması başlatma.
- İşlem arama.
- IP sorgulama.
- Sistem bilgilerini görüntüleme.
- Logları filtreleme.
- Tanımlı güvenlik komutlarını çalıştırma.

Terminal gerçek sistem terminalinden ayrı olmalı. Kullanıcıya özel komut sistemi bulunmalı.

## 10. RAPORLAMA

- Günlük güvenlik raporu.
- Haftalık aktivite raporu.
- Tespit edilen şüpheli işlemler.
- Ağ bağlantısı raporu.
- PDF ve JSON dışa aktarma.
- Olay geçmişi.

## 11. TEKNİK MİMARİ

Öncelikle Windows 10 ve Windows 11 desteklenecek.

Teknoloji seçimini araştırarak yap.

Önerilen yapı:

- Desktop: Tauri 2
- Frontend: React + TypeScript
- UI: Özgün CSS tasarım sistemi
- Backend: Rust
- Grafikler: Uygun performanslı grafik kütüphanesi
- Veri tabanı: SQLite

Windows sistem bilgilerine ve ağ bağlantılarına erişmek için uygun native Windows API'lerini kullan.

Uygulama mümkün olduğunca az RAM ve CPU tüketmeli.

Yönetici izni gerektiren özellikleri gerektiğinde kullanıcıdan izin alarak çalıştır.

Güvenlik uygulaması olduğu için kendi güvenliğini de önemse. Hassas verileri koru, API anahtarlarını düz metin olarak saklama.

## 12. GELİŞTİRME YAKLAŞIMI

Projeyi tek seferde yüzeysel olarak oluşturma.

Önce mimariyi planla.

Ardından:

1. Proje klasör yapısını oluştur.
2. Tasarım sistemini oluştur.
3. Ana arayüzü geliştir.
4. Gerçek Windows sistem verilerini bağla.
5. Process Hunter modülünü geliştir.
6. Network Watch modülünü geliştir.
7. Threat Detection motorunu oluştur.
8. Diğer modülleri sırayla tamamla.
9. Testleri gerçekleştir.
10. Windows için çalıştırılabilir kurulum paketi oluştur.

Sahte verileri gerçek sistem verisi gibi gösterme. Henüz geliştirilmeyen özellikleri açıkça belirt.

## 13. PROJE DURUM DOSYASI

Proje ana dizininde `projesondurum.md` oluştur.

Bu dosyada sürekli olarak şunları güncelle:

- Tamamlanan özellikler.
- Geliştirilmekte olan özellikler.
- Henüz başlanmamış özellikler.
- Bilinen hatalar.
- Teknik kararlar.
- Son yapılan değişiklikler.
- Bir sonraki geliştirme adımları.

Böylece yeni oturum açıldığında projeye kaldığın yerden devam edebilmelisin.

## SON TALİMAT

Bu projede tasarım kalitesi en az teknik kalite kadar önemli.

Ortaya çıkacak uygulama bir öğrenci projesi veya sıradan bir sistem takip programı gibi görünmemeli.

Profesyonel bir siber güvenlik şirketinin geliştirdiği ticari masaüstü yazılımı hissi vermeli.

Özellikle ana ekran, menü sistemi, geçiş animasyonları, veri görselleştirmeleri ve modüllerin kendine özgü tasarımı konusunda yaratıcı ol.

İlk olarak bana mimari planı, teknoloji seçimlerini ve tasarım konseptini sun. Onayımı almadan bütün projeyi kodlamaya başlama.

Bütün arayüz dili Türkçe olsun. Kod, değişken ve teknik isimlendirmelerde İngilizce kullanabilirsin.