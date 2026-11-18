// Plain-language explanation for every engine rule: why it matters and what to do.
// Written for someone who is not a security professional.
import type { Finding, Signal } from "../ipc/types";

export interface Explanation {
  rule: string;
  why: string;
  todo: string;
}

const RULES: Record<string, Omit<Explanation, "rule">> = {
  "masquerade.path": {
    why: "Bu dosya bir Windows sistem programının adını taşıyor ama Windows'un onu koyduğu klasörde değil. Zararlı yazılımlar fark edilmemek için bu adları ödünç alır.",
    todo: "Dosyanın konumuna bakın. Bir program bunu kurmadıysa ve imzası yoksa işlemi sonlandırıp dosyayı bir antivirüsle taratın.",
  },
  "masquerade.typo": {
    why: "Adı bir sistem işlemine harf harf çok benziyor (ör. scvhost, lsas). Gerçek Windows dosyalarında bu tür yazım hataları olmaz.",
    todo: "Bu işlemi tanımıyorsanız sonlandırın ve dosyayı taratın.",
  },
  "sig.invalid": {
    why: "Dosyanın dijital imzası var ama doğrulanamıyor. İmzalandıktan sonra değiştirilmiş ya da güvenilmeyen bir sertifikayla imzalanmış olabilir.",
    todo: "Programı resmi kaynağından yeniden indirin. Değiştirilmiş bir kopya kullanıyorsanız silin.",
  },
  "sig.unsigned": {
    why: "Dosyanın yayıncısını kanıtlayan bir dijital imzası yok. Küçük ve açık kaynak programlarda yaygındır; tek başına tehlike işareti değildir.",
    todo: "Programı siz kurduysanız ve kaynağını biliyorsanız 'Güvenilir say' diyebilirsiniz.",
  },
  "loc.temp": {
    why: "İmzasız bir program geçici dosyalar klasöründen çalışıyor. Kurulum programları dışında bu klasörden program çalışması alışılmadık bir durumdur ve zararlıların sık kullandığı bir yöntemdir.",
    todo: "Az önce bir şey kurmadıysanız işlemi sonlandırın ve dosyayı taratın.",
  },
  "loc.userwritable": {
    why: "İmzasız bir program, yönetici izni olmadan yazılabilen bir klasörden (ör. AppData) çalışıyor. Birçok meşru uygulama da böyle çalışır.",
    todo: "Programı tanıyorsanız sorun yok. Tanımıyorsanız konumunu açıp ne olduğuna bakın.",
  },
  "lineage.docspawn": {
    why: "Word, Excel veya bir PDF okuyucu bir komut yorumlayıcısı (PowerShell, cmd, wscript) başlattı. Bu, zararlı makrolu belgelerin en tipik davranışıdır.",
    todo: "Az önce açtığınız belgeyi kapatın ve silin. Başlatılan işlemi sonlandırın, ardından tam tarama yapın.",
  },
  "ps.cmdline": {
    why: "PowerShell gizlenmiş veya internetten kod indiren bir komutla çalışıyor. Yöneticiler de bunu kullanır ama zararlılar da komutlarını bu şekilde saklar.",
    todo: "Komut satırını okuyun. Bunu siz veya tanıdığınız bir araç başlatmadıysa işlemi sonlandırın.",
  },
  "lolbin.remote": {
    why: "Windows'un kendi aracı (mshta, rundll32, certutil vb.) internetten içerik çalıştırmak için kullanılıyor. Saldırganlar güvenilir görünmek için yerleşik araçları kullanır.",
    todo: "Komut satırındaki adresi kontrol edin. Tanımıyorsanız işlemi sonlandırın.",
  },
  "net.unsigned_public": {
    why: "İmzasız bir program internetteki bir sunucuyla konuşuyor. Oyun başlatıcıları ve küçük araçlar için normaldir.",
    todo: "Hangi programın kime bağlandığını Ağ Gözcüsü'nde görün. Tanıdığınız bir programsa güvenilir sayın.",
  },
  "net.badport": {
    why: "Bağlantı, arka kapı ve uzaktan kontrol yazılımlarının sık kullandığı bir porta gidiyor (ör. 4444, 1337).",
    todo: "İşlemi sonlandırın ve dosyasını taratın. Bilinçli kullandığınız bir araç değilse ciddiye alın.",
  },
  "port.new": {
    why: "Bir program bilgisayarınızda dışarıdan bağlantı kabul eden yeni bir kapı açtı. Paylaşım ve oyun sunucuları bunu yapar; arka kapılar da.",
    todo: "Programı tanıyorsanız güvenilir sayın. Tanımıyorsanız işlemi sonlandırın.",
  },
  "res.cpu": {
    why: "Program uzun süredir işlemciyi yoğun kullanıyor. Gizli kripto para madenciliği böyle görünür; derleme, oyun veya video işleme de öyle.",
    todo: "Programı siz çalıştırmıyorsanız ne olduğuna bakın.",
  },
  "hash.known_bad": {
    why: "Bu dosyanın parmak izi (SHA-256), bilinen zararlı yazılım listesinde birebir eşleşti. Bu, en güçlü kanıttır.",
    todo: "Dosyayı çalıştırmayın, çalışıyorsa sonlandırın ve silin. Ardından tam antivirüs taraması yapın ve önemli şifrelerinizi değiştirin.",
  },
  "file.rtlo": {
    why: "Dosya adında, yazının yönünü ters çeviren gizli bir karakter var. 'faturaexe.pdf' gibi görünen bir dosya aslında '.exe' olabilir.",
    todo: "Bu dosyayı açmayın, silin.",
  },
  "file.double_ext": {
    why: "Dosya 'belge.pdf.exe' gibi çift uzantılı. Windows bilinen uzantıları gizlediği için bu dosya bir belge gibi görünür ama aslında programdır.",
    todo: "Açmayın. Göndereni tanıyorsanız bile önce teyit edin, sonra silin.",
  },
  "file.ext_mismatch": {
    why: "Dosyanın uzantısı belge veya resim diyor ama içi çalıştırılabilir bir program. Bu bilinçli bir gizleme girişimidir.",
    todo: "Açmayın ve silin.",
  },
  "file.motw": {
    why: "Dosya internetten indirilmiş. Bu tek başına sorun değildir; nereden geldiğini görmeniz içindir.",
    todo: "İndirme adresini kontrol edin. Resmi siteden geldiyse sorun yok.",
  },
  "file.script": {
    why: "Bu bir Windows betik dosyası (.vbs, .js, .hta…). Günlük kullanımda nadirdir ama e-posta eklerinde zararlı olarak çok sık görülür.",
    todo: "Ne işe yaradığını bilmiyorsanız çalıştırmayın.",
  },
  "startup.new": {
    why: "Windows açılışında otomatik çalışacak yeni bir kayıt eklendi. Yeni kurduğunuz programlar bunu yapar; kalıcı olmak isteyen zararlılar da.",
    todo: "Açılış ekranında kaydı bulun. Siz bir şey kurmadıysanız devre dışı bırakın ve hedef dosyayı taratın.",
  },
  "startup.missing": {
    why: "Otomatik başlatma kaydı artık var olmayan bir dosyayı gösteriyor. Genellikle kaldırılmış bir programdan kalan artıktır.",
    todo: "Genellikle zararsızdır. Kaydı Windows Görev Yöneticisi'nin Başlangıç sekmesinden kapatabilirsiniz.",
  },
  "startup.winlogon": {
    why: "Windows oturum açılışını yöneten Winlogon ayarları varsayılandan farklı. Bu ayarı çok az meşru program değiştirir.",
    todo: "Değeri ve gösterdiği programı kontrol edin. Tanımıyorsanız bir uzmana danışın.",
  },
  "usb.autorun": {
    why: "Sürücüde, takıldığında bir programı otomatik çalıştırmaya çalışan autorun.inf dosyası var. Güncel Windows bunu USB'lerde çalıştırmaz ama eski bir solucan yöntemidir.",
    todo: "Sürücüdeki programları çalıştırmayın. Sürücüyü bir antivirüsle taratın.",
  },
  "usb.lnk_shell": {
    why: "Sürücünün kökündeki bir kısayol, klasör gibi görünse de komut yorumlayıcısı çalıştırıyor. USB solucanları dosyalarınızı gizleyip yerine böyle kısayollar koyar.",
    todo: "Kısayola tıklamayın. Sürücüyü taratın; dosyalarınız gizli bir klasörde duruyor olabilir.",
  },
  "usb.lnk_root": {
    why: "Sürücünün kökünde bir kısayol var. Tek başına zararsız olabilir ama USB solucanlarının tipik izidir.",
    todo: "Kısayolun hedefine bakın. Tanımıyorsanız tıklamayın.",
  },
  "ransom.canary": {
    why: "Ghost Monitor'ün belge klasörlerine koyduğu tuzak dosyalardan biri değiştirildi, taşındı veya silindi. Bu dosyaları hiçbir normal program açmaz; dokunulması çoğu zaman bir programın klasördeki her dosyayı şifrelemeye başladığı anlamına gelir.",
    todo: "Hemen Tehdit ekranındaki şüpheli işlemleri dondurun veya sonlandırın, ağ kablosunu çekin ya da Wi-Fi'yi kapatın. Bilgisayarı kapatmayın; önemli dosyalarınızın yedeğini kontrol edin.",
  },
  "ransom.rename_burst": {
    why: "Saniyeler içinde çok sayıda belge, bilinmeyen bir uzantıyla yeniden adlandırıldı (ör. .docx → .docx.locked). Fidye yazılımları şifreledikleri dosyaları tam böyle yeniden adlandırır.",
    todo: "Diske en çok yazan işlemi hemen dondurun. Toplu yeniden adlandırma yapan bir programı kendiniz çalıştırmadıysanız ağ bağlantısını kesin.",
  },
  "ransom.write_burst": {
    why: "Belge klasörlerinizde saniyeler içinde çok sayıda dosya yeniden yazıldı. Yedekleme ve senkronizasyon programları da bunu yapabilir, ama fidye yazılımı belirtisi de olabilir.",
    todo: "Şu anda dosyalarınızı işleyen bir program (yedekleme, fotoğraf düzenleme, senkronizasyon) yoksa listedeki işlemi dondurun.",
  },
  "ransom.suspects": {
    why: "Alarm anında diske en çok yazan programlar. Bu liste bir kanıt değil, nereden başlayacağınızı gösteren bir ipucudur.",
    todo: "Tanımadığınız bir program varsa önce dondurun; emin olunca sonlandırın.",
  },
  "ext.all_sites": {
    why: "Bu uzantı ziyaret ettiğiniz her sitedeki içeriği okuyup değiştirebilir: şifre formları, banka sayfaları, e-postalar dahil.",
    todo: "Uzantıyı gerçekten kullanıyor ve tanıyorsanız sorun yok. Tanımıyorsanız tarayıcının uzantılar sayfasından kaldırın.",
  },
  "ext.cookies": {
    why: "Uzantı tarayıcı çerezlerini okuyabilir. Çerezler oturum bilgisi taşır; çalınırsa şifreniz olmadan hesabınıza girilebilir.",
    todo: "Bu izne ihtiyaç duyan bir uzantı kullandığınızdan emin değilseniz kaldırın.",
  },
  "ext.debugger": {
    why: "Uzantı sayfalara hata ayıklayıcı olarak bağlanabilir; bu, sayfadaki her şeyi okuyup değiştirmek demektir. Geliştirici araçları dışında nadiren gerekir.",
    todo: "Geliştirici değilseniz bu uzantıyı kaldırın.",
  },
  "ext.native": {
    why: "Uzantı bilgisayarınızdaki bir programla konuşabilir. Parola yöneticileri gibi meşru araçlar bunu kullanır, ama tarayıcı dışına çıkmanın bir yoludur.",
    todo: "Eşlik eden programı tanıyorsanız sorun yok; tanımıyorsanız kaldırın.",
  },
  "ext.proxy": {
    why: "Uzantı tarayıcınızın tüm trafiğini başka bir sunucu üzerinden geçirebilir. VPN uzantıları bunu yapar; zararlı uzantılar da trafiği dinlemek için kullanır.",
    todo: "Bilinçli kurduğunuz bir VPN değilse kaldırın.",
  },
  "ext.webrequest": {
    why: "Uzantı tarayıcının yaptığı ağ isteklerini yakalayıp değiştirebilir. Reklam engelleyiciler bunu kullanır.",
    todo: "Tanıdığınız bir reklam engelleyici değilse uzantıyı gözden geçirin.",
  },
  "ext.management": {
    why: "Uzantı diğer uzantıları açıp kapatabilir veya kaldırabilir.",
    todo: "Bu izne nadiren ihtiyaç olur; tanımıyorsanız kaldırın.",
  },
  "ext.clipboard": {
    why: "Uzantı panoya kopyaladığınız metni okuyabilir (kopyaladığınız şifreler ve kripto cüzdan adresleri dahil).",
    todo: "Bu izni gerektiren bir özellik kullanmıyorsanız uzantıyı kaldırın.",
  },
  "ext.history": {
    why: "Uzantı tarama geçmişinizin tamamını okuyabilir.",
    todo: "Geçmiş yöneticisi gibi bir uzantı değilse gözden geçirin.",
  },
  "ext.unpacked": {
    why: "Uzantı mağazadan değil, geliştirici modunda bir klasörden yüklenmiş. Zararlı programlar tarayıcıya bu yolla uzantı ekler.",
    todo: "Kendiniz yüklemediyseniz kaldırın ve tarayıcıda geliştirici modunu kapatın.",
  },
  "ext.sideloaded": {
    why: "Uzantı resmi mağaza dışından yüklenmiş. Şirket politikasıyla gelen uzantılar dışında bu alışılmadık bir durumdur.",
    todo: "Kaynağını bilmiyorsanız kaldırın.",
  },
  "ext.new": {
    why: "Bu uzantı son taramadan bu yana eklendi.",
    todo: "Siz eklemediyseniz kaldırın; bir programın sizden habersiz uzantı kurduğu anlamına gelebilir.",
  },
  "net.hosts_redirect": {
    why: "Windows'un hosts dosyası önemli bir siteyi (banka, e-posta, Microsoft vb.) farklı bir IP adresine yönlendiriyor. Adres çubuğunda doğru siteyi görseniz bile sahte bir sunucuya bağlanırsınız.",
    todo: "Bu satırı siz eklemediyseniz hosts dosyasından silin ve bilgisayarı taratın. O sitelere bu arada giriş yapmayın.",
  },
  "net.hosts_block_av": {
    why: "hosts dosyası antivirüs veya Windows güncelleme sitelerini engelliyor. Zararlı yazılımlar güncellenmeyi ve tespit edilmeyi önlemek için bunu yapar.",
    todo: "Bu satırları hosts dosyasından silin ve tam tarama yapın.",
  },
  "net.dns_unknown": {
    why: "Ağ bağdaştırıcınız tanınmayan bir DNS sunucusu kullanıyor. DNS, site adlarını adreslere çevirir; kötü niyetli bir DNS sizi sahte sitelere yönlendirebilir.",
    todo: "Bu adresi siz veya internet sağlayıcınız ayarladıysa sorun yok. Değilse bağdaştırıcı ayarlarından DNS'i otomatiğe alın.",
  },
  "net.proxy_pac": {
    why: "Tarayıcı trafiğinin nereye gideceğine bir otomatik yapılandırma betiği (PAC) karar veriyor. Şirket ağlarında normaldir; evde ise reklam yazılımlarının trafiği yönlendirme yöntemidir.",
    todo: "Şirket bilgisayarı değilse Ayarlar → Ağ → Proxy bölümünden betiği kaldırın.",
  },
  "net.proxy": {
    why: "İnternet trafiğiniz bir proxy sunucusu üzerinden geçiyor. Proxy, gidip gelen her şeyi görebilir.",
    todo: "Bu proxy'yi siz ayarlamadıysanız Ayarlar → Ağ → Proxy bölümünden kapatın.",
  },
  "def.rtp_off": {
    why: "Windows Defender'ın gerçek zamanlı koruması kapalı ve başka bir antivirüs de çalışmıyor. Zararlı dosyalar açıldıkları anda engellenmez.",
    todo: "Windows Güvenliği → Virüs ve tehdit koruması'ndan gerçek zamanlı korumayı açın. Kendiliğinden kapanıyorsa bilgisayarı taratın.",
  },
  "def.no_av": {
    why: "Windows'a kayıtlı hiçbir antivirüs etkin değil.",
    todo: "Windows Güvenliği'ni açın veya kullandığınız antivirüsü etkinleştirin.",
  },
  "def.tamper_off": {
    why: "Kurcalama koruması kapalı; programlar Defender ayarlarını sizden habersiz değiştirebilir.",
    todo: "Windows Güvenliği → Virüs ve tehdit koruması ayarları → Kurcalama koruması'nı açın.",
  },
  "def.sig_old": {
    why: "Defender'ın virüs tanımları bir haftadan eski; yeni tehditleri tanımayabilir.",
    todo: "Windows Güvenliği → Koruma güncelleştirmeleri'nden güncelleyin.",
  },
  "def.exclusion_broad": {
    why: "Defender'a bütün bir sürücüyü, kullanıcı klasörünü veya tüm .exe dosyalarını taramamasını söyleyen bir dışlama eklenmiş. Zararlı yazılımlar kendilerini gizlemek için bunu yapar.",
    todo: "Bu dışlamayı siz eklemediyseniz Windows Güvenliği → Dışlamalar'dan hemen kaldırın ve tam tarama yapın.",
  },
  "def.exclusion_new": {
    why: "Defender'a son kontrolden bu yana yeni bir dışlama eklendi.",
    todo: "Siz eklemediyseniz kaldırın.",
  },
  "fw.off": {
    why: "Windows Güvenlik Duvarı en az bir ağ profilinde kapalı; dışarıdan gelen bağlantılar süzülmüyor.",
    todo: "Windows Güvenliği → Güvenlik duvarı ve ağ koruması'ndan açın.",
  },
  "evt.user_created": {
    why: "Bilgisayarda yeni bir kullanıcı hesabı oluşturuldu. Saldırganlar kalıcı erişim için gizli hesaplar açar.",
    todo: "Bu hesabı siz açmadıysanız Bilgisayar Yönetimi → Yerel Kullanıcılar'dan devre dışı bırakın.",
  },
  "evt.admin_added": {
    why: "Bir hesap Yöneticiler grubuna eklendi; artık bilgisayar üzerinde tam yetkisi var.",
    todo: "Bunu siz yapmadıysanız hesabı gruptan çıkarın ve şifrelerinizi değiştirin.",
  },
  "evt.log_cleared": {
    why: "Windows olay günlüğü temizlendi. Saldırganlar izlerini silmek için bunu yapar; normal kullanımda nadiren olur.",
    todo: "Günlüğü siz temizlemediyseniz bilgisayarı taratın ve diğer bulgulara dikkatle bakın.",
  },
  "evt.bruteforce": {
    why: "Kısa sürede çok sayıda başarısız oturum açma denemesi oldu. Biri şifrenizi tahmin etmeye çalışıyor olabilir (özellikle Uzak Masaüstü açıksa).",
    todo: "Kullanmıyorsanız Uzak Masaüstü'nü kapatın ve güçlü bir şifre kullanın. Kaynak IP'yi Sağlık → Engellenenler'den engelleyebilirsiniz.",
  },
  "lan.gateway_mac": {
    why: "Modeminizin adresi farklı bir cihaza geçti. Modemi değiştirdiyseniz normaldir; değiştirmediyseniz ağdaki biri trafiğinizi kendi üzerinden geçiriyor olabilir (ARP zehirleme).",
    todo: "Modemi değiştirmediyseniz ağdaki tanımadığınız cihazları kontrol edin ve şifre girmeden önce bağlantınızın güvenli olduğundan emin olun.",
  },
};

/** Signals from the user's own rules ("user.<id>"). */
const USER_RULE: Omit<Explanation, "rule"> = {
  why: "Bu uyarıyı sizin yazdığınız bir kural üretti; seviyesini de siz seçtiniz. Ghost Monitor'ün kendi kuralları ayrıca değerlendirilir.",
  todo: "Kuralı yazarken bu durumda ne yapmayı düşündüyseniz onu uygulayın. Kural fazla geniş yakalıyorsa Tehdit → Kurallarım'dan daraltın.",
};

export function explainSignals(signals: Signal[]): Explanation[] {
  const seen = new Set<string>();
  const out: Explanation[] = [];
  for (const s of [...signals].sort((a, b) => b.weight - a.weight)) {
    const e = s.rule.startsWith("user.") ? USER_RULE : RULES[s.rule];
    if (!e || seen.has(s.rule)) continue;
    seen.add(s.rule);
    out.push({ rule: s.rule, ...e });
  }
  return out;
}

/** One sentence summarising what the user should do, based on the overall verdict. */
export function verdictAdvice(f: Pick<Finding, "severity">): string {
  switch (f.severity) {
    case "CRITICAL":
      return "Birden fazla güçlü kanıt aynı yeri gösteriyor. Hemen harekete geçin: işlemi durdurun, dosyayı silin ve tam tarama yapın.";
    case "HIGH":
      return "Ciddi şüphe var. Aşağıdaki adımları uygulayın; emin değilseniz işlemi durdurmak güvenli taraftır.";
    case "MEDIUM":
      return "Dikkat edilmesi gereken bir durum. Programı tanıyorsanız güvenilir sayabilirsiniz; tanımıyorsanız inceleyin.";
    case "LOW":
      return "Zayıf bir sinyal. Çoğu zaman normal bir programdır; sadece bilginiz olsun.";
    default:
      return "Bilgi amaçlı.";
  }
}

export const KNOWN_RULES = Object.keys(RULES);
