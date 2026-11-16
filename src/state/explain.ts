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
};

export function explainSignals(signals: Signal[]): Explanation[] {
  const seen = new Set<string>();
  const out: Explanation[] = [];
  for (const s of [...signals].sort((a, b) => b.weight - a.weight)) {
    const e = RULES[s.rule];
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
