//! Security reports: aggregated from the local database, exported as JSON or PDF.

use std::collections::HashMap;

use serde::Serialize;

use crate::model::{Finding, HostInfo, SecurityEvent, Severity};
use crate::state::Shared;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRow {
    pub remote: String,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub count: i64,
    pub processes: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRow {
    pub port: u16,
    pub protocol: String,
    pub bind: String,
    pub process: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DayRow {
    pub day: String,
    pub events: i64,
    pub threats: i64,
    pub new_remotes: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportData {
    pub kind: String,
    pub title: String,
    pub generated_at: i64,
    pub since: i64,
    pub until: i64,
    pub host: HostInfo,
    pub top_severity: Option<Severity>,
    pub total_events: i64,
    pub by_severity: Vec<(String, i64)>,
    pub by_kind: Vec<(String, i64)>,
    pub findings: Vec<Finding>,
    pub top_processes: Vec<(String, i64)>,
    pub top_remotes: Vec<RemoteRow>,
    pub new_remote_hosts: i64,
    pub startup_events: Vec<SecurityEvent>,
    pub notable_events: Vec<SecurityEvent>,
    pub open_ports: Vec<PortRow>,
    pub days: Vec<DayRow>,
}

pub fn build(shared: &Shared, kind: &str, since: i64, until: i64) -> Result<ReportData, String> {
    let st = shared.store.lock();
    let c = &st.conn;
    let e = |x: rusqlite::Error| x.to_string();

    let count_by = |col: &str| -> Result<Vec<(String, i64)>, String> {
        let mut stmt = c
            .prepare(&format!("SELECT {col}, COUNT(*) FROM events WHERE ts BETWEEN ?1 AND ?2 GROUP BY {col} ORDER BY 2 DESC"))
            .map_err(e)?;
        let rows = stmt.query_map([since, until], |r| Ok((r.get(0)?, r.get(1)?))).map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)
    };
    let by_severity = count_by("severity")?;
    let by_kind = count_by("kind")?;
    let total_events = by_kind.iter().map(|(_, n)| n).sum();

    let mut findings: Vec<Finding> = st
        .finding_history(5000)
        .map_err(e)?
        .into_iter()
        .filter(|f| f.last_seen >= since && f.first_seen <= until && f.status != "dismissed")
        .collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.score.cmp(&a.score)));
    let top_severity = findings.iter().map(|f| f.severity).filter(|s| *s > Severity::Info).max();

    let top_processes = {
        let mut stmt = c
            .prepare("SELECT subject, COUNT(*) FROM events WHERE kind='process.start' AND ts BETWEEN ?1 AND ?2 GROUP BY subject ORDER BY 2 DESC LIMIT 15")
            .map_err(e)?;
        let rows = stmt.query_map([since, until], |r| Ok((r.get::<_, Option<String>>(0)?.unwrap_or_default(), r.get(1)?))).map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)?
    };

    let top_remotes = {
        let mut stmt = c
            .prepare(
                "SELECT remote, MAX(hostname), MAX(country), MAX(asn), COUNT(*), GROUP_CONCAT(DISTINCT process)
                 FROM conn_history WHERE ts BETWEEN ?1 AND ?2 GROUP BY remote ORDER BY 5 DESC LIMIT 20",
            )
            .map_err(e)?;
        let rows = stmt
            .query_map([since, until], |r| {
                Ok(RemoteRow {
                    remote: r.get(0)?,
                    hostname: r.get(1)?,
                    country: r.get(2)?,
                    asn: r.get(3)?,
                    count: r.get(4)?,
                    processes: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                })
            })
            .map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)?
    };
    let new_remote_hosts: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM events WHERE kind='network.new_remote' AND ts BETWEEN ?1 AND ?2",
            [since, until],
            |r| r.get(0),
        )
        .map_err(e)?;

    let startup_kinds = vec!["startup.new".to_string(), "startup.changed".into(), "startup.removed".into()];
    let startup_events = st.events(Some(since), Some(until), &startup_kinds, None, None, 200).map_err(e)?;
    let notable_events = st.events(Some(since), Some(until), &[], Some(Severity::Low), None, 300).map_err(e)?;

    let days = {
        let mut stmt = c
            .prepare(
                "SELECT strftime('%Y-%m-%d', ts/1000, 'unixepoch', 'localtime') d, COUNT(*),
                        SUM(kind='threat.finding'), SUM(kind='network.new_remote')
                 FROM events WHERE ts BETWEEN ?1 AND ?2 GROUP BY d ORDER BY d",
            )
            .map_err(e)?;
        let rows = stmt
            .query_map([since, until], |r| {
                Ok(DayRow { day: r.get(0)?, events: r.get(1)?, threats: r.get(2)?, new_remotes: r.get(3)? })
            })
            .map_err(e)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(e)?
    };
    drop(st);

    let names: HashMap<u32, String> = shared.processes.read().iter().map(|p| (p.pid, p.name.clone())).collect();
    let mut open_ports: Vec<PortRow> = shared
        .connections
        .read()
        .iter()
        .filter(|c| c.state == "LISTEN" && c.scope != crate::model::AddrScope::Loopback)
        .map(|c| PortRow {
            port: c.local_port,
            protocol: if c.ipv6 { "TCPv6".into() } else { "TCP".into() },
            bind: c.local_addr.clone(),
            process: names.get(&c.pid).cloned().unwrap_or_else(|| format!("PID {}", c.pid)),
        })
        .collect();
    open_ports.sort_by_key(|p| (p.port, p.protocol.clone()));
    open_ports.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol);

    Ok(ReportData {
        title: if kind == "weekly" { "Haftalık aktivite raporu".into() } else { "Günlük güvenlik raporu".into() },
        kind: kind.into(),
        generated_at: chrono::Utc::now().timestamp_millis(),
        since,
        until,
        host: shared.host.read().clone(),
        top_severity,
        total_events,
        by_severity,
        by_kind,
        findings,
        top_processes,
        top_remotes,
        new_remote_hosts,
        startup_events,
        notable_events,
        open_ports,
        days,
    })
}

pub fn sev_tr(s: Severity) -> &'static str {
    match s {
        Severity::Info => "bilgi",
        Severity::Low => "düşük",
        Severity::Medium => "orta",
        Severity::High => "yüksek",
        Severity::Critical => "kritik",
    }
}

fn local(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M").to_string())
        .unwrap_or_default()
}

pub fn write_json(r: &ReportData, path: &str) -> Result<(), String> {
    let s = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    std::fs::write(path, s).map_err(|e| e.to_string())
}

pub fn write_pdf(r: &ReportData, path: &str) -> Result<(), String> {
    use genpdf::elements::{Break, FrameCellDecorator, LinearLayout, Paragraph, TableLayout};
    use genpdf::style::{Color, Style};
    use genpdf::{fonts, Alignment, Element, SimplePageDecorator};

    let dir = format!("{}\\Fonts", std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()));
    let load = |f: &str| -> Result<fonts::FontData, String> {
        let bytes = std::fs::read(format!("{dir}\\{f}")).map_err(|e| format!("Yazı tipi okunamadı ({f}): {e}"))?;
        fonts::FontData::new(bytes, None).map_err(|e| e.to_string())
    };
    let regular = load("segoeui.ttf")?;
    let bold = load("segoeuib.ttf").unwrap_or_else(|_| regular.clone());
    let italic = load("segoeuii.ttf").unwrap_or_else(|_| regular.clone());
    let bold_italic = load("segoeuiz.ttf").unwrap_or_else(|_| bold.clone());
    let family = fonts::FontFamily { regular, bold, italic, bold_italic };

    let mut doc = genpdf::Document::new(family);
    doc.set_title(&r.title);
    doc.set_font_size(9);
    doc.set_line_spacing(1.25);
    let mut deco = SimplePageDecorator::new();
    deco.set_margins(16);
    doc.set_page_decorator(deco);

    let dim = Style::new().with_color(Color::Rgb(110, 120, 130));
    let h1 = Style::new().bold().with_font_size(20);
    let h2 = Style::new().bold().with_font_size(12);
    let sev_color = |s: Severity| match s {
        Severity::Critical => Color::Rgb(210, 30, 45),
        Severity::High => Color::Rgb(220, 95, 30),
        Severity::Medium => Color::Rgb(190, 130, 0),
        Severity::Low => Color::Rgb(20, 120, 190),
        Severity::Info => Color::Rgb(110, 120, 130),
    };

    doc.push(Paragraph::new("GHOST MONITOR").styled(Style::new().bold().with_font_size(8).with_color(Color::Rgb(20, 150, 90))));
    doc.push(Paragraph::new(r.title.as_str()).styled(h1));
    doc.push(
        Paragraph::new(format!(
            "{} · {} — {} · oluşturuldu {}",
            r.host.hostname,
            local(r.since),
            local(r.until),
            local(r.generated_at)
        ))
        .styled(dim),
    );
    doc.push(Break::new(1.0));

    let verdict = match r.top_severity {
        None => "Dönem boyunca etkin kurallar şüpheli davranış tespit etmedi.".to_string(),
        Some(s) => format!("Dönemdeki en yüksek bulgu seviyesi: {}. Ayrıntılar aşağıda.", sev_tr(s)),
    };
    doc.push(Paragraph::new(verdict).styled(Style::new().bold().with_color(r.top_severity.map(sev_color).unwrap_or(Color::Rgb(20, 150, 90)))));
    doc.push(Break::new(0.6));

    let mut summary = TableLayout::new(vec![1, 1, 1, 1]);
    summary.set_cell_decorator(FrameCellDecorator::new(false, false, false));
    let cell = |v: String, k: &str| {
        LinearLayout::vertical()
            .element(Paragraph::new(v).styled(Style::new().bold().with_font_size(16)))
            .element(Paragraph::new(k.to_string()).styled(dim))
    };
    let threats = r.findings.iter().filter(|f| f.severity > Severity::Info).count();
    summary
        .row()
        .element(cell(r.total_events.to_string(), "kayıtlı olay"))
        .element(cell(threats.to_string(), "şüpheli bulgu"))
        .element(cell(r.new_remote_hosts.to_string(), "yeni uzak adres"))
        .element(cell(r.open_ports.len().to_string(), "dışa açık port (şu an)"))
        .push()
        .map_err(|e| e.to_string())?;
    doc.push(summary);
    doc.push(Break::new(1.0));

    let table = |cols: Vec<usize>| {
        let mut t = TableLayout::new(cols);
        t.set_cell_decorator(FrameCellDecorator::new(true, true, false));
        t
    };
    let p = |s: String| Paragraph::new(s).padded(1);
    let ph = |s: &str| Paragraph::new(s.to_string()).styled(Style::new().bold()).padded(1);

    doc.push(Paragraph::new("Şüpheli bulgular").styled(h2));
    if r.findings.is_empty() {
        doc.push(Paragraph::new("Bu dönemde bulgu yok.").styled(dim));
    } else {
        let mut t = table(vec![2, 6, 7, 1]);
        t.row().element(ph("Seviye")).element(ph("Bulgu")).element(ph("Öğe")).element(ph("Puan")).push().map_err(|e| e.to_string())?;
        for f in r.findings.iter().take(60) {
            t.row()
                .element(Paragraph::new(sev_tr(f.severity)).styled(Style::new().bold().with_color(sev_color(f.severity))).padded(1))
                .element(p(f.title.clone()))
                .element(p(f.entity.clone()))
                .element(p(f.score.to_string()))
                .push()
                .map_err(|e| e.to_string())?;
        }
        doc.push(t);
    }
    doc.push(Break::new(1.0));

    if r.days.len() > 1 {
        doc.push(Paragraph::new("Günlük dağılım").styled(h2));
        let mut t = table(vec![3, 2, 2, 2]);
        t.row().element(ph("Gün")).element(ph("Olay")).element(ph("Tehdit")).element(ph("Yeni uzak adres")).push().map_err(|e| e.to_string())?;
        for d in &r.days {
            t.row()
                .element(p(d.day.clone()))
                .element(p(d.events.to_string()))
                .element(p(d.threats.to_string()))
                .element(p(d.new_remotes.to_string()))
                .push()
                .map_err(|e| e.to_string())?;
        }
        doc.push(t);
        doc.push(Break::new(1.0));
    }

    doc.push(Paragraph::new("En çok bağlanılan uzak adresler").styled(h2));
    if r.top_remotes.is_empty() {
        doc.push(Paragraph::new("Bu dönemde kayıtlı internet bağlantısı yok.").styled(dim));
    } else {
        let mut t = table(vec![4, 5, 3, 1, 4]);
        t.row().element(ph("Adres")).element(ph("Ana bilgisayar")).element(ph("Ülke / ASN")).element(ph("Sayı")).element(ph("İşlemler")).push().map_err(|e| e.to_string())?;
        for x in &r.top_remotes {
            t.row()
                .element(p(x.remote.clone()))
                .element(p(x.hostname.clone().unwrap_or_else(|| "—".into())))
                .element(p([x.country.clone(), x.asn.clone()].into_iter().flatten().collect::<Vec<_>>().join(" ")))
                .element(p(x.count.to_string()))
                .element(p(x.processes.replace(',', ", ")))
                .push()
                .map_err(|e| e.to_string())?;
        }
        doc.push(t);
    }
    doc.push(Break::new(1.0));

    doc.push(Paragraph::new("Dışa açık portlar (rapor anı)").styled(h2));
    if r.open_ports.is_empty() {
        doc.push(Paragraph::new("Dışa açık dinleyen port yok.").styled(dim));
    } else {
        let mut t = table(vec![1, 1, 3, 4]);
        t.row().element(ph("Port")).element(ph("Protokol")).element(ph("Adres")).element(ph("İşlem")).push().map_err(|e| e.to_string())?;
        for o in &r.open_ports {
            t.row()
                .element(p(o.port.to_string()))
                .element(p(o.protocol.clone()))
                .element(p(o.bind.clone()))
                .element(p(o.process.clone()))
                .push()
                .map_err(|e| e.to_string())?;
        }
        doc.push(t);
    }
    doc.push(Break::new(1.0));

    doc.push(Paragraph::new("Başlangıç değişiklikleri").styled(h2));
    if r.startup_events.is_empty() {
        doc.push(Paragraph::new("Bu dönemde başlangıç girdilerinde değişiklik yok.").styled(dim));
    } else {
        for ev in &r.startup_events {
            doc.push(Paragraph::new(format!("{}  {}", local(ev.ts), ev.title)));
        }
    }
    doc.push(Break::new(1.0));

    doc.push(Paragraph::new("En sık başlatılan işlemler").styled(h2));
    if r.top_processes.is_empty() {
        doc.push(Paragraph::new("Kayıt yok.").styled(dim));
    } else {
        doc.push(Paragraph::new(
            r.top_processes.iter().map(|(n, c)| format!("{n} ({c})")).collect::<Vec<_>>().join(", "),
        ));
    }
    doc.push(Break::new(1.5));
    doc.push(
        Paragraph::new(format!(
            "{} {} · Ghost Monitor {} · Bu rapor yalnızca yerel veritabanındaki kayıtlardan üretilmiştir.",
            r.host.os_name, r.host.os_version, r.host.app_version
        ))
        .aligned(Alignment::Center)
        .styled(dim.with_font_size(7)),
    );

    doc.render_to_file(path).map_err(|e| format!("PDF yazılamadı: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReportData {
        ReportData {
            kind: "daily".into(),
            title: "Günlük güvenlik raporu".into(),
            generated_at: 1_790_000_000_000,
            since: 1_789_900_000_000,
            until: 1_790_000_000_000,
            host: HostInfo {
                hostname: "test-pc".into(),
                os_name: "Windows 11".into(),
                os_version: "26100".into(),
                kernel: "26100".into(),
                cpu_brand: "x".into(),
                cpu_count: 8,
                mem_total: 1,
                elevated: false,
                boot_time: 0,
                app_version: "0.1.0".into(),
                data_dir: "x".into(),
            },
            top_severity: Some(Severity::Medium),
            total_events: 42,
            by_severity: vec![("INFO".into(), 40), ("MEDIUM".into(), 2)],
            by_kind: vec![("process.start".into(), 40)],
            findings: vec![Finding {
                key: "k".into(),
                entity_kind: "process".into(),
                entity: r"C:\Kullanıcılar\şüpheli.exe".into(),
                title: "İmzasız dosya geçici klasörden çalışıyor — ğüşıöç".into(),
                severity: Severity::Medium,
                score: 30,
                signals: vec![],
                first_seen: 1,
                last_seen: 2,
                pid: None,
                pids: vec![],
                status: "open".into(),
            }],
            top_processes: vec![("chrome.exe".into(), 12)],
            top_remotes: vec![],
            new_remote_hosts: 3,
            startup_events: vec![],
            notable_events: vec![],
            open_ports: vec![PortRow { port: 445, protocol: "TCP".into(), bind: "0.0.0.0".into(), process: "System".into() }],
            days: vec![],
        }
    }

    #[test]
    fn pdf_survives_long_paths_and_many_rows() {
        let mut r = sample();
        let long = r"C:\Users\kullanıcı\AppData\Local\Programs\ÇokUzunBirUygulamaAdı\resources\backend\bin\x86_64-pc-windows-msvc\çalıştırılabilir-dosya-adı-çok-uzun.exe";
        let f = r.findings[0].clone();
        r.findings = (0..80)
            .map(|i| Finding { key: format!("k{i}"), entity: format!("{long} — {long}"), ..f.clone() })
            .collect();
        r.top_remotes = (0..20)
            .map(|i| RemoteRow {
                remote: format!("2a00:1450:4017:80{i:02}::200e"),
                hostname: Some("çok-uzun-bir-ana-bilgisayar-adı.örnek.cloudfront.amazonaws.com".into()),
                country: Some("DE".into()),
                asn: Some("AS16509 Amazon.com, Inc.".into()),
                count: 12,
                processes: "chrome.exe,msedge.exe,Discord.exe,steamwebhelper.exe,OneDrive.exe".into(),
            })
            .collect();
        r.days = (1..=7)
            .map(|d| DayRow { day: format!("2026-11-{d:02}"), events: 100 * d, threats: d % 3, new_remotes: d })
            .collect();
        // GM_PDF_OUT=<path> keeps the file for visual inspection.
        let keep = std::env::var("GM_PDF_OUT").ok();
        let p = keep.clone().map(std::path::PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("gm_report_long.pdf"));
        write_pdf(&r, &p.to_string_lossy()).unwrap();
        assert!(std::fs::metadata(&p).unwrap().len() > 10_000);
        if keep.is_none() {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn pdf_and_json_render() {
        let dir = std::env::temp_dir();
        let pdf = dir.join("gm_report_test.pdf");
        let js = dir.join("gm_report_test.json");
        write_pdf(&sample(), &pdf.to_string_lossy()).unwrap();
        write_json(&sample(), &js.to_string_lossy()).unwrap();
        let bytes = std::fs::read(&pdf).unwrap();
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 2000);
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&js).unwrap()).unwrap();
        assert_eq!(v["totalEvents"], 42);
        let _ = std::fs::remove_file(pdf);
        let _ = std::fs::remove_file(js);
    }
}
