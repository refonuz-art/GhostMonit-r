//! "Geçen haftaya göre ne değişti?" — compares the last 7 days with the 7 days before,
//! using only what was recorded (events, findings, process/DNS/connection history, daily
//! health scores). Where history is too short the section says so instead of guessing.

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::model::Severity;

const DAY: i64 = 24 * 3600 * 1000;
const ITEMS: usize = 15;
/// The first hour of a history table is its baseline (everything is "new" then).
const BASELINE_MS: i64 = 3600 * 1000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub ts: i64,
    pub title: String,
    pub detail: String,
    pub severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub id: String,
    pub title: String,
    pub now: i64,
    pub prev: i64,
    pub items: Vec<Item>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckChange {
    pub label: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthDelta {
    pub now: Option<i64>,
    pub now_day: Option<String>,
    pub then: Option<i64>,
    pub then_day: Option<String>,
    pub changed: Vec<CheckChange>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeeklyDiff {
    pub since: i64,
    pub until: i64,
    pub health: HealthDelta,
    pub sections: Vec<Section>,
}

fn count(db: &Connection, sql: &str, a: i64, b: i64) -> i64 {
    db.query_row(sql, params![a, b], |r| r.get(0)).unwrap_or(0)
}

fn events_section(db: &Connection, id: &str, title: &str, kinds: &[&str], since: i64, until: i64) -> Section {
    let list = kinds.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(",");
    let cnt = format!("SELECT COUNT(*) FROM events WHERE kind IN ({list}) AND ts >= ?1 AND ts < ?2");
    let items = db
        .prepare(&format!(
            "SELECT ts, title, detail, severity FROM events WHERE kind IN ({list}) AND ts >= ?1 AND ts < ?2 ORDER BY ts DESC LIMIT {ITEMS}"
        ))
        .and_then(|mut st| {
            st.query_map(params![since, until], |r| {
                Ok(Item { ts: r.get(0)?, title: r.get(1)?, detail: r.get(2)?, severity: Some(Severity::parse(&r.get::<_, String>(3)?)) })
            })?
            .collect()
        })
        .unwrap_or_default();
    Section {
        id: id.into(),
        title: title.into(),
        now: count(db, &cnt, since, until),
        prev: count(db, &cnt, since - 7 * DAY, since),
        items,
        note: coverage_note(earliest(db, "SELECT MIN(ts) FROM events"), since, "Olay geçmişi"),
    }
}

fn earliest(db: &Connection, sql: &str) -> Option<i64> {
    db.query_row(sql, [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()
}

fn coverage_note(first: Option<i64>, since: i64, what: &str) -> Option<String> {
    match first {
        None => Some(format!("{what} henüz kayıt yok.")),
        Some(t) if t > since - 7 * DAY => Some(format!(
            "{what} {} tarihinden beri tutuluyor; önceki haftayla karşılaştırma eksik.",
            chrono::DateTime::from_timestamp_millis(t)
                .map(|d| d.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M").to_string())
                .unwrap_or_default()
        )),
        _ => None,
    }
}

pub fn build(db: &Connection, until: i64) -> WeeklyDiff {
    let since = until - 7 * DAY;
    let prev = since - 7 * DAY;
    let mut sections = Vec::new();

    // ---- findings ----
    {
        let cnt = "SELECT COUNT(*) FROM findings WHERE severity <> 'INFO' AND first_seen >= ?1 AND first_seen < ?2";
        let items = db
            .prepare(&format!(
                "SELECT first_seen, title, entity, severity FROM findings
                  WHERE severity <> 'INFO' AND first_seen >= ?1 AND first_seen < ?2
                  ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, first_seen DESC
                  LIMIT {ITEMS}"
            ))
            .and_then(|mut st| {
                st.query_map(params![since, until], |r| {
                    Ok(Item { ts: r.get(0)?, title: r.get(1)?, detail: r.get(2)?, severity: Some(Severity::parse(&r.get::<_, String>(3)?)) })
                })?
                .collect()
            })
            .unwrap_or_default();
        sections.push(Section {
            id: "findings".into(),
            title: "Yeni bulgular".into(),
            now: count(db, cnt, since, until),
            prev: count(db, cnt, prev, since),
            items,
            note: coverage_note(earliest(db, "SELECT MIN(first_seen) FROM findings"), since, "Bulgu geçmişi"),
        });
    }

    sections.push(events_section(db, "startup", "Açılış kayıtları", &["startup.new", "startup.changed", "startup.removed"], since, until));
    sections.push(events_section(db, "ext", "Tarayıcı uzantıları", &["browser.extension_new"], since, until));

    // ---- new programs (first run ever, after the history baseline) ----
    {
        // Recording start, not the oldest start time: processes already running when
        // recording began carry their (older) real start times.
        let first = db
            .query_row("SELECT CAST(value AS INTEGER) FROM settings WHERE key = ?1", [crate::history::SINCE_KEY], |r| r.get::<_, i64>(0))
            .ok()
            .or_else(|| earliest(db, "SELECT MIN(started) FROM proc_history"));
        let base = first.map(|t| t + BASELINE_MS).unwrap_or(i64::MAX);
        let cnt = |a: i64, b: i64| -> i64 {
            db.query_row(
                "SELECT COUNT(*) FROM (SELECT MIN(started) f FROM proc_history WHERE exe IS NOT NULL GROUP BY exe COLLATE NOCASE)
                  WHERE f >= ?1 AND f < ?2 AND f >= ?3",
                params![a, b, base],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        let items = db
            .prepare(&format!(
                "SELECT f, name, exe, sig FROM (
                   SELECT MIN(started) f, name, exe, MAX(sig_state) sig FROM proc_history WHERE exe IS NOT NULL GROUP BY exe COLLATE NOCASE)
                  WHERE f >= ?1 AND f < ?2 AND f >= ?3 ORDER BY f DESC LIMIT {ITEMS}"
            ))
            .and_then(|mut st| {
                st.query_map(params![since, until, base], |r| {
                    let sig: String = r.get(3)?;
                    Ok(Item {
                        ts: r.get(0)?,
                        title: r.get(1)?,
                        detail: r.get(2)?,
                        severity: (sig == "unsigned" || sig == "invalid").then_some(Severity::Low),
                    })
                })?
                .collect()
            })
            .unwrap_or_default();
        sections.push(Section {
            id: "programs".into(),
            title: "İlk kez çalışan programlar".into(),
            now: cnt(since, until),
            prev: cnt(prev, since),
            items,
            note: coverage_note(first, since, "Süreç geçmişi"),
        });
    }

    // ---- new remote addresses, grouped by program ----
    {
        let cnt = "SELECT COUNT(*) FROM (SELECT MIN(ts) f FROM conn_history GROUP BY remote) WHERE f >= ?1 AND f < ?2";
        let items = db
            .prepare(&format!(
                "SELECT MAX(f), COALESCE(process, '?'), COUNT(*), GROUP_CONCAT(DISTINCT country) FROM (
                   SELECT remote, MIN(ts) f, process, country FROM conn_history GROUP BY remote)
                  WHERE f >= ?1 AND f < ?2 GROUP BY process ORDER BY COUNT(*) DESC LIMIT {ITEMS}"
            ))
            .and_then(|mut st| {
                st.query_map(params![since, until], |r| {
                    let n: i64 = r.get(2)?;
                    let c: Option<String> = r.get(3)?;
                    Ok(Item {
                        ts: r.get(0)?,
                        title: r.get(1)?,
                        detail: format!("{n} yeni adres{}", c.map(|c| format!(" · {c}")).unwrap_or_default()),
                        severity: None,
                    })
                })?
                .collect()
            })
            .unwrap_or_default();
        sections.push(Section {
            id: "remotes".into(),
            title: "Yeni internet adresleri".into(),
            now: count(db, cnt, since, until),
            prev: count(db, cnt, prev, since),
            items,
            note: coverage_note(earliest(db, "SELECT MIN(ts) FROM conn_history"), since, "Bağlantı geçmişi"),
        });
    }

    // ---- new domains ----
    {
        let first = earliest(db, "SELECT MIN(ts) FROM dns_log");
        let base = first.map(|t| t + BASELINE_MS).unwrap_or(i64::MAX);
        let cnt = |a: i64, b: i64| -> i64 {
            db.query_row(
                "SELECT COUNT(*) FROM (SELECT MIN(ts) f FROM dns_log WHERE name NOT LIKE '%.arpa' GROUP BY name) WHERE f >= ?1 AND f < ?2 AND f >= ?3",
                params![a, b, base],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        let items = db
            .prepare(&format!(
                "SELECT f, name, COALESCE(process, 'işlem bilinmiyor') FROM (
                   SELECT MIN(ts) f, name, process FROM dns_log WHERE name NOT LIKE '%.arpa' GROUP BY name)
                  WHERE f >= ?1 AND f < ?2 AND f >= ?3 ORDER BY f DESC LIMIT {ITEMS}"
            ))
            .and_then(|mut st| {
                st.query_map(params![since, until, base], |r| {
                    Ok(Item { ts: r.get(0)?, title: r.get(1)?, detail: r.get(2)?, severity: None })
                })?
                .collect()
            })
            .unwrap_or_default();
        let failed: i64 = db
            .query_row("SELECT COUNT(*) FROM dns_log WHERE status = 9003 AND ts >= ?1 AND ts < ?2", params![since, until], |r| r.get(0))
            .unwrap_or(0);
        let mut note = coverage_note(first, since, "DNS geçmişi");
        if failed > 0 {
            let s = format!("Bu hafta {failed} sorgu “alan adı yok” yanıtı aldı.");
            note = Some(note.map(|n| format!("{n} {s}")).unwrap_or(s));
        }
        sections.push(Section {
            id: "dns".into(),
            title: "İlk kez sorgulanan alan adları".into(),
            now: cnt(since, until),
            prev: cnt(prev, since),
            items,
            note,
        });
    }

    sections.push(events_section(db, "config", "Sistem ve ağ ayarları", &["net.config_change", "defense.change"], since, until));
    sections.push(events_section(db, "lan", "Yerel ağa katılan cihazlar", &["lan.new_device"], since, until));
    sections.push(events_section(
        db,
        "actions",
        "Sizin müdahaleleriniz",
        &["user.block", "user.quarantine", "process.suspend", "process.kill"],
        since,
        until,
    ));

    WeeklyDiff { since, until, health: health_delta(db, until), sections }
}

fn health_delta(db: &Connection, until: i64) -> HealthDelta {
    let latest: Option<(String, i64, String)> = db
        .query_row("SELECT day, score, checks FROM health_history ORDER BY day DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok();
    let then_day = chrono::DateTime::from_timestamp_millis(until - 7 * DAY)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    let then: Option<(String, i64, String)> = db
        .query_row(
            "SELECT day, score, checks FROM health_history WHERE day <= ?1 ORDER BY day DESC LIMIT 1",
            [&then_day],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let mut changed = Vec::new();
    if let (Some(a), Some(b)) = (&then, &latest) {
        let old: Vec<(String, String)> = serde_json::from_str(&a.2).unwrap_or_default();
        let new: Vec<(String, String)> = serde_json::from_str(&b.2).unwrap_or_default();
        for (label, to) in &new {
            if let Some((_, from)) = old.iter().find(|(l, _)| l == label) {
                if from != to {
                    changed.push(CheckChange { label: label.clone(), from: from.clone(), to: to.clone() });
                }
            }
        }
    }
    HealthDelta {
        now: latest.as_ref().map(|l| l.1),
        now_day: latest.map(|l| l.0),
        then: then.as_ref().map(|t| t.1),
        then_day: then.map(|t| t.0),
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn compares_two_weeks() {
        let s = Store::open_memory().unwrap();
        let db = &s.conn;
        let now = 100 * DAY;
        let ev = |ts: i64, kind: &str| {
            db.execute(
                "INSERT INTO events (ts, kind, severity, title, detail) VALUES (?1, ?2, 'LOW', 't', 'd')",
                params![ts, kind],
            )
            .unwrap();
        };
        ev(now - DAY, "startup.new");
        ev(now - 2 * DAY, "startup.removed");
        ev(now - 9 * DAY, "startup.new");
        ev(now - DAY, "process.start"); // not part of any section

        // proc history: baseline at day 80, a new program on day 99
        let run = |exe: &str, started: i64| {
            db.execute(
                "INSERT INTO proc_history (pid, name, exe, sig_state, started) VALUES (1, 'n', ?1, 'unsigned', ?2)",
                params![exe, started],
            )
            .unwrap();
        };
        run(r"C:\old.exe", 80 * DAY);
        run(r"C:\old.exe", 99 * DAY);
        run(r"C:\new.exe", 99 * DAY);

        db.execute("INSERT INTO health_history VALUES ('1970-03-20', 70, '[[\"Defender\",\"bad\"]]', 0)", []).unwrap();
        db.execute("INSERT INTO health_history VALUES ('1970-04-10', 90, '[[\"Defender\",\"ok\"]]', 0)", []).unwrap();

        let d = build(db, now);
        let startup = d.sections.iter().find(|s| s.id == "startup").unwrap();
        assert_eq!((startup.now, startup.prev), (2, 1));
        let programs = d.sections.iter().find(|s| s.id == "programs").unwrap();
        assert_eq!(programs.now, 1);
        assert_eq!(programs.items[0].detail, r"C:\new.exe");
        assert!(programs.note.is_none(), "history older than two weeks");
        let dns = d.sections.iter().find(|s| s.id == "dns").unwrap();
        assert!(dns.note.as_deref().unwrap().contains("henüz"));
        assert_eq!(d.health.now, Some(90));
        assert_eq!(d.health.changed.len(), 1);
        assert_eq!(d.health.changed[0].to, "ok");
    }
}
