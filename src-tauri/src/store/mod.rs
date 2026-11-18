//! SQLite persistence: events (timeline), findings, trust list, baselines, history.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Finding, SecurityEvent, Severity};

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL,
        subject TEXT,
        data TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_events_ts ON events(ts);
    CREATE INDEX idx_events_kind ON events(kind);

    CREATE TABLE findings (
        key TEXT PRIMARY KEY,
        entity_kind TEXT NOT NULL,
        entity TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        score INTEGER NOT NULL,
        signals TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'open'
    );

    CREATE TABLE trust (
        key TEXT PRIMARY KEY,
        note TEXT,
        ts INTEGER NOT NULL
    );

    CREATE TABLE baseline (
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        ts INTEGER NOT NULL,
        PRIMARY KEY (kind, value)
    );

    CREATE TABLE conn_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        pid INTEGER NOT NULL,
        process TEXT,
        exe TEXT,
        protocol TEXT NOT NULL,
        remote TEXT NOT NULL,
        port INTEGER NOT NULL,
        hostname TEXT,
        country TEXT,
        asn TEXT
    );
    CREATE INDEX idx_conn_ts ON conn_history(ts);

    CREATE TABLE startup_items (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        command TEXT NOT NULL,
        location TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        removed_at INTEGER
    );

    CREATE TABLE bad_hashes (
        sha256 TEXT PRIMARY KEY,
        name TEXT,
        source TEXT NOT NULL
    );

    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE secrets (
        name TEXT PRIMARY KEY,
        blob BLOB NOT NULL
    );
    "#,
    // v2 — autostart visibility depends on privilege: some scheduled tasks/services are
    // only readable by an elevated process. 'admin' = never seen by a standard-user scan.
    r#"
    ALTER TABLE startup_items ADD COLUMN scope TEXT NOT NULL DEFAULT 'user';
    -- Repair v1 data: entries "removed" within minutes of first sighting were privilege
    -- flicker (an elevated run saw them, the next standard run could not), not deletions.
    UPDATE startup_items SET scope = 'admin', removed_at = NULL
     WHERE removed_at IS NOT NULL AND removed_at - first_seen < 600000;
    -- That elevated run already established the admin-scope baseline.
    INSERT OR IGNORE INTO settings (key, value)
      SELECT 'startup_scanned_admin', CAST(MIN(first_seen) AS TEXT) FROM startup_items
       WHERE scope = 'admin' HAVING COUNT(*) > 0;
    "#,
    // v3
    r#"
    CREATE TABLE quarantine (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        original    TEXT NOT NULL,
        stored      TEXT NOT NULL,
        sha256      TEXT NOT NULL,
        size        INTEGER NOT NULL,
        key         BLOB NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        created_at  INTEGER NOT NULL
    );
    "#,
    // v4 — process time machine, DNS query log, daily health score
    r#"
    CREATE TABLE proc_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER NOT NULL,
        ppid INTEGER,
        name TEXT NOT NULL,
        exe TEXT,
        cmd TEXT,
        user TEXT,
        sig_state TEXT NOT NULL DEFAULT 'pending',
        publisher TEXT,
        started INTEGER NOT NULL,
        ended INTEGER,
        -- 1 = Ghost Monitor was not running when the process ended; 'ended' is when we noticed.
        ended_approx INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_ph_started ON proc_history(started);
    CREATE INDEX idx_ph_ended ON proc_history(ended);
    CREATE INDEX idx_ph_exe ON proc_history(exe);

    CREATE TABLE dns_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        name TEXT NOT NULL,
        qtype INTEGER NOT NULL,
        status INTEGER,
        pid INTEGER,
        process TEXT,
        exe TEXT,
        results TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL
    );
    CREATE INDEX idx_dns_ts ON dns_log(ts);
    CREATE INDEX idx_dns_name ON dns_log(name);

    CREATE TABLE health_history (
        day TEXT PRIMARY KEY,
        score INTEGER NOT NULL,
        checks TEXT NOT NULL,
        ts INTEGER NOT NULL
    );
    "#,
];

pub struct Store {
    pub conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let s = Self { conn };
        s.migrate()?;
        Ok(s)
    }

    #[cfg(test)]
    pub fn open_memory() -> rusqlite::Result<Self> {
        let s = Self { conn: Connection::open_in_memory()? };
        s.migrate()?;
        Ok(s)
    }

    pub(crate) fn migrate(&self) -> rusqlite::Result<()> {
        let v: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(v as usize) {
            self.conn.execute_batch(&format!("BEGIN; {m} COMMIT;"))?;
            self.conn.pragma_update(None, "user_version", (i + 1) as i64)?;
        }
        Ok(())
    }

    // ---- events ----

    pub fn insert_event(&self, e: &SecurityEvent) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO events (ts, kind, severity, title, detail, subject, data) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![e.ts, e.kind, e.severity.as_str(), e.title, e.detail, e.subject, e.data.to_string()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn events(
        &self,
        since: Option<i64>,
        until: Option<i64>,
        kinds: &[String],
        min_severity: Option<Severity>,
        search: Option<&str>,
        limit: u32,
    ) -> rusqlite::Result<Vec<SecurityEvent>> {
        let mut sql = String::from("SELECT id, ts, kind, severity, title, detail, subject, data FROM events WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(s) = since {
            sql.push_str(" AND ts >= ?");
            args.push(Box::new(s));
        }
        if let Some(u) = until {
            sql.push_str(" AND ts <= ?");
            args.push(Box::new(u));
        }
        if !kinds.is_empty() {
            sql.push_str(&format!(" AND kind IN ({})", vec!["?"; kinds.len()].join(",")));
            for k in kinds {
                args.push(Box::new(k.clone()));
            }
        }
        if let Some(min) = min_severity {
            let allowed: Vec<&str> = [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical]
                .into_iter()
                .filter(|s| *s >= min)
                .map(|s| s.as_str())
                .collect();
            sql.push_str(&format!(" AND severity IN ({})", vec!["?"; allowed.len()].join(",")));
            for a in allowed {
                args.push(Box::new(a.to_string()));
            }
        }
        if let Some(q) = search.filter(|q| !q.is_empty()) {
            sql.push_str(" AND (title LIKE ? OR detail LIKE ? OR subject LIKE ?)");
            let like = format!("%{q}%");
            for _ in 0..3 {
                args.push(Box::new(like.clone()));
            }
        }
        sql.push_str(" ORDER BY ts DESC, id DESC LIMIT ?");
        args.push(Box::new(limit));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|b| b.as_ref())), |r| {
            let data: String = r.get(7)?;
            Ok(SecurityEvent {
                id: r.get(0)?,
                ts: r.get(1)?,
                kind: r.get(2)?,
                severity: Severity::parse(&r.get::<_, String>(3)?),
                title: r.get(4)?,
                detail: r.get(5)?,
                subject: r.get(6)?,
                data: serde_json::from_str(&data).unwrap_or(serde_json::Value::Null),
            })
        })?;
        rows.collect()
    }

    pub fn prune_events(&self, older_than: i64) -> rusqlite::Result<usize> {
        let n = self.conn.execute("DELETE FROM events WHERE ts < ?1", [older_than])?;
        self.conn.execute("DELETE FROM conn_history WHERE ts < ?1", [older_than])?;
        self.conn.execute("DELETE FROM proc_history WHERE ended IS NOT NULL AND ended < ?1", [older_than])?;
        self.conn.execute("DELETE FROM dns_log WHERE ts < ?1", [older_than])?;
        Ok(n)
    }

    // ---- findings ----

    pub fn upsert_finding(&self, f: &Finding) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO findings (key, entity_kind, entity, title, severity, score, signals, first_seen, last_seen, status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(key) DO UPDATE SET title=excluded.title, severity=excluded.severity, score=excluded.score,
               signals=excluded.signals, last_seen=excluded.last_seen,
               status=CASE WHEN findings.status='dismissed' THEN 'dismissed' ELSE excluded.status END",
            params![
                f.key, f.entity_kind, f.entity, f.title, f.severity.as_str(), f.score,
                serde_json::to_string(&f.signals).unwrap_or_default(), f.first_seen, f.last_seen, f.status
            ],
        )?;
        Ok(())
    }

    pub fn finding_first_seen(&self, key: &str) -> rusqlite::Result<Option<(i64, String)>> {
        self.conn
            .query_row("SELECT first_seen, status FROM findings WHERE key=?1", [key], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
    }

    pub fn finding_history(&self, limit: u32) -> rusqlite::Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, entity_kind, entity, title, severity, score, signals, first_seen, last_seen, status
             FROM findings ORDER BY last_seen DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            let sig: String = r.get(6)?;
            Ok(Finding {
                key: r.get(0)?,
                entity_kind: r.get(1)?,
                entity: r.get(2)?,
                title: r.get(3)?,
                severity: Severity::parse(&r.get::<_, String>(4)?),
                score: r.get(5)?,
                signals: serde_json::from_str(&sig).unwrap_or_default(),
                first_seen: r.get(7)?,
                last_seen: r.get(8)?,
                pid: None,
                pids: vec![],
                status: r.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn set_finding_status(&self, key: &str, status: &str) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE findings SET status=?2 WHERE key=?1", params![key, status])?;
        Ok(())
    }

    // ---- trust ----

    pub fn trusted(&self) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT key FROM trust")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    pub fn set_trust(&self, key: &str, trusted: bool, note: Option<&str>) -> rusqlite::Result<()> {
        if trusted {
            self.conn.execute(
                "INSERT OR REPLACE INTO trust (key, note, ts) VALUES (?1, ?2, ?3)",
                params![key, note, chrono::Utc::now().timestamp_millis()],
            )?;
        } else {
            self.conn.execute("DELETE FROM trust WHERE key=?1", [key])?;
        }
        Ok(())
    }

    // ---- baseline ----

    pub fn baseline(&self, kind: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM baseline WHERE kind=?1")?;
        let rows = stmt.query_map([kind], |r| r.get(0))?;
        rows.collect()
    }

    pub fn add_baseline(&self, kind: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO baseline (kind, value, ts) VALUES (?1, ?2, ?3)",
            params![kind, value, chrono::Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }

    // ---- settings ----

    pub fn setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn.query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0)).optional()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)", params![key, value])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: i64, sev: Severity, title: &str) -> SecurityEvent {
        SecurityEvent {
            id: 0,
            ts,
            kind: "process".into(),
            severity: sev,
            title: title.into(),
            detail: "d".into(),
            subject: Some("x.exe".into()),
            data: serde_json::json!({}),
        }
    }

    #[test]
    fn events_roundtrip_and_filter() {
        let s = Store::open_memory().unwrap();
        s.insert_event(&ev(1, Severity::Info, "a")).unwrap();
        s.insert_event(&ev(2, Severity::High, "b")).unwrap();
        s.insert_event(&ev(3, Severity::Low, "c")).unwrap();
        let all = s.events(None, None, &[], None, None, 10).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].title, "c");
        let hi = s.events(None, None, &[], Some(Severity::Low), None, 10).unwrap();
        assert_eq!(hi.len(), 2);
        let q = s.events(None, None, &[], None, Some("b"), 10).unwrap();
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn dismissed_finding_stays_dismissed() {
        let s = Store::open_memory().unwrap();
        let mut f = Finding {
            key: "process:c:\\a.exe".into(),
            entity_kind: "process".into(),
            entity: "a.exe".into(),
            title: "t".into(),
            severity: Severity::Medium,
            score: 30,
            signals: vec![],
            first_seen: 1,
            last_seen: 1,
            pid: None,
            pids: vec![],
            status: "open".into(),
        };
        s.upsert_finding(&f).unwrap();
        s.set_finding_status(&f.key, "dismissed").unwrap();
        f.last_seen = 2;
        s.upsert_finding(&f).unwrap();
        assert_eq!(s.finding_first_seen(&f.key).unwrap().unwrap().1, "dismissed");
    }
}
