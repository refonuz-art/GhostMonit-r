//! Process time machine: every process start and exit is written to `proc_history`, so the
//! process tree at any past moment can be rebuilt. Processes that ended while Ghost Monitor
//! was closed are closed with `ended_approx = 1` (we only know when we noticed).

use std::collections::{HashMap, HashSet};

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::model::{ProcessInfo, SignatureState};

/// Setting holding the moment recording began (process start times can be older).
pub const SINCE_KEY: &str = "proc_history_since";

/// (pid, start ms) identifies one process run; PIDs alone get reused.
type RunKey = (u32, i64);

fn start_ms(p: &ProcessInfo) -> i64 {
    p.start_time as i64 * 1000
}

fn sig_str(s: &SignatureState) -> &'static str {
    match s {
        SignatureState::Pending => "pending",
        SignatureState::Signed => "signed",
        SignatureState::Unsigned => "unsigned",
        SignatureState::Invalid => "invalid",
        SignatureState::Unknown => "unknown",
    }
}

#[derive(Default)]
pub struct ProcTracker {
    /// Open rows: run → (row id, signature still pending)
    open: HashMap<RunKey, (i64, bool)>,
    loaded: bool,
}

impl ProcTracker {
    /// Diff the live list against the open rows. Returns nothing; all effects go to the DB.
    pub fn update(&mut self, db: &Connection, procs: &[ProcessInfo], now: i64) {
        if !self.loaded {
            self.loaded = true;
            if let Ok(mut st) = db.prepare("SELECT id, pid, started, sig_state FROM proc_history WHERE ended IS NULL") {
                let rows = st.query_map([], |r| {
                    Ok(((r.get::<_, u32>(1)?, r.get::<_, i64>(2)?), (r.get::<_, i64>(0)?, r.get::<_, String>(3)? == "pending")))
                });
                if let Ok(rows) = rows {
                    self.open.extend(rows.flatten());
                }
            }
        }
        let live: HashMap<RunKey, &ProcessInfo> =
            procs.iter().filter(|p| p.pid > 4 && p.start_time > 0).map(|p| ((p.pid, start_ms(p)), p)).collect();
        let tx = db.unchecked_transaction();
        let gone: Vec<RunKey> = self.open.keys().filter(|k| !live.contains_key(k)).copied().collect();
        for k in gone {
            if let Some((id, _)) = self.open.remove(&k) {
                let _ = db.execute("UPDATE proc_history SET ended=?2 WHERE id=?1", params![id, now]);
            }
        }
        for (k, p) in &live {
            match self.open.get_mut(k) {
                Some((id, pending)) => {
                    if *pending && p.signature.state != SignatureState::Pending {
                        *pending = false;
                        let _ = db.execute(
                            "UPDATE proc_history SET sig_state=?2, publisher=?3 WHERE id=?1",
                            params![*id, sig_str(&p.signature.state), p.signature.publisher],
                        );
                    }
                }
                None => {
                    let r = db.execute(
                        "INSERT INTO proc_history (pid, ppid, name, exe, cmd, user, sig_state, publisher, started)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        params![
                            p.pid,
                            p.ppid,
                            p.name,
                            p.exe,
                            p.cmd.as_deref().map(|c| c.chars().take(2000).collect::<String>()),
                            p.user,
                            sig_str(&p.signature.state),
                            p.signature.publisher,
                            k.1
                        ],
                    );
                    if r.is_ok() {
                        self.open.insert(*k, (db.last_insert_rowid(), p.signature.state == SignatureState::Pending));
                    }
                }
            }
        }
        if let Ok(tx) = tx {
            let _ = tx.commit();
        }
    }
}

/// Rows still open from an earlier session whose process is gone: the app was closed, so
/// the exit time is unknown. Called once at startup before the first tracker update.
pub fn close_stale(db: &Connection, live: &HashSet<RunKey>, now: i64) {
    let Ok(mut st) = db.prepare("SELECT id, pid, started FROM proc_history WHERE ended IS NULL") else { return };
    let rows: Vec<(i64, u32, i64)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map(|r| r.flatten().collect())
        .unwrap_or_default();
    for (id, pid, started) in rows {
        if !live.contains(&(pid, started)) {
            let _ = db.execute("UPDATE proc_history SET ended=?2, ended_approx=1 WHERE id=?1", params![id, now]);
        }
    }
}

pub fn live_keys(procs: &[ProcessInfo]) -> HashSet<RunKey> {
    procs.iter().map(|p| (p.pid, start_ms(p))).collect()
}

// ---------------------------------------------------------------- queries

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcRun {
    pub id: i64,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmd: Option<String>,
    pub user: Option<String>,
    pub sig_state: String,
    pub publisher: Option<String>,
    pub started: i64,
    pub ended: Option<i64>,
    pub ended_approx: bool,
}

const COLS: &str = "id, pid, ppid, name, exe, cmd, user, sig_state, publisher, started, ended, ended_approx";

fn row(r: &rusqlite::Row) -> rusqlite::Result<ProcRun> {
    Ok(ProcRun {
        id: r.get(0)?,
        pid: r.get(1)?,
        ppid: r.get(2)?,
        name: r.get(3)?,
        exe: r.get(4)?,
        cmd: r.get(5)?,
        user: r.get(6)?,
        sig_state: r.get(7)?,
        publisher: r.get(8)?,
        started: r.get(9)?,
        ended: r.get(10)?,
        ended_approx: r.get::<_, i64>(11)? != 0,
    })
}

/// Processes alive at `ts`.
pub fn at(db: &Connection, ts: i64) -> rusqlite::Result<Vec<ProcRun>> {
    let mut st = db.prepare(&format!(
        "SELECT {COLS} FROM proc_history WHERE started <= ?1 AND (ended IS NULL OR ended >= ?1) ORDER BY started LIMIT 5000"
    ))?;
    let rows = st.query_map([ts], row)?;
    rows.collect()
}

/// Starts and exits inside [since, until], newest first.
pub fn changes(db: &Connection, since: i64, until: i64, limit: u32) -> rusqlite::Result<Vec<ProcRun>> {
    let mut st = db.prepare(&format!(
        "SELECT {COLS} FROM proc_history
          WHERE (started BETWEEN ?1 AND ?2) OR (ended BETWEEN ?1 AND ?2 AND ended_approx = 0)
          ORDER BY MAX(started, COALESCE(ended, 0)) DESC LIMIT ?3"
    ))?;
    let rows = st.query_map(params![since, until, limit], row)?;
    rows.collect()
}

/// Oldest timestamp the history covers (None = empty).
pub fn earliest(db: &Connection) -> Option<i64> {
    db.query_row("SELECT MIN(started) FROM proc_history", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()
}

/// Parent chain of a run, nearest parent first. A parent must have started before the child.
pub fn lineage(db: &Connection, pid: u32, started: i64, depth: usize) -> Vec<ProcRun> {
    let mut out = Vec::new();
    let (mut pid, mut started) = (pid, started);
    for _ in 0..depth {
        let ppid: Option<u32> = db
            .query_row(
                "SELECT ppid FROM proc_history WHERE pid=?1 AND started=?2",
                params![pid, started],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        let Some(ppid) = ppid else { break };
        let parent = db
            .query_row(
                &format!(
                    "SELECT {COLS} FROM proc_history WHERE pid=?1 AND started<=?2 AND (ended IS NULL OR ended>=?2)
                      ORDER BY started DESC LIMIT 1"
                ),
                params![ppid, started],
                row,
            )
            .ok();
        let Some(p) = parent else { break };
        pid = p.pid;
        started = p.started;
        out.push(p);
    }
    out
}

/// Most recent run of an executable (to anchor the lineage of a finding).
pub fn latest_run_of(db: &Connection, exe: &str) -> Option<ProcRun> {
    db.query_row(
        &format!("SELECT {COLS} FROM proc_history WHERE exe = ?1 COLLATE NOCASE ORDER BY started DESC LIMIT 1"),
        [exe],
        row,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SignatureInfo;
    use crate::store::Store;

    fn p(pid: u32, ppid: Option<u32>, name: &str, start: u64, sig: SignatureState) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.into(),
            exe: Some(format!(r"C:\x\{name}")),
            cmd: None,
            cpu: 0.0,
            memory: 0,
            start_time: start,
            user: None,
            signature: SignatureInfo { state: sig, publisher: None },
            connections: 0,
            critical: false,
            risk: None,
        }
    }

    #[test]
    fn records_runs_and_rebuilds_the_past() {
        let s = Store::open_memory().unwrap();
        let db = &s.conn;
        let mut t = ProcTracker::default();
        let a = p(100, None, "explorer.exe", 10, SignatureState::Signed);
        let b = p(200, Some(100), "cmd.exe", 20, SignatureState::Pending);
        t.update(db, &[a.clone(), b.clone()], 25_000);
        // signature resolves later → row updated, not duplicated
        let mut b2 = b.clone();
        b2.signature.state = SignatureState::Signed;
        t.update(db, &[a.clone(), b2], 30_000);
        // cmd exits
        t.update(db, &[a.clone()], 40_000);
        // PID 200 reused by a different process
        let c = p(200, Some(100), "evil.exe", 50, SignatureState::Unsigned);
        t.update(db, &[a.clone(), c], 55_000);

        let then = at(db, 35_000).unwrap();
        assert_eq!(then.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["explorer.exe", "cmd.exe"]);
        assert_eq!(then[1].sig_state, "signed");
        let now = at(db, 60_000).unwrap();
        assert_eq!(now.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["explorer.exe", "evil.exe"]);
        let lin = lineage(db, 200, 50_000, 5);
        assert_eq!(lin.len(), 1);
        assert_eq!(lin[0].name, "explorer.exe");
        let ch = changes(db, 39_000, 60_000, 50).unwrap();
        assert!(ch.iter().any(|r| r.name == "cmd.exe" && r.ended == Some(40_000)));
        assert!(ch.iter().any(|r| r.name == "evil.exe"));
        assert_eq!(earliest(db), Some(10_000));
    }

    #[test]
    fn stale_rows_close_as_approximate() {
        let s = Store::open_memory().unwrap();
        let db = &s.conn;
        let mut t = ProcTracker::default();
        t.update(db, &[p(300, None, "a.exe", 1, SignatureState::Signed), p(301, None, "b.exe", 2, SignatureState::Signed)], 5_000);
        // app restarts; only a.exe still runs
        let still = [p(300, None, "a.exe", 1, SignatureState::Signed)];
        close_stale(db, &live_keys(&still), 90_000);
        let mut t2 = ProcTracker::default();
        t2.update(db, &still, 91_000);
        let rows = at(db, 95_000).unwrap();
        assert_eq!(rows.len(), 1);
        let b: (Option<i64>, i64) =
            db.query_row("SELECT ended, ended_approx FROM proc_history WHERE name='b.exe'", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(b, (Some(90_000), 1));
        let n: i64 = db.query_row("SELECT COUNT(*) FROM proc_history", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "a.exe continues its open row");
    }
}
