//! Append-only, hash-chained audit log (SQLite) + redaction helper.
//! CONTRACT: keep these public signatures; implement bodies.
//!
//! Security properties:
//! - Rows can only be inserted: SQLite triggers `ABORT` any `UPDATE`/`DELETE` on `audit`.
//! - Each row stores `hash = SHA-256(prev_hash || canonical entry json || ts_ms)`, forming a
//!   chain; [`AuditLog::verify_chain`] detects edits, deletions in the middle/head and
//!   re-ordering. (Truncating the newest rows cannot be detected from the DB alone; anchor
//!   the latest hash externally if that matters.)
//! - `args`/`result` are re-redacted with [`redact`] and truncated to [`MAX_FIELD_BYTES`].
use agent_protocol::{Brain, RiskTier};
use regex::{Captures, Regex};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum stored size of `args` and `result` (bytes, UTF-8 boundary respected).
pub const MAX_FIELD_BYTES: usize = 4096;
/// `prev_hash` of the first row.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// "phone:<name>", "agent", "tray", ...
    pub actor: String,
    pub tool: String,
    /// Already redacted by the caller via [`redact`]; `append` redacts again defensively.
    pub args: String,
    pub result: String,
    pub risk: RiskTier,
    pub brain: Brain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub ts_ms: u64,
    pub entry: AuditEntry,
    /// hex SHA-256 over (prev_hash || canonical entry json || ts)
    pub hash: String,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms     INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    tool      TEXT NOT NULL,
    args      TEXT NOT NULL,
    result    TEXT NOT NULL,
    risk      TEXT NOT NULL,
    brain     TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"#;

fn enum_str<T: Serialize>(v: &T) -> anyhow::Result<String> {
    match serde_json::to_value(v)? {
        serde_json::Value::String(s) => Ok(s),
        other => anyhow::bail!("unexpected enum encoding: {other}"),
    }
}

fn enum_parse<T: for<'de> Deserialize<'de>>(s: &str) -> anyhow::Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}

fn compute_hash(prev_hash: &str, e: &AuditEntry, ts_ms: u64) -> anyhow::Result<String> {
    // serde_json serializes struct fields in declaration order => canonical.
    let json = serde_json::to_string(e)?;
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(json.as_bytes());
    h.update(ts_ms.to_string().as_bytes());
    Ok(hex::encode(h.finalize()))
}

fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    const MARK: &str = "…[truncated]";
    let mut cut = max.saturating_sub(MARK.len());
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &s[..cut], MARK)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

type Row = (i64, u64, AuditEntry, String, String);

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, i64, [String; 7], String)> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        [
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
        ],
        r.get(9)?,
    ))
}

fn decode_row(raw: (i64, i64, [String; 7], String)) -> anyhow::Result<Row> {
    let (id, ts, [actor, tool, args, result, risk, brain, prev_hash], hash) = raw;
    let entry = AuditEntry {
        actor,
        tool,
        args,
        result,
        risk: enum_parse(&risk)?,
        brain: enum_parse(&brain)?,
    };
    Ok((id, u64::try_from(ts)?, entry, prev_hash, hash))
}

const SELECT_COLS: &str = "id, ts_ms, actor, tool, args, result, risk, brain, prev_hash, hash";

impl AuditLog {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock only means another thread panicked mid-call; the connection
        // itself is still consistent (statements are transactional).
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn append(&self, e: &AuditEntry) -> anyhow::Result<i64> {
        let entry = AuditEntry {
            actor: truncate(redact(&e.actor), 256),
            tool: truncate(e.tool.clone(), 256),
            args: truncate(redact(&e.args), MAX_FIELD_BYTES),
            result: truncate(redact(&e.result), MAX_FIELD_BYTES),
            risk: e.risk,
            brain: e.brain,
        };
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let prev: String = tx
            .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or_else(|| GENESIS_HASH.to_owned());
        let ts = now_ms();
        let hash = compute_hash(&prev, &entry, ts)?;
        tx.execute(
            "INSERT INTO audit (ts_ms, actor, tool, args, result, risk, brain, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                i64::try_from(ts)?,
                entry.actor,
                entry.tool,
                entry.args,
                entry.result,
                enum_str(&entry.risk)?,
                enum_str(&entry.brain)?,
                prev,
                hash
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Newest-first, at most `n` records.
    pub fn recent(&self, n: usize) -> anyhow::Result<Vec<AuditRecord>> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!(
            "SELECT {SELECT_COLS} FROM audit ORDER BY id DESC LIMIT ?1"
        ))?;
        let rows = st.query_map([i64::try_from(n).unwrap_or(i64::MAX)], read_row)?;
        let mut out = Vec::new();
        for raw in rows {
            let (id, ts_ms, entry, _prev, hash) = decode_row(raw?)?;
            out.push(AuditRecord {
                id,
                ts_ms,
                entry,
                hash,
            });
        }
        Ok(out)
    }

    /// Recomputes the hash chain; false if any row was modified or deleted.
    pub fn verify_chain(&self) -> anyhow::Result<bool> {
        let conn = self.lock();
        let mut st = conn.prepare(&format!("SELECT {SELECT_COLS} FROM audit ORDER BY id ASC"))?;
        let rows = st.query_map([], read_row)?;
        let mut expected_prev = GENESIS_HASH.to_owned();
        for (expected_id, raw) in (1i64..).zip(rows) {
            let Ok((id, ts, entry, prev, hash)) = decode_row(raw?) else {
                return Ok(false);
            };
            if id != expected_id || prev != expected_prev {
                return Ok(false);
            }
            if compute_hash(&prev, &entry, ts)? != hash {
                return Ok(false);
            }
            expected_prev = hash;
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid redaction regex")
}

/// Ordered (kind, pattern) list: most specific first.
static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "private_key",
            re(
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
            ),
        ),
        ("anthropic_key", re(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
        (
            "openai_key",
            re(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}"),
        ),
        ("google_key", re(r"\bAIza[0-9A-Za-z_\-]{30,}")),
        (
            "github_token",
            re(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        ),
        ("aws_key", re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        (
            "jwt",
            re(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        ),
        (
            "email",
            re(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"),
        ),
    ]
});

static BEARER: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9\-._~+/]{8,}=*)"));

static KV_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)([A-Za-z0-9_\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_\-]*)(["']?\s*[:=]\s*["']?)([^\s"',;&}\]]+)"#,
    )
});

static HEX_BLOB: LazyLock<Regex> = LazyLock::new(|| re(r"\b[0-9a-fA-F]{40,}\b"));
static B64_BLOB: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9+/_\-]{40,}={0,2}"));

fn tag(kind: &str) -> String {
    format!("[REDACTED:{kind}]")
}

fn looks_like_b64_secret(s: &str) -> bool {
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if !(has_digit && has_upper && has_lower) {
        return false;
    }
    // File paths ("home/user/Projects/...") are not secrets: if slashes split the run
    // into short segments, keep it.
    if s.contains('/') {
        let longest = s.split('/').map(str::len).max().unwrap_or(0);
        if longest < 32 {
            return false;
        }
    }
    true
}

/// Mask secrets: API keys (sk-..., AIza..., ghp_...), bearer tokens, JWTs, private keys,
/// emails, long hex/base64 blobs, password=... pairs. Used before logging and before any cloud call.
pub fn redact(s: &str) -> String {
    let mut out = s.to_owned();
    // 1. Private key blocks first (they contain base64 that would otherwise be split up).
    for (kind, rx) in PATTERNS.iter() {
        if rx.is_match(&out) {
            out = rx.replace_all(&out, tag(kind).as_str()).into_owned();
        }
    }
    // 2. Authorization-style credentials: keep the scheme, mask the value.
    out = BEARER
        .replace_all(&out, |c: &Captures<'_>| {
            if c[3].starts_with("[REDACTED") || c[3].len() < 8 {
                c[0].to_owned()
            } else {
                format!("{}{}{}", &c[1], &c[2], tag("bearer"))
            }
        })
        .into_owned();
    // 3. key=value / "key": "value" pairs.
    out = KV_SECRET
        .replace_all(&out, |c: &Captures<'_>| {
            let v = &c[3];
            if v.starts_with("[REDACTED") {
                c[0].to_owned()
            } else {
                format!("{}{}{}", &c[1], &c[2], tag("secret"))
            }
        })
        .into_owned();
    // 4. Long opaque blobs.
    out = HEX_BLOB.replace_all(&out, tag("hex").as_str()).into_owned();
    out = B64_BLOB
        .replace_all(&out, |c: &Captures<'_>| {
            if looks_like_b64_secret(&c[0]) {
                tag("base64")
            } else {
                c[0].to_owned()
            }
        })
        .into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(args: &str) -> AuditEntry {
        AuditEntry {
            actor: "phone:pixel".into(),
            tool: "fs.read".into(),
            args: args.into(),
            result: "ok".into(),
            risk: RiskTier::Read,
            brain: Brain::Rules,
        }
    }

    #[test]
    fn append_recent_verify() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.verify_chain().unwrap(), "empty chain is valid");
        for i in 0..5 {
            let id = log
                .append(&entry(&format!("path=Documents/{i}.txt")))
                .unwrap();
            assert_eq!(id, i + 1);
        }
        let r = log.recent(3).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].id, 5);
        assert_eq!(r[0].entry.args, "path=Documents/4.txt");
        assert_eq!(r[0].hash.len(), 64);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn update_and_delete_are_blocked() {
        let log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a")).unwrap();
        let c = log.lock();
        assert!(
            c.execute("UPDATE audit SET args='x' WHERE id=1", [])
                .is_err()
        );
        assert!(c.execute("DELETE FROM audit WHERE id=1", []).is_err());
        drop(c);
        assert!(log.verify_chain().unwrap());
    }

    fn drop_triggers(log: &AuditLog) {
        log.lock()
            .execute_batch("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")
            .unwrap();
    }

    #[test]
    fn verify_detects_edit() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&entry("a")).unwrap();
        }
        drop_triggers(&log);
        log.lock()
            .execute("UPDATE audit SET result='forged' WHERE id=2", [])
            .unwrap();
        assert!(!log.verify_chain().unwrap());
    }

    #[test]
    fn verify_detects_edit_with_recomputed_hash() {
        let log = AuditLog::open_in_memory().unwrap();
        for _ in 0..3 {
            log.append(&entry("a")).unwrap();
        }
        drop_triggers(&log);
        // Attacker rewrites row 2 and fixes its own hash, but row 3's prev_hash breaks.
        let c = log.lock();
        let prev: String = c
            .query_row("SELECT prev_hash FROM audit WHERE id=2", [], |r| r.get(0))
            .unwrap();
        let ts: i64 = c
            .query_row("SELECT ts_ms FROM audit WHERE id=2", [], |r| r.get(0))
            .unwrap();
        let mut forged = entry("a");
        forged.result = "forged".into();
        let h = compute_hash(&prev, &forged, ts as u64).unwrap();
        c.execute(
            "UPDATE audit SET result='forged', hash=?1 WHERE id=2",
            params![h],
        )
        .unwrap();
        drop(c);
        assert!(!log.verify_chain().unwrap());
    }

    #[test]
    fn verify_detects_delete() {
        for victim in [1, 2] {
            let log = AuditLog::open_in_memory().unwrap();
            for _ in 0..3 {
                log.append(&entry("a")).unwrap();
            }
            drop_triggers(&log);
            log.lock()
                .execute("DELETE FROM audit WHERE id=?1", [victim])
                .unwrap();
            assert!(!log.verify_chain().unwrap(), "delete of row {victim}");
        }
    }

    #[test]
    fn append_redacts_and_truncates() {
        let log = AuditLog::open_in_memory().unwrap();
        let mut e = entry("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz");
        e.result = "é".repeat(5000);
        log.append(&e).unwrap();
        let r = &log.recent(1).unwrap()[0];
        assert!(!r.entry.args.contains("sk-ant-api03"), "{}", r.entry.args);
        assert!(r.entry.args.contains("[REDACTED:anthropic_key]"));
        assert!(r.entry.result.len() <= MAX_FIELD_BYTES);
        assert!(r.entry.result.ends_with("[truncated]"));
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn file_db_persists_with_wal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/audit.db");
        {
            let log = AuditLog::open(&p).unwrap();
            log.append(&entry("a")).unwrap();
            let mode: String = log
                .lock()
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode.to_lowercase(), "wal");
        }
        let log = AuditLog::open(&p).unwrap();
        log.append(&entry("b")).unwrap();
        assert_eq!(log.recent(10).unwrap().len(), 2);
        assert!(log.verify_chain().unwrap());
    }

    fn assert_redacted(input: &str, kind: &str, secret: &str) {
        let out = redact(input);
        assert!(
            out.contains(&format!("[REDACTED:{kind}]")),
            "expected {kind} in {out:?}"
        );
        assert!(!out.contains(secret), "secret leaked: {out:?}");
    }

    #[test]
    fn redacts_api_keys() {
        let k = "sk-ant-api03-AbCdEf0123456789_-xyzXYZ0123456789";
        assert_redacted(&format!("use {k} now"), "anthropic_key", k);
        let k = "sk-proj-AbCdEf0123456789abcdefABCDEF";
        assert_redacted(&format!("OPENAI={k}"), "openai_key", "AbCdEf0123456789");
        let k = "sk-AbCdEf0123456789abcdefABCDEF";
        assert_redacted(k, "openai_key", k);
        let k = "AIzaSyA1234567890abcdefghijklmnopqrstu";
        assert_redacted(&format!("k={k}&x"), "google_key", k);
        let k = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        assert_redacted(k, "github_token", k);
        let k = "gho_abcdefghijklmnopqrstuvwxyz0123456789";
        assert_redacted(k, "github_token", k);
        let k = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz";
        assert_redacted(k, "github_token", k);
        let k = "AKIAIOSFODNN7EXAMPLE";
        assert_redacted(&format!("aws {k} key"), "aws_key", k);
    }

    #[test]
    fn redacts_tokens_and_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_redacted(&format!("cookie: {jwt}"), "jwt", "dozjgNryP4J3");
        let out = redact("Authorization: Bearer abc123def456ghi789");
        assert_eq!(out, "Authorization: Bearer [REDACTED:bearer]");
        let out = redact(&format!("Authorization: Bearer {jwt}"));
        assert!(!out.contains("eyJ"), "{out}");
    }

    #[test]
    fn redacts_private_keys() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\nabc\n-----END RSA PRIVATE KEY-----";
        let out = redact(&format!("before\n{pem}\nafter"));
        assert_eq!(out, "before\n[REDACTED:private_key]\nafter");
        let out = redact("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n");
        assert_eq!(out, "[REDACTED:private_key]");
    }

    #[test]
    fn redacts_emails_and_pairs() {
        assert_redacted("mail alice.smith+x@example.co.uk ok", "email", "alice");
        for s in [
            "password=hunter2",
            "passwd: hunter2",
            r#"{"api_key": "hunter2"}"#,
            "DB_SECRET='hunter2'",
            "access_token=hunter2&x=1",
            "API-KEY = hunter2",
        ] {
            assert_redacted(s, "secret", "hunter2");
        }
        assert_eq!(
            redact("password=hunter2 user=bob"),
            "password=[REDACTED:secret] user=bob"
        );
    }

    #[test]
    fn redacts_blobs_but_not_paths() {
        let hex = "a".repeat(20) + &"0123456789abcdef".repeat(2);
        assert_redacted(&format!("sha {hex}"), "hex", &hex);
        let b64 = "QWxhZGRpbjpvcGVuIHNlc2FtZQ1234567890ABCDEFabcdef==";
        assert_redacted(&format!("blob {b64}"), "base64", "QWxhZGRpbjpv");
        // Paths, prose, short ids stay intact.
        for s in [
            "/home/zxnj/Projects/AutoPilot/target/agents/support/debug",
            "Documents/Reports2025/QuarterlyReview/Final-v2.pdf",
            "open the file report.txt and summarise it",
            "transfer 3f2a",
            "uuid 550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert_eq!(redact(s), s);
        }
    }

    #[test]
    fn redact_is_idempotent() {
        let s = "password=sk-ant-api03-abcdefghijklmnopqrstuvwxyz and bob@example.com";
        let once = redact(s);
        assert_eq!(redact(&once), once);
        assert!(!once.contains("abcdefghij"));
    }
}
