//! Append-only, hash-chained audit log (SQLite) + redaction helper.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{Brain, RiskTier};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

pub struct AuditLog {/* rusqlite connection behind a Mutex */}

impl AuditLog {
    pub fn open(_path: &Path) -> anyhow::Result<Self> { todo!() }
    pub fn open_in_memory() -> anyhow::Result<Self> { todo!() }
    pub fn append(&self, _e: &AuditEntry) -> anyhow::Result<i64> { todo!() }
    pub fn recent(&self, _n: usize) -> anyhow::Result<Vec<AuditRecord>> { todo!() }
    /// Recomputes the hash chain; false if any row was modified or deleted.
    pub fn verify_chain(&self) -> anyhow::Result<bool> { todo!() }
}

/// Mask secrets: API keys (sk-..., AIza..., ghp_...), bearer tokens, JWTs, private keys,
/// emails, long hex/base64 blobs, password=... pairs. Used before logging and before any cloud call.
pub fn redact(_s: &str) -> String { todo!() }
