//! Configuration from environment variables.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// `BIND`, default `0.0.0.0:8080`.
    pub bind: String,
    /// `DATABASE_URL` (optional; only used with the `db` feature).
    pub database_url: Option<String>,
    /// `RELAY_IDLE_SECS`, default 120. Connection closed when no frame arrives for this long.
    pub idle_timeout: Duration,
    /// `RELAY_MAX_FRAME`, default 70_000 bytes. Larger frames are dropped and the socket closed.
    pub max_frame: usize,
    /// `RATE_LIMIT_PER_MIN`, default 30 new WS connections per IP per minute.
    pub rate_per_min: u32,
    /// `RATE_LIMIT_BURST`, default 10.
    pub rate_burst: u32,
    /// `MAX_ROOMS`, default 10_000 concurrent rooms.
    pub max_rooms: usize,
    /// `TRUST_FORWARDED=1`: take the client IP from the right-most `X-Forwarded-For` entry
    /// (only enable behind a trusted reverse proxy such as the bundled Caddy).
    pub trust_forwarded: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".into(),
            database_url: None,
            idle_timeout: Duration::from_secs(120),
            max_frame: 70_000,
            rate_per_min: 30,
            rate_burst: 10,
            max_rooms: 10_000,
            trust_forwarded: false,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let d = Self::default();
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let num = |k: &str| get(k).and_then(|v| v.parse::<u64>().ok());
        Self {
            bind: get("BIND").unwrap_or(d.bind),
            database_url: get("DATABASE_URL"),
            idle_timeout: num("RELAY_IDLE_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.idle_timeout),
            max_frame: num("RELAY_MAX_FRAME")
                .map(|v| v as usize)
                .unwrap_or(d.max_frame),
            rate_per_min: num("RATE_LIMIT_PER_MIN")
                .map(|v| v as u32)
                .unwrap_or(d.rate_per_min),
            rate_burst: num("RATE_LIMIT_BURST")
                .map(|v| v as u32)
                .unwrap_or(d.rate_burst),
            max_rooms: num("MAX_ROOMS").map(|v| v as usize).unwrap_or(d.max_rooms),
            trust_forwarded: matches!(
                get("TRUST_FORWARDED").as_deref(),
                Some("1" | "true" | "yes")
            ),
        }
    }
}
