//! Shared HTTP plumbing: client construction, retry with backoff, SSE and NDJSON framing.
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures_util::StreamExt;

/// Connect timeout for every provider.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request timeout (including streaming body) for every provider.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Build the one `reqwest::Client` a provider shares across calls (keeps the TLS/HTTP2
/// connection pool warm, which is the biggest latency win after the first request).
pub fn build_client(connect: Duration, total: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(connect)
        .timeout(total)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .user_agent(concat!("autopilot-agent-llm/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

pub fn default_client() -> reqwest::Client {
    build_client(CONNECT_TIMEOUT, TOTAL_TIMEOUT)
}

/// Retry policy: `retries` extra attempts on 429 / 5xx / connect errors.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub retries: u32,
    /// First backoff; doubles per attempt. `retry-after` (seconds) is honoured, capped at `max`.
    pub base: Duration,
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            retries: 2,
            base: Duration::from_millis(400),
            max: Duration::from_secs(8),
        }
    }
}

impl RetryPolicy {
    pub fn backoff(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let exp = self.base.saturating_mul(1u32 << attempt.min(16));
        retry_after.unwrap_or(exp).min(self.max)
    }
}

pub fn is_retryable_status(s: reqwest::StatusCode) -> bool {
    s == reqwest::StatusCode::TOO_MANY_REQUESTS || s.is_server_error()
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|s| s.is_finite() && *s >= 0.0)
        .map(Duration::from_secs_f64)
}

/// Send a request built by `make` (called once per attempt), retrying per `policy`.
/// Returns the successful response, or an error carrying status + (truncated) body.
/// The body of an error response is included because providers put the reason there; request
/// headers (API keys) are never included in errors.
pub async fn send_with_retry<F>(
    policy: RetryPolicy,
    label: &str,
    make: F,
) -> anyhow::Result<reqwest::Response>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut attempt = 0u32;
    loop {
        match make().send().await {
            Ok(resp) if resp.status().is_success() => return Ok(resp),
            Ok(resp) => {
                let status = resp.status();
                if is_retryable_status(status) && attempt < policy.retries {
                    let wait = policy.backoff(attempt, retry_after(&resp));
                    tracing::debug!(%status, attempt, ?wait, "{label}: retrying");
                    drop(resp);
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                    continue;
                }
                let body = resp.text().await.unwrap_or_default();
                let body: String = body.chars().take(800).collect();
                return Err(anyhow!("{label}: HTTP {status}: {body}"));
            }
            Err(e) if e.is_connect() && attempt < policy.retries => {
                let wait = policy.backoff(attempt, None);
                tracing::debug!(attempt, ?wait, "{label}: connect error, retrying");
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
            Err(e) => return Err(anyhow!("{label}: request failed: {}", e.without_url())),
        }
    }
}

/// Incremental line splitter over a byte stream (handles chunk boundaries inside UTF-8
/// sequences and `\r\n`).
#[derive(Default)]
pub struct LineBuf {
    buf: Vec<u8>,
}

impl LineBuf {
    pub fn push(&mut self, chunk: &[u8], mut on_line: impl FnMut(&str)) {
        self.buf.extend_from_slice(chunk);
        let mut start = 0;
        while let Some(pos) = self.buf[start..].iter().position(|&b| b == b'\n') {
            let end = start + pos;
            let mut line = &self.buf[start..end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            on_line(&String::from_utf8_lossy(line));
            start = end + 1;
        }
        self.buf.drain(..start);
    }

    /// Flush a trailing line with no newline.
    pub fn finish(&mut self, mut on_line: impl FnMut(&str)) {
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let s = String::from_utf8_lossy(&rest);
            on_line(s.trim_end_matches('\r'));
        }
    }
}

/// Server-Sent Events parser: yields the `data:` payload of each event (multi-line data joined
/// with `\n`). Comments and `event:`/`id:` fields are ignored (the JSON carries its own type).
#[derive(Default)]
pub struct SseParser {
    lines: LineBuf,
    data: String,
    has_data: bool,
}

impl SseParser {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let (data, has) = (&mut self.data, &mut self.has_data);
        self.lines
            .push(chunk, |line| sse_line(line, data, has, &mut out));
        out
    }

    pub fn finish(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let (data, has) = (&mut self.data, &mut self.has_data);
        self.lines
            .finish(|line| sse_line(line, data, has, &mut out));
        if self.has_data {
            out.push(std::mem::take(&mut self.data));
            self.has_data = false;
        }
        out
    }
}

fn sse_line(line: &str, data: &mut String, has: &mut bool, out: &mut Vec<String>) {
    if line.is_empty() {
        if *has {
            out.push(std::mem::take(data));
            *has = false;
        }
        return;
    }
    if line.starts_with(':') {
        return;
    }
    let (field, value) = match line.split_once(':') {
        Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
        None => (line, ""),
    };
    if field == "data" {
        if *has {
            data.push('\n');
        }
        data.push_str(value);
        *has = true;
    }
}

/// Drive an SSE response, handing every parsed JSON `data:` payload to `on_json`.
/// `[DONE]` sentinels (OpenAI) are skipped.
pub async fn for_each_sse_json(
    resp: reqwest::Response,
    mut on_json: impl FnMut(serde_json::Value) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut parser = SseParser::default();
    let mut stream = resp.bytes_stream();
    let mut handle = |payloads: Vec<String>| -> anyhow::Result<()> {
        for p in payloads {
            let p = p.trim();
            if p.is_empty() || p == "[DONE]" {
                continue;
            }
            let v: serde_json::Value =
                serde_json::from_str(p).with_context(|| "invalid JSON in SSE event")?;
            on_json(v)?;
        }
        Ok(())
    };
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("stream read failed: {}", e.without_url()))?;
        handle(parser.push(&chunk))?;
    }
    handle(parser.finish())
}

/// Drive an NDJSON response (Ollama), one JSON object per line.
pub async fn for_each_ndjson(
    resp: reqwest::Response,
    mut on_json: impl FnMut(serde_json::Value) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut lines = LineBuf::default();
    let mut stream = resp.bytes_stream();
    let mut pending: Vec<String> = Vec::new();
    let mut run = |pending: &mut Vec<String>| -> anyhow::Result<()> {
        for l in pending.drain(..) {
            if l.trim().is_empty() {
                continue;
            }
            on_json(serde_json::from_str(&l).context("invalid NDJSON line")?)?;
        }
        Ok(())
    };
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("stream read failed: {}", e.without_url()))?;
        lines.push(&chunk, |l| pending.push(l.to_owned()));
        run(&mut pending)?;
    }
    lines.finish(|l| pending.push(l.to_owned()));
    run(&mut pending)
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_splits_events_across_chunks() {
        let mut p = SseParser::default();
        let mut got = p.push(b"event: a\ndata: {\"x\":");
        assert!(got.is_empty());
        got.extend(p.push(b"1}\r\n\r\n: comment\n\ndata: line1\ndata: line2\n\n"));
        got.extend(p.push(b"data: tail"));
        got.extend(p.finish());
        assert_eq!(got, vec!["{\"x\":1}", "line1\nline2", "tail"]);
    }

    #[test]
    fn linebuf_handles_utf8_split() {
        let mut lb = LineBuf::default();
        let s = "héllo\nwörld\n".as_bytes();
        let mut out = Vec::new();
        lb.push(&s[..2], |l| out.push(l.to_owned()));
        lb.push(&s[2..], |l| out.push(l.to_owned()));
        assert_eq!(out, vec!["héllo", "wörld"]);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let p = RetryPolicy {
            retries: 2,
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(p.backoff(0, None), Duration::from_millis(100));
        assert_eq!(p.backoff(1, None), Duration::from_millis(200));
        assert_eq!(p.backoff(5, None), Duration::from_secs(1));
        assert_eq!(
            p.backoff(0, Some(Duration::from_secs(30))),
            Duration::from_secs(1)
        );
    }
}
