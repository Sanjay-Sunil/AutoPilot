//! MCP (Model Context Protocol) client: newline-delimited JSON-RPC 2.0 over a child process's
//! stdio. [`Server`] starts the process on first use, stops it after an idle period, and caches
//! the tool list on disk so the agent can register tools at startup without spawning anything.
//!
//! Everything a server returns (tool names, descriptions, schemas, results) is untrusted; policy
//! (which tools exist, their risk tier) is decided by the caller, not here.
use anyhow::{Context, anyhow, bail};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_LINE: usize = 16 << 20;
const MAX_PAGES: usize = 20;

/// Environment passed through to servers; everything else (API keys of other providers,
/// tokens) is withheld. Per-server variables come from the config.
pub const PASS_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Annotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "inputSchema", default = "empty_schema")]
    pub input_schema: Value,
    #[serde(default)]
    pub annotations: Annotations,
}

fn empty_schema() -> Value {
    json!({ "type": "object" })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    Text(String),
    /// Base64 data as sent by the server.
    Image {
        data: String,
        mime: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub content: Vec<Content>,
    pub is_error: bool,
}

impl CallResult {
    fn parse(v: &Value) -> Self {
        let mut content = vec![];
        for c in v["content"].as_array().into_iter().flatten() {
            let s = |k: &str| c[k].as_str().unwrap_or_default().to_string();
            match c["type"].as_str() {
                Some("text") => content.push(Content::Text(s("text"))),
                Some("image") => content.push(Content::Image {
                    data: s("data"),
                    mime: s("mimeType"),
                }),
                Some("resource") => {
                    let r = &c["resource"];
                    let t = r["text"].as_str().map(str::to_string).unwrap_or_else(|| {
                        format!("[resource {}]", r["uri"].as_str().unwrap_or("?"))
                    });
                    content.push(Content::Text(t));
                }
                Some("resource_link") => {
                    content.push(Content::Text(format!("[link {}]", s("uri"))))
                }
                Some(other) => content.push(Content::Text(format!("[{other} content omitted]"))),
                None => {}
            }
        }
        if content.is_empty()
            && let Some(sc) = v.get("structuredContent")
        {
            content.push(Content::Text(sc.to_string()));
        }
        Self {
            content,
            is_error: v["isError"].as_bool().unwrap_or(false),
        }
    }

    /// All text parts joined with newlines.
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                Content::Text(t) => Some(t.as_str()),
                Content::Image { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// How to start a stdio server.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;
type Writer = Arc<tokio::sync::Mutex<Pin<Box<dyn AsyncWrite + Send>>>>;

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One live JSON-RPC session. Dropping it closes the server's stdin, then kills the process.
pub struct Connection {
    writer: Writer,
    pending: Pending,
    next_id: AtomicU64,
    closed: Arc<AtomicBool>,
    _reader: AbortOnDrop,
    _child: Option<Child>,
}

async fn write_msg(w: &Writer, msg: &Value) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    let mut w = w.lock().await;
    w.write_all(&line).await?;
    w.flush().await?;
    Ok(())
}

impl Connection {
    pub fn spawn(l: &Launch) -> anyhow::Result<Self> {
        let mut cmd = Command::new(&l.command);
        cmd.args(&l.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for k in PASS_ENV {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        cmd.envs(l.env.iter().map(|(k, v)| (k, v)));
        if let Some(d) = &l.cwd {
            cmd.current_dir(d);
        }
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting MCP server `{}`", l.command))?;
        let stdin = child.stdin.take().context("no stdin")?;
        let stdout = child.stdout.take().context("no stdout")?;
        if let Some(err) = child.stderr.take() {
            let cmd = l.command.clone();
            tokio::spawn(async move {
                let mut lines = FramedRead::new(err, LinesCodec::new_with_max_length(4096));
                while let Some(l) = lines.next().await {
                    if let Ok(l) = l {
                        tracing::debug!(server = %cmd, "stderr: {l}");
                    }
                }
            });
        }
        Ok(Self::over(stdout, stdin, Some(child)))
    }

    /// A session over arbitrary streams (tests, other transports).
    pub fn over<R, W>(read: R, write: W, child: Option<Child>) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + 'static,
    {
        let writer: Writer = Arc::new(tokio::sync::Mutex::new(Box::pin(write)));
        let pending: Pending = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let reader = tokio::spawn(read_loop(
            read,
            writer.clone(),
            pending.clone(),
            closed.clone(),
        ));
        Self {
            writer,
            pending,
            next_id: AtomicU64::new(1),
            closed,
            _reader: AbortOnDrop(reader),
            _child: child,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub async fn notify(&self, method: &str, params: Value) -> anyhow::Result<()> {
        write_msg(
            &self.writer,
            &json!({ "jsonrpc": "2.0", "method": method, "params": params }),
        )
        .await
    }

    /// Send a request and wait for its result. If the future is dropped (kill switch) or times
    /// out, the server is told to cancel it.
    pub async fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        if self.is_closed() {
            bail!("MCP server has exited");
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let mut guard = Inflight {
            id,
            pending: self.pending.clone(),
            writer: self.writer.clone(),
            cancel: method != "initialize",
            done: false,
        };
        write_msg(
            &self.writer,
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        )
        .await?;
        let r = tokio::time::timeout(timeout, rx).await;
        match r {
            Ok(Ok(Ok(v))) => {
                guard.done = true;
                Ok(v)
            }
            Ok(Ok(Err(e))) => {
                guard.done = true;
                Err(anyhow!("{method} failed: {e}"))
            }
            Ok(Err(_)) => {
                guard.done = true;
                Err(anyhow!("MCP server exited during {method}"))
            }
            Err(_) => Err(anyhow!("{method} timed out after {}s", timeout.as_secs())),
        }
    }

    pub async fn initialize(&self, timeout: Duration) -> anyhow::Result<Value> {
        let r = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "autopilot", "version": env!("CARGO_PKG_VERSION") },
                }),
                timeout,
            )
            .await?;
        if r.get("protocolVersion").and_then(Value::as_str).is_none() {
            bail!("invalid initialize result");
        }
        self.notify("notifications/initialized", json!({})).await?;
        Ok(r)
    }

    pub async fn list_tools(&self, timeout: Duration) -> anyhow::Result<Vec<McpTool>> {
        let mut out = vec![];
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => json!({}),
            };
            let r = self.request("tools/list", params, timeout).await?;
            for t in r["tools"].as_array().into_iter().flatten() {
                match serde_json::from_value::<McpTool>(t.clone()) {
                    Ok(t) => out.push(t),
                    Err(e) => tracing::warn!("skipping malformed MCP tool: {e}"),
                }
            }
            cursor = r["nextCursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> anyhow::Result<CallResult> {
        let r = self
            .request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
                timeout,
            )
            .await?;
        Ok(CallResult::parse(&r))
    }
}

struct Inflight {
    id: u64,
    pending: Pending,
    writer: Writer,
    cancel: bool,
    done: bool,
}

impl Drop for Inflight {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.pending.lock().unwrap().remove(&self.id);
        if self.cancel
            && let Ok(h) = tokio::runtime::Handle::try_current()
        {
            let (w, id) = (self.writer.clone(), self.id);
            h.spawn(async move {
                let msg = json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": { "requestId": id, "reason": "cancelled by user" } });
                let _ = write_msg(&w, &msg).await;
            });
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    read: R,
    writer: Writer,
    pending: Pending,
    closed: Arc<AtomicBool>,
) {
    let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_LINE));
    while let Some(line) = lines.next().await {
        let line = match line {
            Ok(l) => l,
            Err(LinesCodecError::MaxLineLengthExceeded) => {
                tracing::warn!("MCP message over {MAX_LINE} bytes dropped");
                continue;
            }
            Err(e) => {
                tracing::debug!("MCP read error: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            tracing::debug!("non-JSON line from MCP server ignored");
            continue;
        };
        match (msg.get("method").and_then(Value::as_str), msg.get("id")) {
            // Server -> client request. We offer no client capabilities except ping.
            (Some(method), Some(id)) => {
                let reply = if method == "ping" {
                    json!({ "jsonrpc": "2.0", "id": id, "result": {} })
                } else {
                    json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": "method not supported" } })
                };
                let _ = write_msg(&writer, &reply).await;
            }
            (Some(method), None) => tracing::debug!("MCP notification {method}"),
            (None, Some(id)) => {
                let Some(id) = id.as_u64() else { continue };
                let Some(tx) = pending.lock().unwrap().remove(&id) else {
                    continue;
                };
                let r = match msg.get("error") {
                    Some(e) => Err(e["message"].as_str().unwrap_or("error").to_string()),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = tx.send(r);
            }
            (None, None) => {}
        }
    }
    closed.store(true, Ordering::Release);
    // Dropping the senders wakes every waiter with "server exited".
    pending.lock().unwrap().clear();
}

pub type Connector = Arc<dyn Fn() -> anyhow::Result<Connection> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub start_timeout: Duration,
    pub call_timeout: Duration,
    /// Stop the process after this long without calls.
    pub idle: Duration,
    /// Where to cache the tool list (JSON).
    pub cache: Option<PathBuf>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            start_timeout: Duration::from_secs(20),
            call_timeout: Duration::from_secs(60),
            idle: Duration::from_secs(300),
            cache: None,
        }
    }
}

/// A lazily started, idle-stopped MCP server.
pub struct Server {
    pub name: String,
    connector: Connector,
    opts: ServerOptions,
    conn: tokio::sync::Mutex<Option<(u64, Arc<Connection>)>>,
    generation: AtomicU64,
    epoch: Instant,
    last_used_ms: AtomicU64,
    inflight: AtomicUsize,
}

struct Busy<'a>(&'a Server);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.touch();
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Server {
    pub fn new(name: impl Into<String>, launch: Launch, opts: ServerOptions) -> Arc<Self> {
        Self::with_connector(name, Arc::new(move || Connection::spawn(&launch)), opts)
    }

    pub fn with_connector(
        name: impl Into<String>,
        connector: Connector,
        opts: ServerOptions,
    ) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            connector,
            opts,
            conn: tokio::sync::Mutex::new(None),
            generation: AtomicU64::new(0),
            epoch: Instant::now(),
            last_used_ms: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
        })
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn touch(&self) {
        self.last_used_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    pub async fn is_running(&self) -> bool {
        matches!(self.conn.lock().await.as_ref(), Some((_, c)) if !c.is_closed())
    }

    async fn connection(self: &Arc<Self>) -> anyhow::Result<Arc<Connection>> {
        let mut g = self.conn.lock().await;
        if let Some((_, c)) = g.as_ref()
            && !c.is_closed()
        {
            return Ok(c.clone());
        }
        let c = Arc::new((self.connector)()?);
        c.initialize(self.opts.start_timeout)
            .await
            .with_context(|| format!("initializing MCP server {}", self.name))?;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *g = Some((generation, c.clone()));
        tracing::info!(server = %self.name, "MCP server started");
        self.touch();
        self.spawn_reaper(generation);
        if let Some(path) = self.opts.cache.clone() {
            let (c2, t) = (c.clone(), self.opts.call_timeout);
            tokio::spawn(async move {
                if let Ok(tools) = c2.list_tools(t).await {
                    let _ = write_cache(&path, &tools);
                }
            });
        }
        Ok(c)
    }

    fn spawn_reaper(self: &Arc<Self>, generation: u64) {
        let weak = Arc::downgrade(self);
        let tick = (self.opts.idle / 4).max(Duration::from_millis(50));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tick).await;
                let Some(s) = weak.upgrade() else { return };
                let mut g = s.conn.lock().await;
                match g.as_ref() {
                    Some((gn, _)) if *gn != generation => return,
                    None => return,
                    Some((_, c)) if c.is_closed() => {
                        *g = None;
                        return;
                    }
                    _ => {}
                }
                let idle_ms = s.now_ms() - s.last_used_ms.load(Ordering::Relaxed);
                if s.inflight.load(Ordering::Acquire) == 0
                    && idle_ms >= s.opts.idle.as_millis() as u64
                {
                    tracing::info!(server = %s.name, "stopping idle MCP server");
                    *g = None;
                    return;
                }
            }
        });
    }

    /// Fetch the tool list from the (started) server and refresh the cache.
    pub async fn list_tools(self: &Arc<Self>) -> anyhow::Result<Vec<McpTool>> {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        let _busy = Busy(self);
        let c = self.connection().await?;
        let tools = c.list_tools(self.opts.call_timeout).await?;
        if let Some(p) = &self.opts.cache
            && let Err(e) = write_cache(p, &tools)
        {
            tracing::warn!(server = %self.name, "cannot cache MCP tool list: {e}");
        }
        Ok(tools)
    }

    /// Cached tool list, if any (no process is started).
    pub fn cached_tools(&self) -> Option<Vec<McpTool>> {
        let p = self.opts.cache.as_ref()?;
        serde_json::from_slice(&std::fs::read(p).ok()?).ok()
    }

    pub async fn call(
        self: &Arc<Self>,
        tool: &str,
        arguments: Value,
    ) -> anyhow::Result<CallResult> {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        let _busy = Busy(self);
        let c = self.connection().await?;
        c.call_tool(tool, arguments, self.opts.call_timeout).await
    }

    pub async fn shutdown(&self) {
        *self.conn.lock().await = None;
    }
}

fn write_cache(path: &Path, tools: &[McpTool]) -> anyhow::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    // Unique temp name: the background refresh and list_tools may write concurrently.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}.{n}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(tools)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests;
