//! The agent: decision layer (rules fast path -> Laya -> cloud LLM), policy/router, tool registry,
//! approvals with risk tiers, kill switch, task updates, audit.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::Message;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::mpsc;

pub mod approvals;
pub mod config;
pub mod memory;
pub mod router;
pub mod rules;
pub mod screen;
pub(crate) mod task;
pub mod tools;
pub mod transfer;

use agent_audit::AuditEntry;
use agent_files::{FileReceiver, SharedRoots};
use agent_llm::{LayaDecision, LlmProvider};
use agent_protocol::{
    Brain, ErrorMsg, FileAccept, FileOffer, Notify, NotifyLevel, RiskTier, ScreenAction,
    ScreenState,
};
use approvals::{Approvals, Ask};
use async_trait::async_trait;
use config::Policy;
use screen::{CaptureSource, ScreenCtl};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tools::ToolRegistry;
use transfer::Transfers;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub data_dir: PathBuf,
    /// (name, path) shared roots.
    pub shared_roots: Vec<(String, PathBuf)>,
    pub laya_url: String,
    pub ollama_url: Option<String>,
    pub ollama_model: Option<String>,
    pub cloud_enabled: bool,
    pub cloud_allow_high_sensitivity: bool,
    /// "claude" | "openai" | "gemini"
    pub preferred_cloud: String,
    pub claude_model: Option<String>,
    pub openai_model: Option<String>,
    pub gemini_model: Option<String>,
    /// Program names allowed for `shell.run` without destructive tier.
    pub shell_allowlist: Vec<String>,
    pub approval_timeout_secs: u64,
    pub max_agent_steps: usize,
    /// Max time to wait for Laya's decision before using keyword heuristics.
    pub laya_timeout_ms: u64,
    /// MCP plugin servers (`[[mcp_servers]]`).
    pub mcp_servers: Vec<tools::mcp::McpServerConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        config::default_config()
    }
}

pub type Redactor = Arc<dyn Fn(&str) -> String + Send + Sync>;
pub type Notifier = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Local decision model (Laya). Behind a trait so tests and alternative deciders can plug in.
#[async_trait]
pub trait Decider: Send + Sync {
    async fn decide(&self, text: &str) -> anyhow::Result<LayaDecision>;
}

#[async_trait]
impl Decider for agent_llm::LayaClient {
    async fn decide(&self, text: &str) -> anyhow::Result<LayaDecision> {
        agent_llm::LayaClient::decide(self, text).await
    }
}

pub trait AuditSink: Send + Sync {
    fn append(&self, e: &AuditEntry);
}

impl AuditSink for agent_audit::AuditLog {
    fn append(&self, e: &AuditEntry) {
        if let Err(err) = agent_audit::AuditLog::append(self, e) {
            tracing::error!("audit append failed: {err}");
        }
    }
}

/// Everything the agent depends on, injectable for tests ([`Agent::with_parts`]).
pub struct Parts {
    pub tools: ToolRegistry,
    pub decider: Option<Arc<dyn Decider>>,
    /// Cloud providers that have API keys.
    pub cloud: Vec<Arc<dyn LlmProvider>>,
    /// Local LLM (Ollama), if configured.
    pub local: Option<Arc<dyn LlmProvider>>,
    pub audit: Arc<dyn AuditSink>,
    pub redact: Redactor,
    pub capture: Arc<CaptureSource>,
    /// Desktop notification on the laptop (title, body).
    pub notifier: Notifier,
    pub roots: Option<Arc<SharedRoots>>,
}

pub(crate) struct Inner {
    pub(crate) cfg: AgentConfig,
    pub(crate) policy: RwLock<Policy>,
    pub(crate) parts: Parts,
    pub(crate) approvals: Approvals,
    root: Mutex<CancellationToken>,
    pub(crate) screen: Arc<ScreenCtl>,
    outs: Mutex<Vec<mpsc::Sender<Message>>>,
    pub(crate) laya_down_until: AtomicU64,
    pub(crate) system_prompt: String,
    transfers: Transfers,
    pub(crate) memory: memory::Memory,
}

impl Inner {
    pub(crate) fn root_token(&self) -> CancellationToken {
        self.root.lock().unwrap().clone()
    }

    fn audit(&self, actor: &str, tool: &str, args: &str, result: &str, risk: RiskTier) {
        self.parts.audit.append(&AuditEntry {
            actor: actor.to_string(),
            tool: tool.to_string(),
            args: (self.parts.redact)(args),
            result: (self.parts.redact)(result),
            risk,
            brain: Brain::Rules,
        });
    }
}

/// Handle to the running agent; cheap to clone.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

impl Agent {
    pub async fn new(cfg: AgentConfig) -> anyhow::Result<Self> {
        std::fs::create_dir_all(cfg.data_dir.join("inbox"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cfg.data_dir, std::fs::Permissions::from_mode(0o700));
        }
        let audit = agent_audit::AuditLog::open(&cfg.data_dir.join("audit.sqlite"))?;
        let roots = Arc::new(SharedRoots::new(cfg.shared_roots.clone()));
        let capture = Arc::new(CaptureSource::detect());
        let mut tools = tools::builtin::registry(tools::builtin::BuiltinCtx {
            roots: Some(roots.clone()),
            data_dir: cfg.data_dir.clone(),
            shell_allowlist: cfg.shell_allowlist.clone(),
            capture: capture.clone(),
        });
        // Tool closures hold the servers; processes start lazily and stop when idle.
        let plugins = tools::mcp::register(&mut tools, &cfg.mcp_servers, &cfg.data_dir).await;
        let mut cloud: Vec<Arc<dyn LlmProvider>> = vec![];
        if let Some(k) = agent_llm::api_key("claude") {
            cloud.push(Arc::new(agent_llm::ClaudeProvider::new(
                k,
                cfg.claude_model.clone(),
            )));
        }
        if let Some(k) = agent_llm::api_key("openai") {
            cloud.push(Arc::new(agent_llm::OpenAiProvider::new(
                k,
                cfg.openai_model.clone(),
            )));
        }
        if let Some(k) = agent_llm::api_key("gemini") {
            cloud.push(Arc::new(agent_llm::GeminiProvider::new(
                k,
                cfg.gemini_model.clone(),
            )));
        }
        let local: Option<Arc<dyn LlmProvider>> = match (&cfg.ollama_url, &cfg.ollama_model) {
            (Some(u), Some(m)) => Some(Arc::new(agent_llm::OllamaProvider::new(
                u.clone(),
                m.clone(),
            ))),
            _ => None,
        };
        tracing::info!(
            cloud = cloud.len(),
            local = local.is_some(),
            tools = tools.len(),
            plugins = plugins.len(),
            "agent ready"
        );
        let parts = Parts {
            tools,
            decider: Some(Arc::new(agent_llm::LayaClient::new(cfg.laya_url.clone()))),
            cloud,
            local,
            audit: Arc::new(audit),
            redact: Arc::new(agent_audit::redact),
            capture,
            notifier: Arc::new(|title: &str, body: &str| {
                let (t, b) = (title.to_string(), body.to_string());
                if let Ok(h) = tokio::runtime::Handle::try_current() {
                    h.spawn_blocking(move || {
                        let _ = agent_input::system::notify_local(&t, &b);
                    });
                }
            }),
            roots: Some(roots),
        };
        Ok(Self::with_parts(cfg, parts))
    }

    /// Build an agent from explicit parts (tests, alternative wiring).
    pub fn with_parts(cfg: AgentConfig, parts: Parts) -> Self {
        let roots: Vec<String> = cfg.shared_roots.iter().map(|(n, _)| n.clone()).collect();
        Self {
            inner: Arc::new(Inner {
                policy: RwLock::new(Policy::from_config(&cfg)),
                system_prompt: task::build_system_prompt(&roots),
                cfg,
                parts,
                approvals: Approvals::default(),
                root: Mutex::new(CancellationToken::new()),
                screen: Arc::new(ScreenCtl::default()),
                outs: Mutex::new(vec![]),
                laya_down_until: AtomicU64::new(0),
                transfers: Transfers::default(),
                memory: memory::Memory::default(),
            }),
        }
    }

    pub fn policy(&self) -> Policy {
        self.inner.policy.read().unwrap().clone()
    }

    pub fn pending_approvals(&self) -> usize {
        self.inner.approvals.pending_count()
    }

    fn register_out(&self, out: &mpsc::Sender<Message>) {
        let mut g = self.inner.outs.lock().unwrap();
        g.retain(|o| !o.is_closed());
        if !g.iter().any(|o| o.same_channel(out)) {
            g.push(out.clone());
        }
    }

    /// Handle one inbound message from `actor` (e.g. "phone:Pixel 9"). Outbound messages go to `out`.
    /// Must return quickly: long tasks run on spawned tasks.
    pub async fn handle(&self, actor: &str, msg: Message, out: mpsc::Sender<Message>) {
        self.register_out(&out);
        let inner = &self.inner;
        match msg {
            Message::ChatUser(c) => {
                let text = c.text.trim().to_string();
                if text.is_empty() {
                    return;
                }
                tokio::spawn(task::run_task(inner.clone(), actor.to_string(), text, out));
            }
            Message::ApprovalResponse(r) => {
                if !inner.approvals.respond(r.approval_id, r.decision) {
                    let _ = out
                        .send(Message::Error(ErrorMsg {
                            code: "unknown_approval".into(),
                            message:
                                "No pending approval with that id (expired or already answered)."
                                    .into(),
                        }))
                        .await;
                }
            }
            Message::ScreenRequest(r) => {
                let p = screen::Params::from_request(&r);
                match r.action {
                    ScreenAction::Snapshot => {
                        let inner = inner.clone();
                        let actor = actor.to_string();
                        tokio::spawn(async move {
                            match inner.parts.capture.capture(p.max_width, p.quality).await {
                                Ok(img) => {
                                    inner.screen.send_image(&out, &img).await;
                                    inner.audit(
                                        &actor,
                                        "screen.snapshot",
                                        "",
                                        "ok",
                                        RiskTier::Read,
                                    );
                                }
                                Err(e) => {
                                    let _ = out
                                        .send(notify(
                                            NotifyLevel::Error,
                                            format!("Screenshot failed: {e}"),
                                        ))
                                        .await;
                                }
                            }
                        });
                    }
                    ScreenAction::Start => {
                        inner.audit(
                            actor,
                            "screen.start",
                            &format!("{p:?}"),
                            "started",
                            RiskTier::Read,
                        );
                        inner.screen.start(
                            inner.parts.capture.clone(),
                            &inner.root_token(),
                            p,
                            out,
                            inner.parts.notifier.clone(),
                        );
                    }
                    ScreenAction::Stop => {
                        if !inner.screen.stop() {
                            let _ = out
                                .send(Message::ScreenState(ScreenState {
                                    active: false,
                                    reason: "stopped".into(),
                                }))
                                .await;
                        }
                    }
                }
            }
            Message::FileRequest(r) => self.file_request(actor, r.path, out),
            Message::FileAccept(a) => self.file_accept(a, out),
            Message::FileOffer(o) => self.file_offer(actor, o, out),
            Message::FileChunk(c) => {
                let res = {
                    let mut g = inner.transfers.incoming.lock().unwrap();
                    match g.get_mut(&c.transfer_id) {
                        Some(r) => {
                            let res = r.write_chunk(&c);
                            if res.is_err() {
                                g.remove(&c.transfer_id);
                            }
                            Some(res)
                        }
                        None => None,
                    }
                };
                match res {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        let _ = out.send(transfer::fail(c.transfer_id, e.to_string())).await;
                    }
                    None => {
                        let _ = out
                            .send(transfer::fail(c.transfer_id, "unknown transfer"))
                            .await;
                    }
                }
            }
            Message::FileDone(d) => {
                let recv = inner
                    .transfers
                    .incoming
                    .lock()
                    .unwrap()
                    .remove(&d.transfer_id);
                let Some(recv) = recv else {
                    return;
                };
                let inner = inner.clone();
                let actor = actor.to_string();
                tokio::spawn(async move {
                    let id = d.transfer_id;
                    let res = tokio::task::spawn_blocking(move || recv.finish()).await;
                    let msg = match res {
                        Ok(Ok(done)) => {
                            inner.audit(
                                &actor,
                                "file.receive",
                                &id.to_string(),
                                &format!("ok={}", done.ok),
                                RiskTier::Write,
                            );
                            Message::FileDone(done)
                        }
                        Ok(Err(e)) => transfer::fail(id, e.to_string()),
                        Err(e) => transfer::fail(id, e.to_string()),
                    };
                    let _ = out.send(msg).await;
                });
            }
            Message::ControlKill(k) => {
                let reason = k.reason.unwrap_or_else(|| "kill switch".into());
                self.kill_by(actor, &reason);
            }
            Message::SettingsUpdate(u) => {
                inner.policy.write().unwrap().apply(&u);
                let p = self.policy();
                inner.audit(
                    actor,
                    "settings.update",
                    &format!("{u:?}"),
                    &format!("{p:?}"),
                    RiskTier::Write,
                );
                let _ = out
                    .send(notify(
                        NotifyLevel::Info,
                        format!(
                            "Settings updated: cloud {}, high-sensitivity to cloud {}, preferred {:?}.",
                            if p.cloud_enabled { "on" } else { "off" },
                            if p.cloud_allow_high_sensitivity { "allowed" } else { "blocked" },
                            p.preferred_cloud
                        ),
                    ))
                    .await;
            }
            Message::Ping(p) => {
                let _ = out.send(Message::Pong(p)).await;
            }
            // Laptop->phone types (or pairing, handled by transport) are not valid here.
            other => {
                tracing::debug!("ignoring unexpected inbound message type");
                let _ = out
                    .send(Message::Error(ErrorMsg {
                        code: "unexpected_message".into(),
                        message: format!("not accepted by the laptop: {}", msg_type(&other)),
                    }))
                    .await;
            }
        }
    }

    fn file_request(&self, actor: &str, path: String, out: mpsc::Sender<Message>) {
        let inner = self.inner.clone();
        let actor = actor.to_string();
        tokio::spawn(async move {
            let Some(roots) = inner.parts.roots.clone() else {
                let _ = out
                    .send(notify(NotifyLevel::Error, "No shared folders configured."))
                    .await;
                return;
            };
            let id = Uuid::new_v4();
            let p2 = path.clone();
            let opened = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let rel = tools::builtin::fix_root(&roots.names(), &p2);
                let abs = roots.resolve(&rel, true)?;
                if !abs.is_file() {
                    anyhow::bail!("not a file");
                }
                let (_, offer) = agent_files::FileSender::open(&abs, id)?;
                Ok((abs, offer))
            })
            .await;
            let (abs, offer) = match opened {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    inner.audit(
                        &actor,
                        "file.send",
                        &path,
                        &format!("refused: {e}"),
                        RiskTier::Read,
                    );
                    let _ = out.send(transfer::fail(id, e.to_string())).await;
                    return;
                }
                Err(e) => {
                    let _ = out.send(transfer::fail(id, e.to_string())).await;
                    return;
                }
            };
            inner.audit(
                &actor,
                "file.send",
                &path,
                &format!("{} bytes", offer.size),
                RiskTier::Read,
            );
            let (atx, arx) = tokio::sync::oneshot::channel();
            let cancel = inner.root_token().child_token();
            inner.transfers.insert_outgoing(
                id,
                transfer::Outgoing {
                    path: abs.clone(),
                    offer: offer.clone(),
                    accept: Some(atx),
                    cancel: cancel.clone(),
                },
            );
            if out.send(Message::FileOffer(offer.clone())).await.is_err() {
                return;
            }
            let offset = tokio::time::timeout(transfer::ACCEPT_WAIT, arx)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
            if let Some(o) = inner.transfers.outgoing.lock().unwrap().get_mut(&id) {
                o.accept = None;
            }
            spawn_stream(abs, offer, offset, out, cancel);
        });
    }

    fn file_accept(&self, a: FileAccept, out: mpsc::Sender<Message>) {
        let mut g = self.inner.transfers.outgoing.lock().unwrap();
        let Some(o) = g.get_mut(&a.transfer_id) else {
            return;
        };
        if let Some(tx) = o.accept.take() {
            let _ = tx.send(a.offset);
        } else if a.offset > 0 {
            // Resume after a drop: restart streaming from the requested offset.
            o.cancel.cancel();
            o.cancel = self.inner.root_token().child_token();
            spawn_stream(
                o.path.clone(),
                o.offer.clone(),
                a.offset,
                out,
                o.cancel.clone(),
            );
        }
    }

    fn file_offer(&self, actor: &str, offer: FileOffer, out: mpsc::Sender<Message>) {
        let inner = self.inner.clone();
        let actor = actor.to_string();
        tokio::spawn(async move {
            let id = offer.transfer_id;
            if !transfer::safe_incoming_name(&offer.name) || offer.size > transfer::MAX_INCOMING {
                inner.audit(
                    &actor,
                    "file.receive",
                    &offer.name,
                    "rejected",
                    RiskTier::Write,
                );
                let _ = out
                    .send(transfer::fail(id, "rejected: bad name or too large"))
                    .await;
                return;
            }
            if transfer::incoming_needs_approval(&offer) {
                let cancel = inner.root_token().child_token();
                let summary = format!(
                    "Receive {} ({:.1} MB){}",
                    offer.name,
                    offer.size as f64 / 1e6,
                    if transfer::is_executable_name(&offer.name) {
                        " — executable type"
                    } else {
                        ""
                    }
                );
                let outcome = inner
                    .approvals
                    .request(
                        &out,
                        Ask {
                            task_id: id,
                            tool: "file.receive",
                            summary: &summary,
                            risk: RiskTier::Write,
                            preview: Some(summary.clone()),
                        },
                        Duration::from_secs(inner.cfg.approval_timeout_secs),
                        &cancel,
                    )
                    .await;
                if !outcome.approved() {
                    inner.audit(
                        &actor,
                        "file.receive",
                        &offer.name,
                        "denied",
                        RiskTier::Write,
                    );
                    let _ = out.send(transfer::fail(id, "denied")).await;
                    return;
                }
            }
            let inbox = inner.cfg.data_dir.join("inbox");
            let o2 = offer.clone();
            let res = tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&inbox)?;
                FileReceiver::new(&inbox, &o2, transfer::MAX_INCOMING)
            })
            .await;
            match res {
                Ok(Ok(recv)) => {
                    let offset = recv.offset();
                    inner.transfers.incoming.lock().unwrap().insert(id, recv);
                    inner.audit(
                        &actor,
                        "file.receive",
                        &offer.name,
                        &format!("accepted at {offset}"),
                        RiskTier::Write,
                    );
                    let _ = out
                        .send(Message::FileAccept(FileAccept {
                            transfer_id: id,
                            offset,
                        }))
                        .await;
                }
                Ok(Err(e)) => {
                    let _ = out.send(transfer::fail(id, e.to_string())).await;
                }
                Err(e) => {
                    let _ = out.send(transfer::fail(id, e.to_string())).await;
                }
            }
        });
    }

    /// Kill switch: cancel every running task, deny pending approvals, stop screen stream.
    pub fn kill(&self, reason: &str) {
        self.kill_by("local", reason);
    }

    fn kill_by(&self, actor: &str, reason: &str) {
        let inner = &self.inner;
        let old = std::mem::take(&mut *inner.root.lock().unwrap());
        old.cancel();
        let denied = inner.approvals.deny_all();
        let screen = inner.screen.stop();
        inner.transfers.cancel_all();
        let reason = (inner.parts.redact)(reason);
        inner.audit(
            actor,
            "control.kill",
            &reason,
            &format!("approvals denied: {denied}, screen stopped: {screen}"),
            RiskTier::Read,
        );
        tracing::warn!("kill switch by {actor}");
        let msg = notify(
            NotifyLevel::Warn,
            format!("Kill switch: all actions stopped ({reason})."),
        );
        let mut g = inner.outs.lock().unwrap();
        g.retain(|o| !o.is_closed());
        for o in g.iter() {
            let _ = o.try_send(msg.clone());
        }
    }
}

fn spawn_stream(
    path: PathBuf,
    offer: FileOffer,
    offset: u64,
    out: mpsc::Sender<Message>,
    cancel: CancellationToken,
) {
    tokio::task::spawn_blocking(move || {
        if let Err(e) = transfer::stream_file_blocking(path, offer, offset, out, cancel) {
            tracing::debug!("file stream ended: {e}");
        }
    });
}

fn notify(level: NotifyLevel, text: impl Into<String>) -> Message {
    Message::Notify(Notify {
        level,
        text: text.into(),
    })
}

fn msg_type(m: &Message) -> String {
    serde_json::to_value(m)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
