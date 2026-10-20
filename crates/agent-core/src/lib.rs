//! The agent: decision layer (rules fast path -> Laya -> cloud LLM), policy/router, tool registry,
//! approvals with risk tiers, kill switch, task updates, audit.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::Message;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::mpsc;

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
}

impl Default for AgentConfig {
    fn default() -> Self { todo!() }
}

/// Handle to the running agent; cheap to clone.
#[derive(Clone)]
pub struct Agent {}

impl Agent {
    pub async fn new(_cfg: AgentConfig) -> anyhow::Result<Self> { todo!() }
    /// Handle one inbound message from `actor` (e.g. "phone:Pixel 9"). Outbound messages go to `out`.
    /// Must return quickly: long tasks run on spawned tasks.
    pub async fn handle(&self, _actor: &str, _msg: Message, _out: mpsc::Sender<Message>) { todo!() }
    /// Kill switch: cancel every running task, deny pending approvals, stop screen stream.
    pub fn kill(&self, _reason: &str) { todo!() }
}
