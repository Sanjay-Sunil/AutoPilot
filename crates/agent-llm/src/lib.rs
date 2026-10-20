//! LLM + decision-model providers behind one trait.
//! Cloud: Claude (Anthropic Messages API), OpenAI (Responses/Chat Completions), Gemini.
//! Local: Ollama (optional LLM) and Laya (decision model via Jev-compatible `POST /v1/systemone`).
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{Brain, RiskTier, Sensitivity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod claude;
pub mod gemini;
pub mod http;
pub mod keys;
pub mod laya;
pub mod ollama;
pub mod openai;

pub use claude::ClaudeProvider;
pub use gemini::GeminiProvider;
pub use http::RetryPolicy;
pub use laya::LayaClient;
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema object for the arguments.
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Msg {
    pub role: Role,
    pub content: String,
    /// Tool calls made by the assistant in this turn.
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    /// For role=Tool: which call this is the result of.
    pub tool_call_id: Option<String>,
    /// JPEG images attached to a user/tool message (vision).
    #[serde(default, skip_serializing)]
    pub images: Vec<Vec<u8>>,
}

impl Msg {
    pub fn user(s: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: s.into(),
            tool_calls: vec![],
            tool_call_id: None,
            images: vec![],
        }
    }
    pub fn assistant(s: impl Into<String>, calls: Vec<ToolCall>) -> Self {
        Self {
            role: Role::Assistant,
            content: s.into(),
            tool_calls: calls,
            tool_call_id: None,
            images: vec![],
        }
    }
    pub fn tool(id: impl Into<String>, s: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: s.into(),
            tool_calls: vec![],
            tool_call_id: Some(id.into()),
            images: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub system: String,
    pub messages: Vec<Msg>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
}

pub type DeltaFn<'a> = &'a (dyn Fn(&str) + Send + Sync);

#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn brain(&self) -> Brain;
    fn model(&self) -> &str;
    fn supports_vision(&self) -> bool;
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse>;
    /// Streams text deltas through `on_delta`; returns the full response (incl. tool calls).
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse>;
}

/// Look up an API key: env var first (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY),
/// then OS keyring (service "autopilot", user = provider name: "claude" | "openai" | "gemini").
/// `GOOGLE_API_KEY` is also accepted for gemini. Keyring failures yield `None`, never a panic.
pub fn api_key(provider: &str) -> Option<String> {
    keys::lookup(provider, |k| std::env::var(k).ok(), keys::keyring_get)
}
/// Store a key in the OS keyring.
pub fn set_api_key(provider: &str, key: &str) -> anyhow::Result<()> {
    keys::keyring_set(provider, key)
}

/// Output of the local decision layer for one user message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayaDecision {
    /// One of [`INTENTS`].
    pub intent: String,
    pub intent_confidence: f32,
    pub risk: RiskTier,
    pub sensitivity: Sensitivity,
    /// Probability that this needs a frontier model (multi-step, generation, reasoning).
    pub needs_cloud: f32,
    pub latency_ms: u64,
}

/// Intent labels the decider chooses from.
pub const INTENTS: &[&str] = &[
    "open_app",
    "window_control",
    "files",
    "shell",
    "system_control",
    "system_info",
    "browser",
    "screen",
    "clipboard",
    "type_or_keys",
    "question",
    "multi_step_task",
];

/// Price table per 1M tokens (input, output) for cost accounting.
/// Sources (2026-10-20): Anthropic model table (claude-api skill), developers.openai.com/api/docs/pricing,
/// cloud.google.com Gemini pricing (3.6-3.8 Flash introductory price through 2026-12-31).
/// Unknown cloud models fall back to a conservative (high) estimate so budgets err safe.
pub fn price_per_mtok(brain: Brain, model: &str) -> (f64, f64) {
    let m = model.to_ascii_lowercase();
    let table: &[(&str, (f64, f64))] = match brain {
        Brain::Rules | Brain::Laya | Brain::Local => return (0.0, 0.0),
        Brain::Claude => &[
            ("claude-fable", (10.0, 50.0)),
            ("claude-mythos", (10.0, 50.0)),
            ("claude-opus-5-5", (4.0, 20.0)),
            ("claude-opus", (5.0, 25.0)),
            ("claude-sonnet-5", (2.0, 10.0)),
            ("claude-sonnet", (3.0, 15.0)),
            ("claude-haiku", (1.0, 5.0)),
            ("", (5.0, 25.0)),
        ],
        Brain::Openai => &[
            ("gpt-6-luna", (0.10, 0.50)),
            ("gpt-6", (2.0, 10.0)),
            ("gpt-5.6-luna", (0.20, 1.20)),
            ("gpt-5.4-nano", (0.20, 1.25)),
            ("gpt-5.4-mini", (0.75, 4.50)),
            ("gpt-5.4", (2.50, 15.0)),
            ("gpt-5-nano", (0.05, 0.40)),
            ("gpt-5-mini", (0.25, 2.0)),
            ("gpt-5", (1.25, 10.0)),
            ("gpt-4.1-nano", (0.10, 0.40)),
            ("o4-mini", (1.10, 4.40)),
            ("", (2.50, 15.0)),
        ],
        Brain::Gemini => &[
            ("gemini-3.8-flash", (0.75, 3.75)),
            ("gemini-3.7-flash", (0.75, 3.75)),
            ("gemini-3.6-flash", (0.75, 3.75)),
            ("gemini-3.5-flash", (1.50, 9.0)),
            ("gemini-2.5-flash", (0.30, 2.50)),
            ("", (1.50, 9.0)),
        ],
    };
    table
        .iter()
        .find(|(p, _)| m.starts_with(p))
        .map(|(_, v)| *v)
        .unwrap_or((0.0, 0.0))
}

#[cfg(test)]
mod tests;
