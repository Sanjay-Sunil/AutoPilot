//! LLM + decision-model providers behind one trait.
//! Cloud: Claude (Anthropic Messages API), OpenAI (Responses/Chat Completions), Gemini.
//! Local: Ollama (optional LLM) and Laya (decision model via Jev-compatible `POST /v1/systemone`).
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{Brain, RiskTier, Sensitivity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role { User, Assistant, Tool }

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
    pub fn user(s: impl Into<String>) -> Self { Self { role: Role::User, content: s.into(), tool_calls: vec![], tool_call_id: None, images: vec![] } }
    pub fn assistant(s: impl Into<String>, calls: Vec<ToolCall>) -> Self { Self { role: Role::Assistant, content: s.into(), tool_calls: calls, tool_call_id: None, images: vec![] } }
    pub fn tool(id: impl Into<String>, s: impl Into<String>) -> Self { Self { role: Role::Tool, content: s.into(), tool_calls: vec![], tool_call_id: Some(id.into()), images: vec![] } }
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
pub struct Usage { pub input_tokens: u64, pub output_tokens: u64, pub cost_usd: f64 }

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
    async fn chat_stream(&self, req: &ChatRequest, on_delta: DeltaFn<'_>) -> anyhow::Result<ChatResponse>;
}

/// Look up an API key: env var first (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY),
/// then OS keyring (service "autopilot", user = provider name: "claude" | "openai" | "gemini").
pub fn api_key(_provider: &str) -> Option<String> { todo!() }
/// Store a key in the OS keyring.
pub fn set_api_key(_provider: &str, _key: &str) -> anyhow::Result<()> { todo!() }

pub struct ClaudeProvider {}
impl ClaudeProvider { pub fn new(_api_key: String, _model: Option<String>) -> Self { todo!() } }
pub struct OpenAiProvider {}
impl OpenAiProvider { pub fn new(_api_key: String, _model: Option<String>) -> Self { todo!() } }
pub struct GeminiProvider {}
impl GeminiProvider { pub fn new(_api_key: String, _model: Option<String>) -> Self { todo!() } }
pub struct OllamaProvider {}
impl OllamaProvider { pub fn new(_base_url: String, _model: String) -> Self { todo!() } }

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
    "open_app", "window_control", "files", "shell", "system_control", "system_info",
    "browser", "screen", "clipboard", "type_or_keys", "question", "multi_step_task",
];

/// HTTP client for a local `laya-serve` (default http://127.0.0.1:8765).
pub struct LayaClient {}
impl LayaClient {
    pub fn new(_base_url: String) -> Self { todo!() }
    pub async fn healthy(&self) -> bool { todo!() }
    /// Raw Jev-compatible call: POST /v1/systemone {state, questions} -> response json.
    pub async fn system_one(&self, _state: &serde_json::Value, _questions: &serde_json::Value) -> anyhow::Result<serde_json::Value> { todo!() }
    /// Ask intent / risk / sensitivity / needs_cloud in ONE forward pass.
    pub async fn decide(&self, _text: &str) -> anyhow::Result<LayaDecision> { todo!() }
}

/// Price table per 1M tokens (input, output) for cost accounting.
pub fn price_per_mtok(_brain: Brain, _model: &str) -> (f64, f64) { todo!() }
