//! Ollama `/api/chat` with tools; NDJSON streaming. `keep_alive: "2m"` so the model is unloaded
//! from RAM/VRAM shortly after the owner stops talking (battery).
use agent_protocol::Brain;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::http::{self, RetryPolicy};
use crate::{ChatRequest, ChatResponse, DeltaFn, LlmProvider, Msg, Role, ToolCall, Usage};

pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";
pub const KEEP_ALIVE: &str = "2m";

pub struct OllamaProvider {
    pub(crate) client: reqwest::Client,
    pub(crate) model: String,
    pub(crate) base_url: String,
    pub(crate) retry: RetryPolicy,
}

impl std::fmt::Debug for OllamaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OllamaProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl OllamaProvider {
    pub fn new(base_url: String, model: String) -> Self {
        let base = if base_url.is_empty() {
            DEFAULT_BASE_URL.to_owned()
        } else {
            base_url
        };
        Self {
            client: http::default_client(),
            model,
            base_url: base.trim_end_matches('/').to_owned(),
            retry: RetryPolicy::default(),
        }
    }
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }
    async fn send(&self, body: &Value) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}/api/chat", self.base_url);
        http::send_with_retry(self.retry, "ollama", || self.client.post(&url).json(body)).await
    }
}

pub fn map_messages(system: &str, msgs: &[Msg]) -> Vec<Value> {
    let mut out = Vec::with_capacity(msgs.len() + 1);
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }
    for (i, m) in msgs.iter().enumerate() {
        let mut v = match m.role {
            Role::User => json!({"role": "user", "content": m.content}),
            Role::Assistant => {
                let mut v = json!({"role": "assistant", "content": m.content});
                if !m.tool_calls.is_empty() {
                    v["tool_calls"] = m
                        .tool_calls
                        .iter()
                        .map(|c| json!({"function": {"name": c.name, "arguments": c.arguments}}))
                        .collect();
                }
                v
            }
            Role::Tool => {
                let id = m.tool_call_id.as_deref().unwrap_or_default();
                let name = msgs[..i]
                    .iter()
                    .rev()
                    .flat_map(|x| x.tool_calls.iter())
                    .find(|c| c.id == id)
                    .map(|c| c.name.clone());
                let mut v = json!({"role": "tool", "content": m.content});
                if let Some(n) = name {
                    v["tool_name"] = json!(n);
                }
                v
            }
        };
        if !m.images.is_empty() {
            v["images"] = m.images.iter().map(|i| json!(http::b64(i))).collect();
        }
        out.push(v);
    }
    out
}

pub fn build_body(model: &str, req: &ChatRequest, stream: bool) -> Value {
    let mut b = Map::new();
    b.insert("model".into(), json!(model));
    b.insert(
        "messages".into(),
        Value::Array(map_messages(&req.system, &req.messages)),
    );
    b.insert("stream".into(), json!(stream));
    b.insert("keep_alive".into(), json!(KEEP_ALIVE));
    if !req.tools.is_empty() {
        b.insert(
            "tools".into(),
            req.tools
                .iter()
                .map(|t| json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}))
                .collect(),
        );
    }
    let mut opts = json!({"num_predict": req.max_tokens});
    if let Some(t) = req.temperature {
        opts["temperature"] = json!(t);
    }
    b.insert("options".into(), opts);
    Value::Object(b)
}

#[derive(Default)]
pub struct StreamState {
    text: String,
    calls: Vec<ToolCall>,
    usage: Usage,
}

impl StreamState {
    pub fn on_line(&mut self, v: &Value, on_delta: DeltaFn<'_>) -> anyhow::Result<()> {
        if let Some(e) = v["error"].as_str() {
            return Err(anyhow!("ollama: {e}"));
        }
        let msg = &v["message"];
        if let Some(t) = msg["content"].as_str().filter(|t| !t.is_empty()) {
            self.text.push_str(t);
            on_delta(t);
        }
        for c in msg["tool_calls"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let f = &c["function"];
            let arguments = match &f["arguments"] {
                Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
                Value::Object(_) => f["arguments"].clone(),
                _ => json!({}),
            };
            let id = c["id"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("ollama-call-{}", self.calls.len()));
            self.calls.push(ToolCall {
                id,
                name: f["name"].as_str().unwrap_or_default().to_owned(),
                arguments,
            });
        }
        if v["done"].as_bool() == Some(true) {
            self.usage.input_tokens = v["prompt_eval_count"].as_u64().unwrap_or(0);
            self.usage.output_tokens = v["eval_count"].as_u64().unwrap_or(0);
        }
        Ok(())
    }
    pub fn finish(self) -> ChatResponse {
        ChatResponse {
            text: self.text,
            tool_calls: self.calls,
            usage: self.usage,
        }
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn brain(&self) -> Brain {
        Brain::Local
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_vision(&self) -> bool {
        let m = self.model.to_ascii_lowercase();
        [
            "llava",
            "vision",
            "-vl",
            "vl:",
            "gemma3",
            "minicpm-v",
            "moondream",
            "llama4",
        ]
        .iter()
        .any(|k| m.contains(k))
    }
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, false)).await?;
        let v: Value = resp.json().await.context("ollama: invalid JSON response")?;
        let mut st = StreamState::default();
        st.on_line(&v, &|_| {})?;
        Ok(st.finish())
    }
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, true)).await?;
        let mut st = StreamState::default();
        http::for_each_ndjson(resp, |v| st.on_line(&v, on_delta)).await?;
        Ok(st.finish())
    }
}
