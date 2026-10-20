//! OpenAI Chat Completions API (`POST /v1/chat/completions`) with function calling.
//! Works against any OpenAI-compatible server via [`OpenAiProvider::with_base_url`].
use agent_protocol::Brain;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::http::{self, RetryPolicy};
use crate::{
    ChatRequest, ChatResponse, DeltaFn, LlmProvider, Msg, Role, ToolCall, Usage, price_per_mtok,
};

/// `gpt-6-luna`: OpenAI's "most efficient model for focused, high-volume tasks", $0.10/$0.50
/// per MTok (developers.openai.com/api/docs/models/gpt-6-luna, checked 2026-10-20).
pub const DEFAULT_MODEL: &str = "gpt-6-luna";
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com";

pub struct OpenAiProvider {
    pub(crate) client: reqwest::Client,
    pub(crate) api_key: String,
    pub(crate) model: String,
    pub(crate) base_url: String,
    pub(crate) retry: RetryPolicy,
}

impl std::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl OpenAiProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        Self {
            client: http::default_client(),
            api_key,
            model: model.unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
            base_url: DEFAULT_BASE_URL.to_owned(),
            retry: RetryPolicy::default(),
        }
    }
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into().trim_end_matches('/').to_owned();
        self
    }
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }
    async fn send(&self, body: &Value) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}/v1/chat/completions", self.base_url);
        http::send_with_retry(self.retry, "openai", || {
            self.client.post(&url).bearer_auth(&self.api_key).json(body)
        })
        .await
    }
}

/// Reasoning-family models reject `temperature`.
fn accepts_temperature(model: &str) -> bool {
    !(model.starts_with("gpt-5") || model.starts_with("gpt-6") || model.starts_with('o'))
}

fn image_part(jpeg: &[u8]) -> Value {
    json!({"type": "image_url", "image_url": {"url": format!("data:image/jpeg;base64,{}", http::b64(jpeg))}})
}

fn user_content(text: &str, images: &[Vec<u8>]) -> Value {
    if images.is_empty() {
        return json!(text);
    }
    let mut parts = vec![json!({"type": "text", "text": text})];
    parts.extend(images.iter().map(|i| image_part(i)));
    Value::Array(parts)
}

pub fn map_messages(system: &str, msgs: &[Msg]) -> Vec<Value> {
    let mut out = Vec::with_capacity(msgs.len() + 1);
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }
    for m in msgs {
        match m.role {
            Role::User => {
                out.push(json!({"role": "user", "content": user_content(&m.content, &m.images)}))
            }
            Role::Assistant => {
                let mut v = json!({"role": "assistant", "content": if m.content.is_empty() { Value::Null } else { json!(m.content) }});
                if !m.tool_calls.is_empty() {
                    v["tool_calls"] = m
                        .tool_calls
                        .iter()
                        .map(|c| json!({"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments.to_string()}}))
                        .collect();
                }
                out.push(v);
            }
            Role::Tool => {
                out.push(json!({"role": "tool", "tool_call_id": m.tool_call_id.clone().unwrap_or_default(), "content": m.content}));
                // Tool messages are text-only in Chat Completions; attach screenshots as a user turn.
                if !m.images.is_empty() {
                    out.push(json!({"role": "user", "content": user_content("(image output of the tool call above)", &m.images)}));
                }
            }
        }
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
    b.insert("max_completion_tokens".into(), json!(req.max_tokens));
    if let Some(t) = req.temperature.filter(|_| accepts_temperature(model)) {
        b.insert("temperature".into(), json!(t));
    }
    if !req.tools.is_empty() {
        b.insert(
            "tools".into(),
            req.tools
                .iter()
                .map(|t| json!({"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}))
                .collect(),
        );
    }
    if stream {
        b.insert("stream".into(), json!(true));
        b.insert("stream_options".into(), json!({"include_usage": true}));
    }
    Value::Object(b)
}

fn usage_from(model: &str, u: &Value) -> Usage {
    let input = u["prompt_tokens"].as_u64().unwrap_or(0);
    let cached = u["prompt_tokens_details"]["cached_tokens"]
        .as_u64()
        .unwrap_or(0)
        .min(input);
    let output = u["completion_tokens"].as_u64().unwrap_or(0);
    let (pin, pout) = price_per_mtok(Brain::Openai, model);
    let cost =
        ((input - cached) as f64 * pin + cached as f64 * pin * 0.1 + output as f64 * pout) / 1e6;
    Usage {
        input_tokens: input,
        output_tokens: output,
        cost_usd: cost,
    }
}

fn parse_args(name: &str, s: &str) -> anyhow::Result<Value> {
    if s.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(s)
        .with_context(|| format!("openai: invalid tool arguments JSON for {name}"))
}

pub fn parse_response(model: &str, v: &Value) -> anyhow::Result<ChatResponse> {
    if let Some(e) = v.get("error") {
        return Err(anyhow!(
            "openai: {}",
            e["message"].as_str().unwrap_or("error")
        ));
    }
    let msg = &v["choices"][0]["message"];
    if let Some(r) = msg["refusal"].as_str() {
        return Err(anyhow!("openai: refused: {r}"));
    }
    let mut tool_calls = Vec::new();
    for c in msg["tool_calls"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let name = c["function"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let arguments = parse_args(
            &name,
            c["function"]["arguments"].as_str().unwrap_or_default(),
        )?;
        tool_calls.push(ToolCall {
            id: c["id"].as_str().unwrap_or_default().to_owned(),
            name,
            arguments,
        });
    }
    Ok(ChatResponse {
        text: msg["content"].as_str().unwrap_or_default().to_owned(),
        tool_calls,
        usage: usage_from(model, &v["usage"]),
    })
}

#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    args: String,
}

#[derive(Default)]
pub struct StreamState {
    text: String,
    calls: Vec<(u64, PartialCall)>,
    usage: Option<Value>,
}

impl StreamState {
    pub fn on_chunk(&mut self, v: &Value, on_delta: DeltaFn<'_>) -> anyhow::Result<()> {
        if let Some(e) = v.get("error") {
            return Err(anyhow!(
                "openai stream error: {}",
                e["message"].as_str().unwrap_or("unknown")
            ));
        }
        if v["usage"].is_object() {
            self.usage = Some(v["usage"].clone());
        }
        let Some(delta) = v["choices"].get(0).map(|c| &c["delta"]) else {
            return Ok(());
        };
        if let Some(t) = delta["content"].as_str().filter(|t| !t.is_empty()) {
            self.text.push_str(t);
            on_delta(t);
        }
        for tc in delta["tool_calls"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let idx = tc["index"].as_u64().unwrap_or(0);
            let pos = match self.calls.iter().position(|(i, _)| *i == idx) {
                Some(p) => p,
                None => {
                    self.calls.push((idx, PartialCall::default()));
                    self.calls.len() - 1
                }
            };
            let pc = &mut self.calls[pos].1;
            if let Some(id) = tc["id"].as_str() {
                pc.id = id.to_owned();
            }
            if let Some(n) = tc["function"]["name"].as_str() {
                pc.name.push_str(n);
            }
            if let Some(a) = tc["function"]["arguments"].as_str() {
                pc.args.push_str(a);
            }
        }
        Ok(())
    }

    pub fn finish(mut self, model: &str) -> anyhow::Result<ChatResponse> {
        self.calls.sort_by_key(|(i, _)| *i);
        let mut tool_calls = Vec::with_capacity(self.calls.len());
        for (_, c) in self.calls {
            let arguments = parse_args(&c.name, &c.args)?;
            tool_calls.push(ToolCall {
                id: c.id,
                name: c.name,
                arguments,
            });
        }
        Ok(ChatResponse {
            text: self.text,
            tool_calls,
            usage: self
                .usage
                .map(|u| usage_from(model, &u))
                .unwrap_or_default(),
        })
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn brain(&self) -> Brain {
        Brain::Openai
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_vision(&self) -> bool {
        !self.model.contains("gpt-3.5")
    }
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, false)).await?;
        let v: Value = resp.json().await.context("openai: invalid JSON response")?;
        parse_response(&self.model, &v)
    }
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, true)).await?;
        let mut st = StreamState::default();
        http::for_each_sse_json(resp, |v| st.on_chunk(&v, on_delta)).await?;
        st.finish(&self.model)
    }
}
