//! Anthropic Messages API (`POST /v1/messages`), raw HTTP.
//!
//! - Tools + system prompt are marked with one `cache_control: ephemeral` breakpoint (render
//!   order is tools -> system -> messages, so a breakpoint on the last system block caches both).
//! - Thinking is disabled on models that allow it: AutoPilot's [`Msg`] has no slot to replay
//!   thinking blocks across tool-use turns, and the router wants low latency. Models where
//!   thinking cannot be disabled (Fable 5.x, Opus 5.5) run at `effort: low` instead.
//! - Sampling params (`temperature`) are only sent to models that still accept them.
use agent_protocol::Brain;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::http::{self, RetryPolicy};
use crate::{
    ChatRequest, ChatResponse, DeltaFn, LlmProvider, Msg, Role, ToolCall, Usage, price_per_mtok,
};

pub const DEFAULT_MODEL: &str = "claude-sonnet-5";
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const API_VERSION: &str = "2023-06-01";

pub struct ClaudeProvider {
    pub(crate) client: reqwest::Client,
    pub(crate) api_key: String,
    pub(crate) model: String,
    pub(crate) base_url: String,
    pub(crate) retry: RetryPolicy,
}

impl std::fmt::Debug for ClaudeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ClaudeProvider {
    pub fn new(api_key: String, model: Option<String>) -> Self {
        Self {
            client: http::default_client(),
            api_key,
            model: model.unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
            base_url: DEFAULT_BASE_URL.to_owned(),
            retry: RetryPolicy::default(),
        }
    }
    /// Override the API base URL (proxies, tests).
    pub fn with_base_url(mut self, base: impl Into<String>) -> Self {
        self.base_url = base.into().trim_end_matches('/').to_owned();
        self
    }
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    async fn send(&self, body: &Value) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}/v1/messages", self.base_url);
        http::send_with_retry(self.retry, "claude", || {
            self.client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", API_VERSION)
                .json(body)
        })
        .await
    }
}

fn thinking_always_on(model: &str) -> bool {
    model.starts_with("claude-fable")
        || model.starts_with("claude-mythos")
        || model.starts_with("claude-opus-5-5")
}

fn accepts_sampling(model: &str) -> bool {
    // Sampling params were removed on Opus 4.7+, Sonnet 5, Opus 5.x, Fable.
    model.contains("haiku")
        || model.contains("-4-6")
        || model.contains("-4-5")
        || model.contains("-3-")
}

/// Build the Messages API request body.
pub fn build_body(model: &str, req: &ChatRequest, stream: bool) -> Value {
    let mut body = Map::new();
    body.insert("model".into(), json!(model));
    body.insert("max_tokens".into(), json!(req.max_tokens));
    if stream {
        body.insert("stream".into(), json!(true));
    }
    if thinking_always_on(model) {
        body.insert("output_config".into(), json!({"effort": "low"}));
    } else if !model.contains("haiku") {
        body.insert("thinking".into(), json!({"type": "disabled"}));
    }
    if let Some(t) = req.temperature.filter(|_| accepts_sampling(model)) {
        body.insert("temperature".into(), json!(t));
    }

    let mut tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| {
            let mut v =
                json!({"name": t.name, "description": t.description, "input_schema": t.parameters});
            if stream {
                v["eager_input_streaming"] = json!(true);
            }
            v
        })
        .collect();
    if !req.system.is_empty() {
        body.insert(
            "system".into(),
            json!([{"type": "text", "text": req.system, "cache_control": {"type": "ephemeral"}}]),
        );
    } else if let Some(last) = tools.last_mut() {
        last["cache_control"] = json!({"type": "ephemeral"});
    }
    if !tools.is_empty() {
        body.insert("tools".into(), Value::Array(tools));
    }
    body.insert("messages".into(), Value::Array(map_messages(&req.messages)));
    Value::Object(body)
}

fn image_block(jpeg: &[u8]) -> Value {
    json!({"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": http::b64(jpeg)}})
}

/// Map AutoPilot messages to Anthropic turns. Tool results become `tool_result` blocks in a user
/// turn; consecutive user-side messages are merged so parallel tool results share one turn.
pub fn map_messages(msgs: &[Msg]) -> Vec<Value> {
    let mut out: Vec<(String, Vec<Value>)> = Vec::new();
    for m in msgs {
        let (role, blocks) = match m.role {
            Role::User => {
                let mut b: Vec<Value> = m.images.iter().map(|i| image_block(i)).collect();
                if !m.content.is_empty() || b.is_empty() {
                    b.push(json!({"type": "text", "text": m.content}));
                }
                ("user", b)
            }
            Role::Assistant => {
                let mut b = Vec::new();
                if !m.content.is_empty() {
                    b.push(json!({"type": "text", "text": m.content}));
                }
                for c in &m.tool_calls {
                    let input = if c.arguments.is_object() {
                        c.arguments.clone()
                    } else {
                        json!({})
                    };
                    b.push(json!({"type": "tool_use", "id": c.id, "name": c.name, "input": input}));
                }
                if b.is_empty() {
                    b.push(json!({"type": "text", "text": "(no content)"}));
                }
                ("assistant", b)
            }
            Role::Tool => {
                let mut content = vec![
                    json!({"type": "text", "text": if m.content.is_empty() { "(empty)" } else { &m.content }}),
                ];
                content.extend(m.images.iter().map(|i| image_block(i)));
                (
                    "user",
                    vec![json!({
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id.clone().unwrap_or_default(),
                        "content": content,
                    })],
                )
            }
        };
        match out.last_mut() {
            Some((r, b)) if r.as_str() == role => b.extend(blocks),
            _ => out.push((role.to_owned(), blocks)),
        }
    }
    // tool_result blocks must come first in a user turn.
    for (role, blocks) in &mut out {
        if role == "user" {
            blocks.sort_by_key(|b| b["type"] != "tool_result");
        }
    }
    out.into_iter()
        .map(|(role, content)| json!({"role": role, "content": content}))
        .collect()
}

#[derive(Default, Debug)]
struct RawUsage {
    input: u64,
    cache_write: u64,
    cache_read: u64,
    output: u64,
}

impl RawUsage {
    fn absorb(&mut self, u: &Value) {
        let g = |k: &str| u.get(k).and_then(Value::as_u64);
        if let Some(v) = g("input_tokens") {
            self.input = v;
        }
        if let Some(v) = g("cache_creation_input_tokens") {
            self.cache_write = v;
        }
        if let Some(v) = g("cache_read_input_tokens") {
            self.cache_read = v;
        }
        if let Some(v) = g("output_tokens") {
            self.output = v;
        }
    }
    fn finish(&self, model: &str) -> Usage {
        let (pin, pout) = price_per_mtok(Brain::Claude, model);
        let cost = (self.input as f64 * pin
            + self.cache_write as f64 * pin * 1.25
            + self.cache_read as f64 * pin * 0.1
            + self.output as f64 * pout)
            / 1e6;
        Usage {
            input_tokens: self.input + self.cache_write + self.cache_read,
            output_tokens: self.output,
            cost_usd: cost,
        }
    }
}

/// Parse a non-streaming Messages API response.
pub fn parse_response(model: &str, v: &Value) -> anyhow::Result<ChatResponse> {
    if v.get("type").and_then(Value::as_str) == Some("error") {
        return Err(anyhow!(
            "claude: {}",
            v["error"]["message"].as_str().unwrap_or("error")
        ));
    }
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for b in v["content"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        match b["type"].as_str() {
            Some("text") => text.push_str(b["text"].as_str().unwrap_or_default()),
            Some("tool_use") => tool_calls.push(ToolCall {
                id: b["id"].as_str().unwrap_or_default().to_owned(),
                name: b["name"].as_str().unwrap_or_default().to_owned(),
                arguments: b["input"].clone(),
            }),
            _ => {}
        }
    }
    let mut u = RawUsage::default();
    u.absorb(&v["usage"]);
    check_stop(v["stop_reason"].as_str())?;
    Ok(ChatResponse {
        text,
        tool_calls,
        usage: u.finish(model),
    })
}

fn check_stop(stop: Option<&str>) -> anyhow::Result<()> {
    if stop == Some("refusal") {
        return Err(anyhow!(
            "claude: request refused by model safety classifier"
        ));
    }
    Ok(())
}

enum Block {
    Text,
    Tool {
        id: String,
        name: String,
        json: String,
    },
    Other,
}

/// Incremental state for an SSE stream.
#[derive(Default)]
pub struct StreamState {
    text: String,
    blocks: Vec<(u64, Block)>,
    calls: Vec<ToolCall>,
    usage: RawUsage,
    stop: Option<String>,
}

impl StreamState {
    pub fn on_event(&mut self, ev: &Value, on_delta: DeltaFn<'_>) -> anyhow::Result<()> {
        match ev["type"].as_str().unwrap_or_default() {
            "message_start" => self.usage.absorb(&ev["message"]["usage"]),
            "content_block_start" => {
                let idx = ev["index"].as_u64().unwrap_or(0);
                let cb = &ev["content_block"];
                let block = match cb["type"].as_str() {
                    Some("text") => {
                        if let Some(t) = cb["text"].as_str().filter(|t| !t.is_empty()) {
                            self.text.push_str(t);
                            on_delta(t);
                        }
                        Block::Text
                    }
                    Some("tool_use") => Block::Tool {
                        id: cb["id"].as_str().unwrap_or_default().to_owned(),
                        name: cb["name"].as_str().unwrap_or_default().to_owned(),
                        json: String::new(),
                    },
                    _ => Block::Other,
                };
                self.blocks.push((idx, block));
            }
            "content_block_delta" => {
                let idx = ev["index"].as_u64().unwrap_or(0);
                let d = &ev["delta"];
                match d["type"].as_str() {
                    Some("text_delta") => {
                        let t = d["text"].as_str().unwrap_or_default();
                        self.text.push_str(t);
                        if !t.is_empty() {
                            on_delta(t);
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some((_, Block::Tool { json, .. })) =
                            self.blocks.iter_mut().rev().find(|(i, _)| *i == idx)
                        {
                            json.push_str(d["partial_json"].as_str().unwrap_or_default());
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let idx = ev["index"].as_u64().unwrap_or(0);
                if let Some(pos) = self.blocks.iter().position(|(i, _)| *i == idx) {
                    let (_, b) = self.blocks.remove(pos);
                    if let Block::Tool { id, name, json } = b {
                        let arguments = if json.trim().is_empty() {
                            json!({})
                        } else {
                            serde_json::from_str(&json).with_context(|| {
                                format!("claude: invalid tool input JSON for {name}")
                            })?
                        };
                        self.calls.push(ToolCall {
                            id,
                            name,
                            arguments,
                        });
                    }
                }
            }
            "message_delta" => {
                self.usage.absorb(&ev["usage"]);
                if let Some(s) = ev["delta"]["stop_reason"].as_str() {
                    self.stop = Some(s.to_owned());
                }
            }
            "error" => {
                return Err(anyhow!(
                    "claude stream error: {}",
                    ev["error"]["message"].as_str().unwrap_or("unknown")
                ));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn finish(self, model: &str) -> anyhow::Result<ChatResponse> {
        check_stop(self.stop.as_deref())?;
        Ok(ChatResponse {
            text: self.text,
            tool_calls: self.calls,
            usage: self.usage.finish(model),
        })
    }
}

#[async_trait]
impl LlmProvider for ClaudeProvider {
    fn brain(&self) -> Brain {
        Brain::Claude
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_vision(&self) -> bool {
        true
    }
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, false)).await?;
        let v: Value = resp.json().await.context("claude: invalid JSON response")?;
        parse_response(&self.model, &v)
    }
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(&self.model, req, true)).await?;
        let mut st = StreamState::default();
        http::for_each_sse_json(resp, |ev| st.on_event(&ev, on_delta)).await?;
        st.finish(&self.model)
    }
}
