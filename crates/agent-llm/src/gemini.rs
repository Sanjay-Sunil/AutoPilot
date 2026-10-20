//! Gemini API `generateContent` / `streamGenerateContent?alt=sse` with function declarations.
//!
//! Gemini 3 returns a `thoughtSignature` on function-call parts that must be echoed back on the
//! next turn. [`ToolCall`] has no slot for it, so it is carried inside the call id as
//! `<id>#ts=<signature>` and unpacked when the history is sent back.
use agent_protocol::Brain;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::http::{self, RetryPolicy};
use crate::{
    ChatRequest, ChatResponse, DeltaFn, LlmProvider, Msg, Role, ToolCall, Usage, price_per_mtok,
};

/// `gemini-3.8-flash`: current Flash model in ai.google.dev/gemini-api/docs/models (checked
/// 2026-10-20); used in Google's own function-calling docs.
pub const DEFAULT_MODEL: &str = "gemini-3.8-flash";
pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const SIG_SEP: &str = "#ts=";

pub struct GeminiProvider {
    pub(crate) client: reqwest::Client,
    pub(crate) api_key: String,
    pub(crate) model: String,
    pub(crate) base_url: String,
    pub(crate) retry: RetryPolicy,
}

impl std::fmt::Debug for GeminiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeminiProvider")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GeminiProvider {
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
    async fn send(&self, body: &Value, stream: bool) -> anyhow::Result<reqwest::Response> {
        let url = if stream {
            format!(
                "{}/v1beta/models/{}:streamGenerateContent?alt=sse",
                self.base_url, self.model
            )
        } else {
            format!(
                "{}/v1beta/models/{}:generateContent",
                self.base_url, self.model
            )
        };
        http::send_with_retry(self.retry, "gemini", || {
            self.client
                .post(&url)
                .header("x-goog-api-key", &self.api_key)
                .json(body)
        })
        .await
    }
}

fn split_id(id: &str) -> (&str, Option<&str>) {
    match id.split_once(SIG_SEP) {
        Some((a, s)) => (a, Some(s)),
        None => (id, None),
    }
}

fn inline_jpeg(jpeg: &[u8]) -> Value {
    json!({"inlineData": {"mimeType": "image/jpeg", "data": http::b64(jpeg)}})
}

pub fn map_contents(msgs: &[Msg]) -> Vec<Value> {
    let mut out: Vec<(&'static str, Vec<Value>)> = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        let (role, parts) = match m.role {
            Role::User => {
                let mut p: Vec<Value> = Vec::new();
                if !m.content.is_empty() || m.images.is_empty() {
                    p.push(json!({"text": m.content}));
                }
                p.extend(m.images.iter().map(|i| inline_jpeg(i)));
                ("user", p)
            }
            Role::Assistant => {
                let mut p = Vec::new();
                if !m.content.is_empty() {
                    p.push(json!({"text": m.content}));
                }
                for c in &m.tool_calls {
                    let (id, sig) = split_id(&c.id);
                    let mut fc = json!({"name": c.name, "args": if c.arguments.is_object() { c.arguments.clone() } else { json!({}) }});
                    if !id.is_empty() && !id.starts_with("gemini-call-") {
                        fc["id"] = json!(id);
                    }
                    let mut part = json!({"functionCall": fc});
                    if let Some(s) = sig {
                        part["thoughtSignature"] = json!(s);
                    }
                    p.push(part);
                }
                ("model", p)
            }
            Role::Tool => {
                let call_id = m.tool_call_id.as_deref().unwrap_or_default();
                // Find the function name from the assistant turn that issued this call.
                let name = msgs[..i]
                    .iter()
                    .rev()
                    .flat_map(|x| x.tool_calls.iter())
                    .find(|c| c.id == call_id)
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| "tool".to_owned());
                let (id, _) = split_id(call_id);
                let mut fr = json!({"name": name, "response": {"content": m.content}});
                if !id.is_empty() && !id.starts_with("gemini-call-") {
                    fr["id"] = json!(id);
                }
                let mut p = vec![json!({"functionResponse": fr})];
                p.extend(m.images.iter().map(|i| inline_jpeg(i)));
                ("user", p)
            }
        };
        if parts.is_empty() {
            continue;
        }
        match out.last_mut() {
            Some((r, p)) if *r == role => p.extend(parts),
            _ => out.push((role, parts)),
        }
    }
    out.into_iter()
        .map(|(role, parts)| json!({"role": role, "parts": parts}))
        .collect()
}

pub fn build_body(req: &ChatRequest) -> Value {
    let mut b = Map::new();
    if !req.system.is_empty() {
        b.insert(
            "systemInstruction".into(),
            json!({"parts": [{"text": req.system}]}),
        );
    }
    b.insert("contents".into(), Value::Array(map_contents(&req.messages)));
    if !req.tools.is_empty() {
        let decls: Vec<Value> =
            req.tools.iter().map(|t| json!({"name": t.name, "description": t.description, "parameters": t.parameters})).collect();
        b.insert("tools".into(), json!([{"functionDeclarations": decls}]));
    }
    let mut gc = json!({"maxOutputTokens": req.max_tokens});
    if let Some(t) = req.temperature {
        gc["temperature"] = json!(t);
    }
    b.insert("generationConfig".into(), gc);
    Value::Object(b)
}

/// Accumulates one or more `GenerateContentResponse` chunks (non-streaming = one chunk).
#[derive(Default)]
pub struct StreamState {
    text: String,
    calls: Vec<ToolCall>,
    usage: Value,
}

impl StreamState {
    pub fn on_chunk(&mut self, v: &Value, on_delta: DeltaFn<'_>) -> anyhow::Result<()> {
        if let Some(e) = v.get("error") {
            return Err(anyhow!(
                "gemini: {}",
                e["message"].as_str().unwrap_or("error")
            ));
        }
        if v["usageMetadata"].is_object() {
            self.usage = v["usageMetadata"].clone();
        }
        if let Some(r) = v["promptFeedback"]["blockReason"].as_str() {
            return Err(anyhow!("gemini: prompt blocked: {r}"));
        }
        let parts = v["candidates"][0]["content"]["parts"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        for p in parts {
            if p["thought"].as_bool() == Some(true) {
                continue;
            }
            if let Some(t) = p["text"].as_str() {
                if !t.is_empty() {
                    self.text.push_str(t);
                    on_delta(t);
                }
            } else if p["functionCall"].is_object() {
                let fc = &p["functionCall"];
                let mut id = fc["id"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("gemini-call-{}", self.calls.len()));
                if let Some(sig) = p["thoughtSignature"].as_str() {
                    id = format!("{id}{SIG_SEP}{sig}");
                }
                self.calls.push(ToolCall {
                    id,
                    name: fc["name"].as_str().unwrap_or_default().to_owned(),
                    arguments: if fc["args"].is_object() {
                        fc["args"].clone()
                    } else {
                        json!({})
                    },
                });
            }
        }
        Ok(())
    }

    pub fn finish(self, model: &str) -> ChatResponse {
        let u = &self.usage;
        let input = u["promptTokenCount"].as_u64().unwrap_or(0);
        let cached = u["cachedContentTokenCount"]
            .as_u64()
            .unwrap_or(0)
            .min(input);
        let output = u["candidatesTokenCount"].as_u64().unwrap_or(0)
            + u["thoughtsTokenCount"].as_u64().unwrap_or(0);
        let (pin, pout) = price_per_mtok(Brain::Gemini, model);
        let cost =
            ((input - cached) as f64 * pin + cached as f64 * pin * 0.1 + output as f64 * pout)
                / 1e6;
        ChatResponse {
            text: self.text,
            tool_calls: self.calls,
            usage: Usage {
                input_tokens: input,
                output_tokens: output,
                cost_usd: cost,
            },
        }
    }
}

#[async_trait]
impl LlmProvider for GeminiProvider {
    fn brain(&self) -> Brain {
        Brain::Gemini
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn supports_vision(&self) -> bool {
        true
    }
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(req), false).await?;
        let v: Value = resp.json().await.context("gemini: invalid JSON response")?;
        let mut st = StreamState::default();
        st.on_chunk(&v, &|_| {})?;
        Ok(st.finish(&self.model))
    }
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse> {
        let resp = self.send(&build_body(req), true).await?;
        let mut st = StreamState::default();
        http::for_each_sse_json(resp, |v| st.on_chunk(&v, on_delta)).await?;
        Ok(st.finish(&self.model))
    }
}
