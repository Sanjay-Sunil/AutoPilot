//! Client for a local `laya-serve` (Jev-compatible `POST /v1/systemone`).
//!
//! [`LayaClient::decide`] asks intent / risk / sensitivity / needs_cloud in ONE forward pass.
//!
//! Measured on the dev laptop (24-core x86, CPU torch, `LAYA_THREADS=4`, english checkpoint,
//! laya 0.4.12, other heavy builds running concurrently so treat as an upper-ish bound):
//! - one `noul` question: ~270 ms
//! - full `decide()` (12-way intent + 3 choices + 1 noul): ~2.6-3.5 s typical, up to ~8 s when
//!   the machine was saturated; warm model, measured client side. The 12 option descriptions
//!   dominate the cost (labels-only intent: ~1.7-2 s for the full set).
//! - first call after `LAYA_IDLE_UNLOAD_SECONDS` pays a cold checkpoint load.
//!
//! Zero-shot accuracy is decent on clear commands (system_info, screen, clipboard, files,
//! window_control) but `needs_cloud` from the `noul` head alone is weak, so [`LayaDecision::needs_cloud`]
//! is `max(noul, P(intent = multi_step_task))`. Treat everything here as advisory input to the
//! deterministic router, never as the final policy.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use agent_protocol::{RiskTier, Sensitivity};
use anyhow::{Context, anyhow};
use serde_json::{Value, json};

use crate::http::{self, RetryPolicy};
use crate::{INTENTS, LayaDecision};

pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8765";

/// Short option descriptions: every token of option text costs CPU time on each decide().
const INTENT_CRITERIA: &[(&str, &str)] = &[
    ("open_app", "open or launch an app like firefox or spotify"),
    ("window_control", "focus, move, close windows"),
    ("files", "find, copy, move, delete files"),
    ("shell", "run a terminal command"),
    ("system_control", "volume, brightness, wifi, power"),
    ("system_info", "battery, cpu, disk, network status"),
    ("browser", "visit a website, search the web"),
    ("screen", "see what is on screen"),
    ("clipboard", "read or set the clipboard"),
    ("type_or_keys", "type text or press keys"),
    ("question", "answer a question from knowledge, no action"),
    ("multi_step_task", "several steps, or write content"),
];

type Criteria = &'static [(&'static str, &'static str)];

const QUESTIONS: &[(&str, &str, &str, Criteria)] = &[
    (
        "intent",
        "choice",
        "Which kind of laptop action is requested?",
        INTENT_CRITERIA,
    ),
    (
        "risk",
        "choice",
        "What is the worst effect of doing this on the laptop?",
        &[
            ("read", "only reads or shows information"),
            ("write", "changes something reversible"),
            ("destructive", "deletes, overwrites, sends or pays"),
        ],
    ),
    (
        "sensitivity",
        "choice",
        "How sensitive is the data involved?",
        &[
            ("low", "ordinary harmless information"),
            ("medium", "personal files or work documents"),
            ("high", "passwords, keys, money, health, private messages"),
        ],
    ),
    (
        "needs_cloud",
        "noul",
        "Does this need a smart assistant to write long text, write code, plan many steps, or reason deeply?",
        &[],
    ),
];

/// The question set sent by [`LayaClient::decide`], serialized with option order preserved.
/// Order matters: Laya's answers shift when choice options are reordered, and
/// `serde_json::Map` (without `preserve_order`) would sort them alphabetically.
pub fn decide_questions_json() -> &'static str {
    static Q: OnceLock<String> = OnceLock::new();
    Q.get_or_init(|| {
        let s = |x: &str| serde_json::to_string(x).unwrap_or_default();
        let qs: Vec<String> = QUESTIONS
            .iter()
            .map(|(id, ty, instr, crit)| {
                let mut q = format!(
                    "{}:{{\"type\":{},\"instructions\":{}",
                    s(id),
                    s(ty),
                    s(instr)
                );
                if !crit.is_empty() {
                    let c: Vec<String> = crit
                        .iter()
                        .map(|(k, d)| format!("{}:{}", s(k), s(d)))
                        .collect();
                    q.push_str(&format!(",\"criteria\":{{{}}}", c.join(",")));
                }
                q.push('}');
                q
            })
            .collect();
        format!("{{{}}}", qs.join(","))
    })
}

/// [`decide_questions_json`] parsed (key order is not preserved in a `Value`).
pub fn decide_questions() -> &'static Value {
    static Q: OnceLock<Value> = OnceLock::new();
    Q.get_or_init(|| serde_json::from_str(decide_questions_json()).unwrap_or(Value::Null))
}

/// HTTP client for a local `laya-serve` (default http://127.0.0.1:8765).
pub struct LayaClient {
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
    pub(crate) api_key: Option<String>,
}

impl std::fmt::Debug for LayaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayaClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl LayaClient {
    pub fn new(base_url: String) -> Self {
        let base = if base_url.is_empty() {
            DEFAULT_BASE_URL.to_owned()
        } else {
            base_url
        };
        Self {
            // Local server: fast connect timeout; total covers a cold checkpoint load.
            client: http::build_client(Duration::from_secs(1), Duration::from_secs(60)),
            base_url: base.trim_end_matches('/').to_owned(),
            api_key: None,
        }
    }
    /// Bearer token if `laya-serve` runs with `LAYA_API_KEY`.
    pub fn with_api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key.filter(|k| !k.is_empty());
        self
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(k) => rb.bearer_auth(k),
            None => rb,
        }
    }

    pub async fn healthy(&self) -> bool {
        let get = |path: &str| {
            self.auth(self.client.get(format!("{}{path}", self.base_url)))
                .timeout(Duration::from_secs(1))
                .send()
        };
        match get("/health").await {
            Ok(r) if r.status().is_success() => match r.json::<Value>().await {
                Ok(v) => v["status"].as_str().is_none_or(|s| s == "ok"),
                Err(_) => true,
            },
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                get("/models").await.is_ok_and(|r| r.status().is_success())
            }
            _ => false,
        }
    }

    pub async fn system_one(&self, state: &Value, questions: &Value) -> anyhow::Result<Value> {
        self.post(json!({"state": state, "questions": questions}).to_string())
            .await
    }

    async fn post(&self, body: String) -> anyhow::Result<Value> {
        let url = format!("{}/v1/systemone", self.base_url);
        let policy = RetryPolicy {
            retries: 1,
            base: Duration::from_millis(100),
            max: Duration::from_millis(500),
        };
        let resp = http::send_with_retry(policy, "laya", || {
            self.auth(self.client.post(&url))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone())
        })
        .await?;
        resp.json().await.context("laya: invalid JSON response")
    }

    pub async fn decide(&self, text: &str) -> anyhow::Result<LayaDecision> {
        let t0 = Instant::now();
        let body = format!(
            "{{\"state\":{},\"questions\":{}}}",
            json!({"request": text}),
            decide_questions_json()
        );
        let resp = self.post(body).await?;
        let mut d = parse_decision(&resp)?;
        d.latency_ms = t0.elapsed().as_millis() as u64;
        Ok(d)
    }
}

/// Map a `/v1/systemone` response for [`decide_questions`] into a [`LayaDecision`]
/// (`latency_ms` is left 0; the caller measures it).
pub fn parse_decision(resp: &Value) -> anyhow::Result<LayaDecision> {
    let a = resp
        .get("answers")
        .ok_or_else(|| anyhow!("laya: response has no answers"))?;
    let choice = |q: &str| -> anyhow::Result<&str> {
        a[q]["choice"]
            .as_str()
            .ok_or_else(|| anyhow!("laya: missing choice for {q}"))
    };
    let intent = choice("intent")?;
    if !INTENTS.contains(&intent) {
        return Err(anyhow!("laya: unknown intent {intent:?}"));
    }
    let intent_confidence = a["intent"]["answer_confidence"]
        .as_f64()
        .or_else(|| a["intent"]["probabilities"][intent].as_f64())
        .or_else(|| a["intent"]["confidence"].as_f64())
        .unwrap_or(0.0) as f32;
    let risk = match choice("risk")? {
        "read" => RiskTier::Read,
        "write" => RiskTier::Write,
        "destructive" => RiskTier::Destructive,
        other => return Err(anyhow!("laya: unknown risk {other:?}")),
    };
    let sensitivity = match choice("sensitivity")? {
        "low" => Sensitivity::Low,
        "medium" => Sensitivity::Medium,
        "high" => Sensitivity::High,
        other => return Err(anyhow!("laya: unknown sensitivity {other:?}")),
    };
    let noul = a["needs_cloud"]["noul"]
        .as_f64()
        .ok_or_else(|| anyhow!("laya: missing noul for needs_cloud"))?;
    let p_multi = a["intent"]["probabilities"]["multi_step_task"]
        .as_f64()
        .unwrap_or(0.0);
    let needs_cloud = noul.max(p_multi).clamp(0.0, 1.0) as f32;
    Ok(LayaDecision {
        intent: intent.to_owned(),
        intent_confidence,
        risk,
        sensitivity,
        needs_cloud,
        latency_ms: 0,
    })
}
