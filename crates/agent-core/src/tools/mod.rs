//! Tool registry. Each tool declares name, description, JSON schema, risk tier (possibly
//! argument-dependent), sensitivity, relevant intents, a preview, and its implementation.
pub mod builtin;
pub mod shell;

use agent_llm::ToolSpec;
use agent_protocol::{RiskTier, Sensitivity};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type RunFn = Arc<dyn Fn(Value) -> BoxFut<anyhow::Result<ToolOutput>> + Send + Sync>;
type RiskFn = Arc<dyn Fn(&Value) -> RiskTier + Send + Sync>;
type PreviewFn = Arc<dyn Fn(&Value) -> String + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Image {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ToolOutput {
    /// Concise, human-readable result (also what the LLM sees).
    pub text: String,
    /// Optional screenshot: forwarded to the phone and to vision-capable brains.
    pub image: Option<Image>,
}

impl ToolOutput {
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            text: s.into(),
            image: None,
        }
    }
}

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
    pub base_risk: RiskTier,
    pub sensitivity: Sensitivity,
    /// Laya intents this tool is relevant for (used to trim the tool list sent to the LLM).
    pub intents: &'static [&'static str],
    risk_fn: Option<RiskFn>,
    preview_fn: Option<PreviewFn>,
    run: RunFn,
}

impl Tool {
    pub fn new(
        name: &'static str,
        description: &'static str,
        schema: Value,
        risk: RiskTier,
        intents: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            description,
            schema,
            base_risk: risk,
            sensitivity: Sensitivity::Low,
            intents,
            risk_fn: None,
            preview_fn: None,
            run: Arc::new(|_| Box::pin(async { anyhow::bail!("tool not implemented") })),
        }
    }

    /// Synchronous implementation; runs on the blocking pool.
    pub fn blocking<F>(mut self, f: F) -> Self
    where
        F: Fn(Value) -> anyhow::Result<ToolOutput> + Send + Sync + 'static,
    {
        let f = Arc::new(f);
        self.run = Arc::new(move |args| {
            let f = f.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || f(args))
                    .await
                    .map_err(|e| anyhow::anyhow!("tool panicked: {e}"))?
            })
        });
        self
    }

    pub fn run_async<F, Fut>(mut self, f: F) -> Self
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<ToolOutput>> + Send + 'static,
    {
        self.run = Arc::new(move |args| Box::pin(f(args)));
        self
    }

    pub fn risk_with(mut self, f: impl Fn(&Value) -> RiskTier + Send + Sync + 'static) -> Self {
        self.risk_fn = Some(Arc::new(f));
        self
    }

    pub fn preview_with(mut self, f: impl Fn(&Value) -> String + Send + Sync + 'static) -> Self {
        self.preview_fn = Some(Arc::new(f));
        self
    }

    pub fn sensitivity(mut self, s: Sensitivity) -> Self {
        self.sensitivity = s;
        self
    }

    /// Effective tier for these arguments; never below the declared base tier.
    pub fn risk(&self, args: &Value) -> RiskTier {
        match &self.risk_fn {
            Some(f) => f(args).max(self.base_risk),
            None => self.base_risk,
        }
    }

    pub fn needs_approval(&self, args: &Value) -> bool {
        self.risk(args) != RiskTier::Read
    }

    /// Human-readable preview of the effect (NOT yet redacted).
    pub fn preview(&self, args: &Value) -> String {
        match &self.preview_fn {
            Some(f) => f(args),
            None => {
                let a = compact_args(args);
                if a.is_empty() {
                    self.name.to_string()
                } else {
                    format!("{} {a}", self.name)
                }
            }
        }
    }

    pub fn run(&self, args: Value) -> BoxFut<anyhow::Result<ToolOutput>> {
        (self.run)(args)
    }

    /// Provider-safe name (Claude/OpenAI/Gemini only allow `[a-zA-Z0-9_-]`).
    pub fn wire_name(&self) -> String {
        self.name.replace('.', "_")
    }

    pub fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.wire_name(),
            description: self.description.to_string(),
            parameters: self.schema.clone(),
        }
    }
}

pub fn compact_args(args: &Value) -> String {
    match args {
        Value::Object(m) if m.is_empty() => String::new(),
        Value::Null => String::new(),
        v => {
            let s = v.to_string();
            truncate(&s, 300)
        }
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[derive(Default, Clone)]
pub struct ToolRegistry {
    tools: HashMap<String, Arc<Tool>>,
    order: Vec<Arc<Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, t: Tool) {
        let t = Arc::new(t);
        self.tools.insert(t.name.to_string(), t.clone());
        self.tools.insert(t.wire_name(), t.clone());
        self.order.retain(|o| o.name != t.name);
        self.order.push(t);
    }

    pub fn with(mut self, t: Tool) -> Self {
        self.add(t);
        self
    }

    /// Lookup by dotted (`fs.list`) or wire (`fs_list`) name.
    pub fn get(&self, name: &str) -> Option<Arc<Tool>> {
        self.tools.get(name).cloned()
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.order.iter().map(|t| t.name).collect()
    }

    /// Tool specs relevant to `intent` (fewer tokens). Broad intents get everything.
    pub fn specs_for(&self, intent: Option<&str>) -> Vec<ToolSpec> {
        let broad = matches!(intent, None | Some("multi_step_task") | Some("question"));
        self.order
            .iter()
            .filter(|t| broad || t.intents.iter().any(|i| Some(*i) == intent))
            .map(|t| t.spec())
            .collect()
    }
}

/// Small argument helpers for tool implementations.
pub mod args {
    use serde_json::Value;

    pub fn str<'a>(a: &'a Value, k: &str) -> anyhow::Result<&'a str> {
        a.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing string argument `{k}`"))
    }
    pub fn opt_str<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
        a.get(k).and_then(Value::as_str)
    }
    pub fn opt_i64(a: &Value, k: &str) -> Option<i64> {
        a.get(k).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_f64().map(|f| f as i64))
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
        })
    }
    pub fn i64(a: &Value, k: &str) -> anyhow::Result<i64> {
        opt_i64(a, k).ok_or_else(|| anyhow::anyhow!("missing integer argument `{k}`"))
    }
    pub fn opt_bool(a: &Value, k: &str) -> Option<bool> {
        a.get(k).and_then(Value::as_bool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn registry_and_risk() {
        let reg = ToolRegistry::new()
            .with(
                Tool::new(
                    "a.read",
                    "r",
                    json!({"type":"object"}),
                    RiskTier::Read,
                    &["files"],
                )
                .blocking(|_| Ok(ToolOutput::text("hi"))),
            )
            .with(
                Tool::new(
                    "b.write",
                    "w",
                    json!({"type":"object"}),
                    RiskTier::Write,
                    &["shell"],
                )
                .risk_with(|a| {
                    if a.get("x").is_some() {
                        RiskTier::Destructive
                    } else {
                        RiskTier::Read
                    }
                })
                .run_async(|_| async { Ok(ToolOutput::text("async")) }),
            );
        assert_eq!(reg.len(), 2);
        let a = reg.get("a_read").unwrap();
        assert_eq!(a.name, "a.read");
        assert_eq!(a.run(json!({})).await.unwrap().text, "hi");
        let b = reg.get("b.write").unwrap();
        // Risk never drops below the base tier.
        assert_eq!(b.risk(&json!({})), RiskTier::Write);
        assert_eq!(b.risk(&json!({"x":1})), RiskTier::Destructive);
        assert!(b.needs_approval(&json!({})));
        assert!(!a.needs_approval(&json!({})));
        assert_eq!(b.run(json!({})).await.unwrap().text, "async");
        assert_eq!(b.preview(&json!({"x":1})), "b.write {\"x\":1}");
        assert_eq!(reg.specs_for(Some("files")).len(), 1);
        assert_eq!(reg.specs_for(Some("files"))[0].name, "a_read");
        assert_eq!(reg.specs_for(Some("question")).len(), 2);
        assert_eq!(reg.specs_for(None).len(), 2);
    }

    #[test]
    fn truncate_utf8() {
        assert_eq!(truncate("héllo", 2), "h…");
        assert_eq!(truncate("abc", 5), "abc");
    }
}
