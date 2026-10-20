//! Agent-level tests with fake brains/tools (no real LLM, capture, input or audit backends).
use super::*;
use crate::tools::{Tool, ToolOutput};
use agent_llm::{ChatRequest, ChatResponse, DeltaFn, Role, ToolCall, Usage};
use agent_protocol::{
    ApprovalDecision, ApprovalResponse, ChatUser, ControlKill, Ping, SettingsUpdate, TaskState,
    TaskUpdate,
};
use serde_json::json;
use std::collections::VecDeque;

struct FakeLlm {
    brain: Brain,
    script: Mutex<VecDeque<ChatResponse>>,
    seen: Mutex<Vec<ChatRequest>>,
    fail: bool,
}

impl FakeLlm {
    fn new(brain: Brain, script: Vec<ChatResponse>) -> Arc<Self> {
        Arc::new(Self {
            brain,
            script: Mutex::new(script.into()),
            seen: Mutex::new(vec![]),
            fail: false,
        })
    }
}

#[async_trait]
impl LlmProvider for FakeLlm {
    fn brain(&self) -> Brain {
        self.brain
    }
    fn model(&self) -> &str {
        "fake"
    }
    fn supports_vision(&self) -> bool {
        false
    }
    async fn chat(&self, req: &ChatRequest) -> anyhow::Result<ChatResponse> {
        self.chat_stream(req, &|_| {}).await
    }
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        on_delta: DeltaFn<'_>,
    ) -> anyhow::Result<ChatResponse> {
        self.seen.lock().unwrap().push(req.clone());
        if self.fail {
            anyhow::bail!("provider down");
        }
        let r = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| text("done"));
        if !r.text.is_empty() {
            on_delta(&r.text);
        }
        Ok(r)
    }
}

fn text(s: &str) -> ChatResponse {
    ChatResponse {
        text: s.into(),
        tool_calls: vec![],
        usage: Usage::default(),
    }
}
fn call(name: &str, args: serde_json::Value) -> ChatResponse {
    ChatResponse {
        text: String::new(),
        tool_calls: vec![ToolCall {
            id: format!("c-{name}"),
            name: name.into(),
            arguments: args,
        }],
        usage: Usage::default(),
    }
}

struct DownDecider;
#[async_trait]
impl Decider for DownDecider {
    async fn decide(&self, _: &str) -> anyhow::Result<LayaDecision> {
        anyhow::bail!("connection refused")
    }
}

#[derive(Default)]
struct VecAudit(Mutex<Vec<AuditEntry>>);
impl AuditSink for VecAudit {
    fn append(&self, e: &AuditEntry) {
        self.0.lock().unwrap().push(e.clone());
    }
}

fn fake_tools() -> ToolRegistry {
    ToolRegistry::new()
        .with(
            Tool::new(
                "app.launch",
                "launch",
                json!({"type":"object"}),
                RiskTier::Read,
                &["open_app"],
            )
            .blocking(|a| {
                Ok(ToolOutput::text(format!(
                    "Opened {}.",
                    a["app"].as_str().unwrap_or("?")
                )))
            }),
        )
        .with(
            Tool::new(
                "fs.write",
                "write",
                json!({"type":"object"}),
                RiskTier::Write,
                &["files"],
            )
            .blocking(|_| Ok(ToolOutput::text("wrote"))),
        )
        .with(
            Tool::new(
                "fs.delete",
                "delete",
                json!({"type":"object"}),
                RiskTier::Destructive,
                &["files"],
            )
            .blocking(|_| Ok(ToolOutput::text("deleted"))),
        )
        .with(
            Tool::new(
                "slow.read",
                "slow",
                json!({"type":"object"}),
                RiskTier::Read,
                &["files"],
            )
            .run_async(|_| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(ToolOutput::text("late"))
            }),
        )
        .with(
            Tool::new(
                "clipboard.get",
                "clip",
                json!({"type":"object"}),
                RiskTier::Read,
                &["clipboard"],
            )
            .sensitivity(agent_protocol::Sensitivity::High)
            .blocking(|_| Ok(ToolOutput::text("hunter2-clip"))),
        )
}

struct Harness {
    agent: Agent,
    audit: Arc<VecAudit>,
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
}

fn harness(cloud: Vec<Arc<dyn LlmProvider>>, local: Option<Arc<dyn LlmProvider>>) -> Harness {
    harness_t(cloud, local, 5)
}

fn harness_t(
    cloud: Vec<Arc<dyn LlmProvider>>,
    local: Option<Arc<dyn LlmProvider>>,
    approval_secs: u64,
) -> Harness {
    let audit = Arc::new(VecAudit::default());
    let parts = Parts {
        tools: fake_tools(),
        decider: Some(Arc::new(DownDecider)),
        cloud,
        local,
        audit: audit.clone(),
        redact: Arc::new(|s: &str| s.replace("SECRET", "[REDACTED]")),
        capture: Arc::new(CaptureSource::new(|| panic!("no capture in tests"))),
        notifier: Arc::new(|_, _| {}),
        roots: None,
    };
    let cfg = AgentConfig {
        approval_timeout_secs: approval_secs,
        max_agent_steps: 5,
        shared_roots: vec![],
        ..AgentConfig::default()
    };
    let agent = Agent::with_parts(cfg, parts);
    let (tx, rx) = mpsc::channel(256);
    Harness {
        agent,
        audit,
        tx,
        rx,
    }
}

impl Harness {
    async fn chat(&self, s: &str) {
        self.agent
            .handle(
                "phone:test",
                Message::ChatUser(ChatUser {
                    text: s.into(),
                    voice: false,
                }),
                self.tx.clone(),
            )
            .await;
    }
    async fn next_until(&mut self, mut f: impl FnMut(&Message) -> bool) -> Message {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(5), self.rx.recv())
                .await
                .expect("timed out waiting for message")
                .expect("closed");
            if f(&m) {
                return m;
            }
        }
    }
    async fn final_reply(&mut self) -> (String, Brain) {
        match self
            .next_until(|m| matches!(m, Message::ChatAgent(c) if c.final_))
            .await
        {
            Message::ChatAgent(c) => (c.text, c.brain),
            _ => unreachable!(),
        }
    }
    async fn final_state(&mut self) -> TaskUpdate {
        match self
            .next_until(|m| matches!(m, Message::TaskUpdate(u) if matches!(u.state, TaskState::Done | TaskState::Failed | TaskState::Cancelled)))
            .await
        {
            Message::TaskUpdate(u) => u,
            _ => unreachable!(),
        }
    }
    async fn approval(&mut self) -> agent_protocol::ApprovalRequest {
        match self
            .next_until(|m| matches!(m, Message::ApprovalRequest(_)))
            .await
        {
            Message::ApprovalRequest(r) => r,
            _ => unreachable!(),
        }
    }
    async fn respond(&self, id: Uuid, d: ApprovalDecision) {
        self.agent
            .handle(
                "phone:test",
                Message::ApprovalResponse(ApprovalResponse {
                    approval_id: id,
                    decision: d,
                }),
                self.tx.clone(),
            )
            .await;
    }
}

#[tokio::test]
async fn rules_fast_path_needs_no_model() {
    let mut h = harness(vec![], None);
    h.chat("open firefox").await;
    let (t, b) = h.final_reply().await;
    assert_eq!(t, "Opened firefox.");
    assert_eq!(b, Brain::Rules);
    let u = h.final_state().await;
    assert_eq!(u.state, TaskState::Done);
    assert_eq!(u.steps[0].brain, Brain::Rules);
    let a = h.audit.0.lock().unwrap();
    assert_eq!(a[0].tool, "app.launch");
    assert_eq!(a[0].actor, "phone:test");
}

#[tokio::test]
async fn agent_loop_with_tool_calls_and_approval() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![
            call("fs_write", json!({"path":"Documents/a","content":"SECRET"})),
            text("All done."),
        ],
    );
    let mut h = harness(vec![llm.clone()], None);
    h.chat("write a summary of my week into a new note").await;
    let req = h.approval().await;
    assert_eq!(req.tool, "fs.write");
    assert_eq!(req.risk, RiskTier::Write);
    assert!(
        !req.preview.unwrap().contains("SECRET"),
        "preview is redacted"
    );
    h.respond(req.approval_id, ApprovalDecision::Approve).await;
    let (t, b) = h.final_reply().await;
    assert_eq!((t.as_str(), b), ("All done.", Brain::Claude));
    let u = h.final_state().await;
    assert_eq!(u.state, TaskState::Done);
    assert!(
        u.steps
            .iter()
            .any(|s| s.tool == "router" && s.brain == Brain::Rules)
    ); // Laya down -> heuristics
    assert!(
        u.steps.iter().any(|s| s.tool == "fs.write"
            && s.brain == Brain::Claude
            && s.state == TaskState::Done)
    );
    // Second LLM call got the tool result, and nothing unredacted went to the cloud.
    let seen = llm.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[1]
            .messages
            .iter()
            .any(|m| m.role == Role::Tool && m.content == "wrote")
    );
    assert!(seen.iter().all(|r| {
        !serde_json::to_string(&r.messages)
            .unwrap()
            .contains("SECRET")
    }));
    assert!(seen[0].system.len() < 800, "system prompt stays short");
    let a = h.audit.0.lock().unwrap();
    assert!(
        a.iter().any(|e| e.tool == "fs.write"
            && e.brain == Brain::Claude
            && !e.args.contains("SECRET"))
    );
}

#[tokio::test]
async fn denied_step_tells_llm() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![
            call("fs.delete", json!({"path":"Documents/a"})),
            text("OK, not deleted."),
        ],
    );
    let mut h = harness(vec![llm.clone()], None);
    h.chat("delete the old report and then tidy up the folder")
        .await;
    let req = h.approval().await;
    assert_eq!(req.risk, RiskTier::Destructive);
    h.respond(req.approval_id, ApprovalDecision::Deny).await;
    let (t, _) = h.final_reply().await;
    assert_eq!(t, "OK, not deleted.");
    let seen = llm.seen.lock().unwrap();
    assert!(
        seen[1]
            .messages
            .iter()
            .any(|m| m.role == Role::Tool && m.content.contains("user denied"))
    );
    assert!(
        h.audit
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.result.contains("denied"))
    );
}

#[tokio::test]
async fn approve_for_task_remembers_write_tool() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![
            call("fs.write", json!({"path":"a"})),
            call("fs.write", json!({"path":"b"})),
            text("two files"),
        ],
    );
    let mut h = harness(vec![llm], None);
    h.chat("create two notes for me and then fill them").await;
    let req = h.approval().await;
    h.respond(req.approval_id, ApprovalDecision::ApproveForTask)
        .await;
    let mut approvals = 0;
    let reply = loop {
        match h
            .next_until(|m| {
                matches!(m, Message::ApprovalRequest(_))
                    || matches!(m, Message::ChatAgent(c) if c.final_)
            })
            .await
        {
            Message::ApprovalRequest(_) => approvals += 1,
            Message::ChatAgent(c) => break c.text,
            _ => unreachable!(),
        }
    };
    assert_eq!(approvals, 0, "second write did not ask again");
    assert_eq!(reply, "two files");
}

#[tokio::test]
async fn approve_for_task_does_not_cover_destructive() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![
            call("fs.delete", json!({"path":"a"})),
            call("fs.delete", json!({"path":"b"})),
            text("ok"),
        ],
    );
    let mut h = harness(vec![llm], None);
    h.chat("delete these two files and then report").await;
    let r1 = h.approval().await;
    h.respond(r1.approval_id, ApprovalDecision::ApproveForTask)
        .await;
    let r2 = h.approval().await;
    assert_ne!(r1.approval_id, r2.approval_id);
    assert!(r2.expires_at_ms <= approvals::now_ms() + 60_000);
    h.respond(r2.approval_id, ApprovalDecision::Approve).await;
    assert_eq!(h.final_reply().await.0, "ok");
}

#[tokio::test]
async fn expired_approval_fails_gracefully() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![call("fs.write", json!({})), text("gave up")],
    );
    let mut h = harness_t(vec![llm.clone()], None, 1);
    h.chat("write a note and then save it").await;
    let _ = h.approval().await;
    assert_eq!(h.final_reply().await.0, "gave up");
    assert!(
        llm.seen.lock().unwrap()[1]
            .messages
            .iter()
            .any(|m| m.content.contains("expired"))
    );
}

#[tokio::test]
async fn unknown_approval_id_rejected() {
    let mut h = harness(vec![], None);
    h.respond(Uuid::new_v4(), ApprovalDecision::Approve).await;
    let m = h.next_until(|_| true).await;
    assert!(matches!(m, Message::Error(e) if e.code == "unknown_approval"));
}

#[tokio::test]
async fn kill_switch_cancels_running_task() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![call("slow.read", json!({})), text("never")],
    );
    let mut h = harness(vec![llm], None);
    h.chat("read everything slowly and then summarize").await;
    h.next_until(
        |m| matches!(m, Message::TaskUpdate(u) if u.steps.iter().any(|s| s.tool == "slow.read")),
    )
    .await;
    let start = std::time::Instant::now();
    h.agent
        .handle(
            "phone:test",
            Message::ControlKill(ControlKill {
                reason: Some("panic".into()),
            }),
            h.tx.clone(),
        )
        .await;
    let u = h.final_state().await;
    assert_eq!(u.state, TaskState::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(
        h.audit
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.tool == "control.kill")
    );
    // The agent still works after a kill.
    h.chat("open firefox").await;
    assert_eq!(h.final_reply().await.0, "Opened firefox.");
}

#[tokio::test]
async fn kill_denies_pending_approvals() {
    let llm = FakeLlm::new(Brain::Claude, vec![call("fs.write", json!({})), text("x")]);
    let mut h = harness(vec![llm], None);
    h.chat("write a note and then save it").await;
    let req = h.approval().await;
    assert_eq!(h.agent.pending_approvals(), 1);
    h.agent.kill("test");
    let u = h.final_state().await;
    assert_eq!(u.state, TaskState::Cancelled);
    assert_eq!(h.agent.pending_approvals(), 0);
    // A late approval for the killed request is rejected.
    h.respond(req.approval_id, ApprovalDecision::Approve).await;
    h.next_until(|m| matches!(m, Message::Error(e) if e.code == "unknown_approval"))
        .await;
}

#[tokio::test]
async fn high_sensitivity_never_reaches_cloud() {
    let llm = FakeLlm::new(Brain::Claude, vec![text("should not be called")]);
    let mut h = harness(vec![llm.clone()], None);
    h.chat("what is my bank password stored in the notes").await;
    let (t, _) = h.final_reply().await;
    assert!(t.contains("sensitive"), "{t}");
    assert!(llm.seen.lock().unwrap().is_empty());
    // Allowed via settings -> goes to cloud.
    h.agent
        .handle(
            "phone:test",
            Message::SettingsUpdate(SettingsUpdate {
                cloud_allow_high_sensitivity: Some(true),
                ..Default::default()
            }),
            h.tx.clone(),
        )
        .await;
    h.chat("what is my bank password stored in the notes").await;
    assert_eq!(h.final_reply().await.0, "should not be called");
}

#[tokio::test]
async fn high_sensitivity_routes_local_when_available() {
    let cloud = FakeLlm::new(Brain::Claude, vec![]);
    let local = FakeLlm::new(Brain::Local, vec![text("local answer")]);
    let mut h = harness(vec![cloud.clone()], Some(local.clone()));
    h.chat("summarize my api key notes").await;
    assert_eq!(
        h.final_reply().await,
        ("local answer".to_string(), Brain::Local)
    );
    assert!(cloud.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sensitive_tool_output_withheld_from_cloud() {
    let llm = FakeLlm::new(
        Brain::Claude,
        vec![call("clipboard.get", json!({})), text("shown")],
    );
    let mut h = harness(vec![llm.clone()], None);
    h.chat("look at what I copied and then explain it").await;
    // heuristic marks "copied"? no: low sensitivity, so cloud is used; tool output is High.
    let (first, _) = h.final_reply().await;
    assert_eq!(first, "hunter2-clip");
    assert_eq!(h.final_reply().await.0, "shown");
    let seen = llm.seen.lock().unwrap();
    assert!(
        !serde_json::to_string(&seen[1].messages)
            .unwrap()
            .contains("hunter2")
    );
}

#[tokio::test]
async fn provider_fallback_and_no_brain() {
    let bad = Arc::new(FakeLlm {
        brain: Brain::Claude,
        script: Mutex::new(VecDeque::new()),
        seen: Mutex::new(vec![]),
        fail: true,
    });
    let good = FakeLlm::new(Brain::Gemini, vec![text("from gemini")]);
    let mut h = harness(vec![bad.clone(), good], None);
    h.chat("explain how tides work").await;
    assert_eq!(
        h.final_reply().await,
        ("from gemini".to_string(), Brain::Gemini)
    );
    assert_eq!(bad.seen.lock().unwrap().len(), 1);

    let mut h = harness(vec![], None);
    h.chat("explain how tides work").await;
    assert!(h.final_reply().await.0.contains("API key"));
    assert_eq!(h.final_state().await.state, TaskState::Failed);
}

#[tokio::test]
async fn ping_settings_and_unexpected() {
    let mut h = harness(vec![], None);
    h.agent
        .handle("p", Message::Ping(Ping { t_ms: 42 }), h.tx.clone())
        .await;
    assert_eq!(
        h.next_until(|_| true).await,
        Message::Pong(Ping { t_ms: 42 })
    );
    h.agent
        .handle(
            "p",
            Message::SettingsUpdate(SettingsUpdate {
                cloud_enabled: Some(false),
                ..Default::default()
            }),
            h.tx.clone(),
        )
        .await;
    assert!(!h.agent.policy().cloud_enabled);
    assert!(matches!(h.next_until(|_| true).await, Message::Notify(_)));
    h.agent
        .handle("p", Message::Pong(Ping { t_ms: 1 }), h.tx.clone())
        .await;
    assert!(
        matches!(h.next_until(|_| true).await, Message::Error(e) if e.code == "unexpected_message")
    );
}

#[tokio::test]
async fn streams_deltas() {
    let llm = FakeLlm::new(Brain::Claude, vec![text("hello there")]);
    let mut h = harness(vec![llm], None);
    h.chat("explain rust lifetimes").await;
    let m = h.next_until(|m| matches!(m, Message::ChatAgent(_))).await;
    assert!(matches!(m, Message::ChatAgent(c) if !c.final_ && c.text == "hello there"));
}
