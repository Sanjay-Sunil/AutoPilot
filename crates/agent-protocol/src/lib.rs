//! Shared wire protocol between the phone and the laptop agent.
//!
//! Every control message is a JSON [`Envelope`]. On the wire each envelope is
//! encrypted inside a Noise transport message (see `docs/protocol.md`).
//! TypeScript bindings are generated with `ts-rs` into `apps/mobile/src/protocol/`
//! by running `cargo test -p agent-protocol export_bindings`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u8 = 1;
/// Max encrypted Noise message size; plaintext must leave 16 bytes for the tag.
pub const MAX_NOISE_MSG: usize = 65_535;
/// File chunk size used by `file.chunk` (base64 inside JSON keeps us well under the Noise limit).
pub const FILE_CHUNK_SIZE: usize = 32 * 1024;

/// Message envelope: `{ "v": 1, "id": "uuid", "session": "uuid", "seq": 42, "type": "...", "payload": {} }`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Envelope {
    pub v: u8,
    #[ts(type = "string")]
    pub id: Uuid,
    #[ts(type = "string")]
    pub session: Uuid,
    /// Strictly increasing per sender per session. Receivers drop anything `<=` the last seen.
    #[ts(type = "number")]
    pub seq: u64,
    #[serde(flatten)]
    pub msg: Message,
}

impl Envelope {
    pub fn new(session: Uuid, seq: u64, msg: Message) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: Uuid::new_v4(),
            session,
            seq,
            msg,
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let env: Envelope =
            serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        if env.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(env.v));
        }
        Ok(env)
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Malformed(String),
    UnsupportedVersion(u8),
    Replay { last: u64, got: u64 },
}

impl std::error::Error for ProtocolError {}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed message: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::Replay { last, got } => {
                write!(f, "replayed or reordered seq {got} (last {last})")
            }
        }
    }
}

/// Tracks the last accepted sequence number from the peer.
#[derive(Debug, Default, Clone)]
pub struct SeqGuard {
    last: Option<u64>,
}

impl SeqGuard {
    pub fn check(&mut self, seq: u64) -> Result<(), ProtocolError> {
        if let Some(last) = self.last {
            if seq <= last {
                return Err(ProtocolError::Replay { last, got: seq });
            }
        }
        self.last = Some(seq);
        Ok(())
    }
}

/// All message types. Serialized as `"type": "<dotted.name>", "payload": {...}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "type", content = "payload")]
#[ts(export)]
pub enum Message {
    // ---- pairing (first message after a Noise handshake with an unknown phone) ----
    #[serde(rename = "pair.claim")]
    PairClaim(PairClaim),
    #[serde(rename = "pair.result")]
    PairResult(PairResult),

    // ---- phone -> laptop ----
    #[serde(rename = "chat.user")]
    ChatUser(ChatUser),
    #[serde(rename = "approval.response")]
    ApprovalResponse(ApprovalResponse),
    #[serde(rename = "screen.request")]
    ScreenRequest(ScreenRequest),
    #[serde(rename = "file.offer")]
    FileOffer(FileOffer),
    #[serde(rename = "file.accept")]
    FileAccept(FileAccept),
    #[serde(rename = "file.request")]
    FileRequest(FileRequest),
    #[serde(rename = "control.kill")]
    ControlKill(ControlKill),
    #[serde(rename = "settings.update")]
    SettingsUpdate(SettingsUpdate),
    #[serde(rename = "ping")]
    Ping(Ping),

    // ---- laptop -> phone ----
    #[serde(rename = "chat.agent")]
    ChatAgent(ChatAgent),
    #[serde(rename = "task.update")]
    TaskUpdate(TaskUpdate),
    #[serde(rename = "approval.request")]
    ApprovalRequest(ApprovalRequest),
    #[serde(rename = "screen.state")]
    ScreenState(ScreenState),
    #[serde(rename = "screen.frame")]
    ScreenFrame(ScreenFrame),
    #[serde(rename = "notify")]
    Notify(Notify),
    #[serde(rename = "pong")]
    Pong(Ping),

    // ---- both directions ----
    #[serde(rename = "file.chunk")]
    FileChunk(FileChunk),
    #[serde(rename = "file.done")]
    FileDone(FileDone),
    #[serde(rename = "error")]
    Error(ErrorMsg),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PairClaim {
    /// One-time token from the laptop's QR code (base64url).
    pub token: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PairResult {
    pub ok: bool,
    pub laptop_name: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Ping {
    #[ts(type = "number")]
    pub t_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ChatUser {
    pub text: String,
    /// True when the text came from speech-to-text on the phone.
    #[serde(default)]
    pub voice: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ChatAgent {
    #[ts(type = "string")]
    pub task_id: Uuid,
    /// Streamed delta text (when `final_` is false) or the full final message.
    pub text: String,
    #[serde(rename = "final")]
    pub final_: bool,
    /// Which brain produced this text.
    pub brain: Brain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Brain {
    /// Deterministic fast path, no model involved.
    Rules,
    /// Local Laya decision model.
    Laya,
    /// Local LLM (Ollama / llama.cpp).
    Local,
    Claude,
    Openai,
    Gemini,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum TaskState {
    Planned,
    Running,
    WaitingApproval,
    Done,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum RiskTier {
    Read,
    Write,
    Destructive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TaskStep {
    pub tool: String,
    /// Short human-readable description (args already redacted).
    pub summary: String,
    pub state: TaskState,
    pub brain: Brain,
    pub risk: RiskTier,
    pub output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TaskUpdate {
    #[ts(type = "string")]
    pub task_id: Uuid,
    pub title: String,
    pub state: TaskState,
    pub steps: Vec<TaskStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalRequest {
    #[ts(type = "string")]
    pub approval_id: Uuid,
    #[ts(type = "string")]
    pub task_id: Uuid,
    pub tool: String,
    pub summary: String,
    pub risk: RiskTier,
    /// Preview of the effect (diff, command line, file list...), redacted.
    pub preview: Option<String>,
    /// Unix ms after which the laptop treats the request as denied.
    #[ts(type = "number")]
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ApprovalDecision {
    Approve,
    /// Approve this tool for the rest of this task (only valid for `write` tier).
    ApproveForTask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalResponse {
    #[ts(type = "string")]
    pub approval_id: Uuid,
    pub decision: ApprovalDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ScreenAction {
    Start,
    Stop,
    /// Single snapshot, then stop (cheapest on battery).
    Snapshot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScreenRequest {
    pub action: ScreenAction,
    /// Max width in px of frames sent to the phone (default 1280).
    pub max_width: Option<u32>,
    /// Target fps for `start` (default 2, capped at 15).
    pub fps: Option<u8>,
    /// JPEG quality 1-100 (default 60).
    pub quality: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScreenState {
    pub active: bool,
    pub reason: String,
}

/// A JPEG frame. Frames larger than one Noise message are split into parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ScreenFrame {
    #[ts(type = "number")]
    pub frame_id: u64,
    pub part: u16,
    pub parts: u16,
    pub width: u32,
    pub height: u32,
    /// Base64 JPEG bytes for this part.
    pub data_b64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileOffer {
    #[ts(type = "string")]
    pub transfer_id: Uuid,
    pub name: String,
    #[ts(type = "number")]
    pub size: u64,
    /// Hex SHA-256 of the whole file.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileAccept {
    #[ts(type = "string")]
    pub transfer_id: Uuid,
    /// Resume from this byte offset (0 for a fresh transfer).
    #[ts(type = "number")]
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileRequest {
    /// Path relative to a shared root, e.g. `Documents/report.pdf`.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileChunk {
    #[ts(type = "string")]
    pub transfer_id: Uuid,
    #[ts(type = "number")]
    pub offset: u64,
    pub data_b64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileDone {
    #[ts(type = "string")]
    pub transfer_id: Uuid,
    pub ok: bool,
    pub sha256: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ControlKill {
    pub reason: Option<String>,
}

/// Policy knobs the phone may change. `None` fields are left as they are.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SettingsUpdate {
    /// Allow cloud brains at all.
    pub cloud_enabled: Option<bool>,
    /// Allow high-sensitivity content to reach cloud brains.
    pub cloud_allow_high_sensitivity: Option<bool>,
    /// Preferred cloud provider.
    pub preferred_cloud: Option<Brain>,
    /// Speak agent replies on the phone (phone-side only, echoed back).
    pub voice_replies: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum NotifyLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Notify {
    pub level: NotifyLevel,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ErrorMsg {
    pub code: String,
    pub message: String,
}

/// Structured decision produced by the local decision layer (Laya + rules), see spec §8.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Decision {
    pub intent: String,
    pub route: Route,
    pub cloud_reason: Option<CloudReason>,
    pub sensitivity: Sensitivity,
    pub risk: RiskTier,
    pub confidence: f32,
    pub brain: Brain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Route {
    Local,
    Cloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CloudReason {
    ComplexReasoning,
    LongGeneration,
    Vision,
    LowConfidence,
}

/// Contents of the pairing QR code (JSON, then base64url in the QR).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PairingQr {
    pub v: u8,
    /// Direct addresses to try first, e.g. `["192.168.1.20:7878"]`.
    pub addrs: Vec<String>,
    /// Optional relay base URL (`wss://host/relay`).
    pub relay: Option<String>,
    /// Laptop Noise static public key (X25519, base64url, no padding).
    pub laptop_pk: String,
    pub laptop_name: String,
    /// One-time pairing token (base64url).
    pub token: String,
    #[ts(type = "number")]
    pub expires_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message) {
        let env = Envelope::new(Uuid::new_v4(), 7, msg);
        let bytes = env.to_json();
        let back = Envelope::from_json(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_shape_matches_spec() {
        let env = Envelope::new(
            Uuid::nil(),
            42,
            Message::ChatUser(ChatUser {
                text: "hi".into(),
                voice: false,
            }),
        );
        let v: serde_json::Value = serde_json::from_slice(&env.to_json()).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["seq"], 42);
        assert_eq!(v["type"], "chat.user");
        assert_eq!(v["payload"]["text"], "hi");
        assert!(v["id"].is_string());
        assert!(v["session"].is_string());
    }

    #[test]
    fn all_messages_roundtrip() {
        let id = Uuid::new_v4();
        roundtrip(Message::PairClaim(PairClaim {
            token: "t".into(),
            device_name: "Pixel".into(),
        }));
        roundtrip(Message::PairResult(PairResult {
            ok: true,
            laptop_name: "lap".into(),
            reason: None,
        }));
        roundtrip(Message::ChatUser(ChatUser {
            text: "open firefox".into(),
            voice: true,
        }));
        roundtrip(Message::ApprovalResponse(ApprovalResponse {
            approval_id: id,
            decision: ApprovalDecision::ApproveForTask,
        }));
        roundtrip(Message::ScreenRequest(ScreenRequest {
            action: ScreenAction::Snapshot,
            max_width: Some(720),
            fps: None,
            quality: Some(50),
        }));
        roundtrip(Message::FileOffer(FileOffer {
            transfer_id: id,
            name: "a.txt".into(),
            size: 3,
            sha256: "ab".into(),
        }));
        roundtrip(Message::FileAccept(FileAccept {
            transfer_id: id,
            offset: 0,
        }));
        roundtrip(Message::FileRequest(FileRequest {
            path: "Documents/a".into(),
        }));
        roundtrip(Message::ControlKill(ControlKill { reason: None }));
        roundtrip(Message::SettingsUpdate(SettingsUpdate::default()));
        roundtrip(Message::Ping(Ping { t_ms: 1 }));
        roundtrip(Message::Pong(Ping { t_ms: 1 }));
        roundtrip(Message::ChatAgent(ChatAgent {
            task_id: id,
            text: "ok".into(),
            final_: true,
            brain: Brain::Laya,
        }));
        roundtrip(Message::TaskUpdate(TaskUpdate {
            task_id: id,
            title: "t".into(),
            state: TaskState::WaitingApproval,
            steps: vec![TaskStep {
                tool: "fs.list".into(),
                summary: "list".into(),
                state: TaskState::Done,
                brain: Brain::Rules,
                risk: RiskTier::Read,
                output: None,
            }],
        }));
        roundtrip(Message::ApprovalRequest(ApprovalRequest {
            approval_id: id,
            task_id: id,
            tool: "shell".into(),
            summary: "rm".into(),
            risk: RiskTier::Destructive,
            preview: Some("rm x".into()),
            expires_at_ms: 9,
        }));
        roundtrip(Message::ScreenState(ScreenState {
            active: true,
            reason: "on_demand".into(),
        }));
        roundtrip(Message::ScreenFrame(ScreenFrame {
            frame_id: 1,
            part: 0,
            parts: 1,
            width: 2,
            height: 2,
            data_b64: "AA".into(),
        }));
        roundtrip(Message::Notify(Notify {
            level: NotifyLevel::Warn,
            text: "x".into(),
        }));
        roundtrip(Message::FileChunk(FileChunk {
            transfer_id: id,
            offset: 0,
            data_b64: "AA".into(),
        }));
        roundtrip(Message::FileDone(FileDone {
            transfer_id: id,
            ok: true,
            sha256: "ab".into(),
            reason: None,
        }));
        roundtrip(Message::Error(ErrorMsg {
            code: "e".into(),
            message: "m".into(),
        }));
    }

    #[test]
    fn rejects_bad_version_and_garbage() {
        assert!(Envelope::from_json(b"not json").is_err());
        let bad = br#"{"v":9,"id":"00000000-0000-0000-0000-000000000000","session":"00000000-0000-0000-0000-000000000000","seq":1,"type":"ping","payload":{"t_ms":1}}"#;
        assert!(matches!(
            Envelope::from_json(bad),
            Err(ProtocolError::UnsupportedVersion(9))
        ));
        let unknown = br#"{"v":1,"id":"00000000-0000-0000-0000-000000000000","session":"00000000-0000-0000-0000-000000000000","seq":1,"type":"evil.cmd","payload":{}}"#;
        assert!(Envelope::from_json(unknown).is_err());
    }

    #[test]
    fn seq_guard_blocks_replay() {
        let mut g = SeqGuard::default();
        g.check(1).unwrap();
        g.check(5).unwrap();
        assert!(g.check(5).is_err());
        assert!(g.check(3).is_err());
        g.check(6).unwrap();
    }
}
