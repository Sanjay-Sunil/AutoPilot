//! `autopilotd chat`: interactive phone simulator over the real transport.
use agent_protocol::{
    ApprovalDecision, ApprovalResponse, ChatUser, ControlKill, Message, PairingQr, ScreenAction,
    ScreenRequest,
};
use agent_transport::{DeviceKeys, connect_with_code};
use base64::Engine;
use std::collections::HashMap;
use std::io::Write;
use tokio::io::AsyncBufReadExt;
use uuid::Uuid;

fn decode_uri(uri: &str) -> anyhow::Result<PairingQr> {
    let d = uri
        .trim()
        .strip_prefix("autopilot://pair?d=")
        .ok_or_else(|| anyhow::anyhow!("not an autopilot://pair?d= link"))?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(d)?;
    Ok(serde_json::from_slice(&json)?)
}

fn b64_any(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}

pub async fn run(
    url: Option<String>,
    laptop_pk: Option<String>,
    pair_token: Option<String>,
    uri: Option<String>,
    name: String,
) -> anyhow::Result<()> {
    let (mut url, mut laptop_pk, mut token) = (url, laptop_pk, pair_token);
    if let Some(uri) = uri {
        let qr = decode_uri(&uri)?;
        url = url.or_else(|| qr.addrs.first().map(|a| format!("ws://{a}/ws")));
        laptop_pk = laptop_pk.or(Some(qr.laptop_pk));
        token = token.or(Some(qr.token));
    }
    let url = url.unwrap_or_else(|| "ws://127.0.0.1:7878/ws".into());
    let laptop_pk = laptop_pk.ok_or_else(|| anyhow::anyhow!("--laptop-pk or --uri is required"))?;

    let key_path = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("autopilot")
        .join("sim-phone.key");
    let keys = DeviceKeys::load_or_create(&key_path)?;
    let pairing = token.is_some();
    let (mut session, code) = connect_with_code(&url, &keys, &laptop_pk, &name, token).await?;
    if pairing {
        println!(
            "paired with {} - confirmation code {code} (must match the laptop)",
            session.peer_name
        );
    } else {
        println!("connected to {url}");
    }
    println!("type a message; `y`/`n` answers the latest approval; /kill, /snap, /quit");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut latest_approval: Option<Uuid> = None;
    let mut streaming: HashMap<Uuid, bool> = HashMap::new();
    let mut frames: HashMap<u64, Vec<Option<Vec<u8>>>> = HashMap::new();
    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line? else { break };
                let line = line.trim();
                let msg = match line {
                    "" => continue,
                    "/quit" | "/exit" => break,
                    "/kill" => Message::ControlKill(ControlKill { reason: Some("sim /kill".into()) }),
                    "/snap" => Message::ScreenRequest(ScreenRequest { action: ScreenAction::Snapshot, max_width: None, fps: None, quality: None }),
                    "y" | "n" if latest_approval.is_some() => {
                        let decision = if line == "y" { ApprovalDecision::Approve } else { ApprovalDecision::Deny };
                        Message::ApprovalResponse(ApprovalResponse { approval_id: latest_approval.take().unwrap_or_default(), decision })
                    }
                    text => Message::ChatUser(ChatUser { text: text.to_string(), voice: false }),
                };
                session.sender.send(msg).await?;
            }
            env = session.inbound.recv() => {
                let Some(env) = env else { println!("session closed"); break };
                match env.msg {
                    Message::ChatAgent(c) => {
                        if c.final_ {
                            if streaming.remove(&c.task_id).is_some() { println!(); } else { println!("agent [{:?}]: {}", c.brain, c.text); }
                        } else {
                            if streaming.insert(c.task_id, true).is_none() { print!("agent [{:?}]: ", c.brain); }
                            print!("{}", c.text);
                            let _ = std::io::stdout().flush();
                        }
                    }
                    Message::TaskUpdate(t) => {
                        println!("[task {:?}] {}", t.state, t.title);
                        for s in t.steps { println!("    - {:?} {} ({}) {:?}", s.state, s.tool, s.summary, s.risk); }
                    }
                    Message::ApprovalRequest(a) => {
                        println!("[approval {:?}] {}: {}", a.risk, a.tool, a.summary);
                        if let Some(p) = a.preview { println!("    {p}"); }
                        println!("    answer y/n");
                        latest_approval = Some(a.approval_id);
                    }
                    Message::ScreenFrame(f) => {
                        let parts = f.parts.max(1) as usize;
                        let slot = frames.entry(f.frame_id).or_insert_with(|| vec![None; parts]);
                        if let (Some(cell), Some(bytes)) = (slot.get_mut(f.part as usize), b64_any(&f.data_b64)) { *cell = Some(bytes); }
                        if slot.iter().all(Option::is_some) {
                            let jpg: Vec<u8> = frames.remove(&f.frame_id).unwrap_or_default().into_iter().flatten().flatten().collect();
                            std::fs::write("snap.jpg", &jpg)?;
                            println!("[screen] saved {}x{} frame to ./snap.jpg ({} bytes)", f.width, f.height, jpg.len());
                        }
                    }
                    Message::ScreenState(s) => println!("[screen] active={} ({})", s.active, s.reason),
                    Message::Notify(n) => println!("[{:?}] {}", n.level, n.text),
                    Message::Error(e) => println!("[error {}] {}", e.code, e.message),
                    Message::Pong(_) => {}
                    other => println!("[recv] {other:?}"),
                }
            }
        }
    }
    Ok(())
}
