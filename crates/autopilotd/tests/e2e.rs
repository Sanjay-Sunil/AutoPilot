//! End to end: transport server + session dispatch with a fake handler + control socket.
use agent_protocol::{Brain, ChatAgent, ChatUser, Message, PairingQr, Ping};
use agent_transport::{DeviceKeys, PairingManager, TrustStore, connect_with_code, serve_listener};
use autopilotd::control::{self, ControlClient};
use autopilotd::{DaemonState, Handler, dispatch_sessions};
use base64::Engine;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

fn echo_handler() -> Handler {
    Arc::new(|actor, msg, out| {
        Box::pin(async move {
            if let Message::ChatUser(c) = msg {
                let text = format!("{actor} said {}", c.text);
                let _ = out
                    .send(Message::ChatAgent(ChatAgent {
                        task_id: uuid::Uuid::nil(),
                        text,
                        final_: true,
                        brain: Brain::Rules,
                    }))
                    .await;
            }
        })
    })
}

#[tokio::test]
async fn pair_via_control_socket_then_ping_pong() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let keys = Arc::new(DeviceKeys::load_or_create(&data.join("device.key")).unwrap());
    let trust = Arc::new(Mutex::new(
        TrustStore::load(&data.join("trusted.json")).unwrap(),
    ));
    let pairing = Arc::new(PairingManager::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let killed = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let k = killed.clone();
    let state = Arc::new(DaemonState {
        keys: keys.clone(),
        trust: trust.clone(),
        pairing: pairing.clone(),
        laptop_name: "test-lap".into(),
        listen: addr.to_string(),
        relay: None,
        kill: Arc::new(move |_| k.store(true, Ordering::SeqCst)),
        active_sessions: active.clone(),
        started: std::time::Instant::now(),
    });
    let _guard = control::start(&data, state).await.unwrap();
    let (stx, srx) = mpsc::channel(8);
    tokio::spawn(dispatch_sessions(srx, echo_handler(), active));
    tokio::spawn(serve_listener(
        listener,
        None,
        "test-lap".into(),
        keys.clone(),
        trust.clone(),
        pairing,
        stx,
    ));

    // `autopilotd pair` equivalent
    let (mut ctl, v) = ControlClient::request(&data, &json!({"cmd": "pair"}))
        .await
        .unwrap();
    let uri = v["uri"].as_str().unwrap();
    let d = uri.strip_prefix("autopilot://pair?d=").unwrap();
    let qr: PairingQr = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(qr.laptop_pk, keys.public_b64());
    assert_eq!(qr.addrs, vec![addr.to_string()]);

    let phone = DeviceKeys::generate();
    let url = format!("ws://{}/ws", qr.addrs[0]);
    let (mut s, code) = connect_with_code(&url, &phone, &qr.laptop_pk, "Pixel", Some(qr.token))
        .await
        .unwrap();
    let ev = timeout(T, ctl.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(ev["event"], "paired");
    assert_eq!(ev["code"], code.as_str());

    s.sender
        .send(Message::Ping(Ping { t_ms: 42 }))
        .await
        .unwrap();
    let env = timeout(T, s.inbound.recv()).await.unwrap().unwrap();
    assert_eq!(env.msg, Message::Pong(Ping { t_ms: 42 }));
    assert_eq!(env.session, s.session_id);

    s.sender
        .send(Message::ChatUser(ChatUser {
            text: "hello".into(),
            voice: false,
        }))
        .await
        .unwrap();
    let env = timeout(T, s.inbound.recv()).await.unwrap().unwrap();
    match env.msg {
        Message::ChatAgent(c) => assert_eq!(c.text, "phone:Pixel said hello"),
        other => panic!("unexpected {other:?}"),
    }

    let (_, st) = ControlClient::request(&data, &json!({"cmd": "status"}))
        .await
        .unwrap();
    assert_eq!(st["sessions"], 1);
    assert_eq!(st["devices"], 1);
    let (_, devs) = ControlClient::request(&data, &json!({"cmd": "devices"}))
        .await
        .unwrap();
    assert_eq!(devs["devices"][0]["pk_b64"], phone.public_b64().as_str());

    ControlClient::request(&data, &json!({"cmd": "kill"}))
        .await
        .unwrap();
    assert!(killed.load(Ordering::SeqCst));

    let (_, r) = ControlClient::request(&data, &json!({"cmd": "revoke", "pk": phone.public_b64()}))
        .await
        .unwrap();
    assert_eq!(r["revoked"], true);
    assert!(
        timeout(T, s.inbound.recv()).await.unwrap().is_none(),
        "revoked session closed"
    );

    assert!(
        ControlClient::request(&data, &json!({"cmd": "nope"}))
            .await
            .is_err()
    );
}
