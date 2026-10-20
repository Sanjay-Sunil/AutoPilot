use super::*;
use agent_protocol::ChatUser;

struct Server {
    url: String,
    laptop_pk: String,
    trust: Arc<tokio::sync::Mutex<TrustStore>>,
    pairing: Arc<PairingManager>,
    sessions: mpsc::Receiver<Session>,
    _dir: tempfile::TempDir,
}

async fn start_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(DeviceKeys::load_or_create(&dir.path().join("device.key")).unwrap());
    let trust = Arc::new(tokio::sync::Mutex::new(
        TrustStore::load(&dir.path().join("trusted.json")).unwrap(),
    ));
    let pairing = Arc::new(PairingManager::new());
    let (tx, sessions) = mpsc::channel(8);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let laptop_pk = keys.public_b64();
    tokio::spawn(serve_listener(
        listener,
        None,
        "test-laptop".into(),
        keys,
        trust.clone(),
        pairing.clone(),
        tx,
    ));
    Server {
        url,
        laptop_pk,
        trust,
        pairing,
        sessions,
        _dir: dir,
    }
}

const T: Duration = Duration::from_secs(5);

async fn expect_closed(rx: &mut mpsc::Receiver<Envelope>) {
    loop {
        match timeout(T, rx.recv()).await.expect("session should close") {
            None => return,
            Some(_) => continue,
        }
    }
}

/// Raw initiator exposing the channel so tests can forge seq numbers and ciphertexts.
async fn raw_client(url: &str, keys: &DeviceKeys, laptop_pk: &str) -> (SecureChannel, Link) {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let mut link = spawn_pump(ws);
    let hs = noise_builder()
        .unwrap()
        .local_private_key(&keys.private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let (noise, _) = initiator_handshake(hs, &mut link, &decode_pk(laptop_pk).unwrap())
        .await
        .unwrap();
    (SecureChannel::new(noise, Uuid::nil()), link)
}

async fn link_closed(link: &mut Link) -> bool {
    loop {
        match timeout(T, link.rx.recv()).await {
            Ok(None) => return true,
            Ok(Some(_)) => continue,
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn pair_then_roundtrip_and_reconnect() {
    let mut s = start_server().await;
    let mut events = s.pairing.subscribe();
    let phone = DeviceKeys::generate();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let (mut client, code) = connect_with_code(&s.url, &phone, &s.laptop_pk, "Pixel", Some(token))
        .await
        .unwrap();
    assert_eq!(client.peer_name, "test-laptop");
    assert!(!client.session_id.is_nil());

    let ev = timeout(T, events.recv()).await.unwrap().unwrap();
    assert_eq!(ev.code, code, "confirmation codes match on both sides");
    assert_eq!(ev.code.len(), 6);
    assert_eq!(ev.pk_b64, phone.public_b64());
    assert!(s.trust.lock().await.is_trusted(&phone.public_b64()));

    let mut server = timeout(T, s.sessions.recv()).await.unwrap().unwrap();
    assert_eq!(server.session_id, client.session_id);
    assert_eq!(server.peer_name, "Pixel");

    // phone -> laptop
    client
        .sender
        .send(Message::ChatUser(ChatUser {
            text: "open firefox".into(),
            voice: false,
        }))
        .await
        .unwrap();
    let env = timeout(T, server.inbound.recv()).await.unwrap().unwrap();
    assert_eq!(env.session, server.session_id);
    assert!(matches!(env.msg, Message::ChatUser(ref c) if c.text == "open firefox"));
    // laptop -> phone
    server
        .sender
        .send(Message::Notify(agent_protocol::Notify {
            level: agent_protocol::NotifyLevel::Info,
            text: "hi".into(),
        }))
        .await
        .unwrap();
    let env = timeout(T, client.inbound.recv()).await.unwrap().unwrap();
    assert_eq!(env.session, server.session_id);
    assert!(matches!(env.msg, Message::Notify(_)));
    // ping is answered by the transport
    client
        .sender
        .send(Message::Ping(Ping { t_ms: 7 }))
        .await
        .unwrap();
    let env = timeout(T, client.inbound.recv()).await.unwrap().unwrap();
    assert_eq!(env.msg, Message::Pong(Ping { t_ms: 7 }));

    // oversized payload is refused before hitting the wire
    let big = Message::ChatUser(ChatUser {
        text: "x".repeat(MAX_PLAINTEXT),
        voice: false,
    });
    assert!(client.sender.send(big).await.is_err());

    // reconnect as a trusted device without a token
    drop(client);
    let mut c2 = connect(&s.url, &phone, &s.laptop_pk, "Pixel", None)
        .await
        .unwrap();
    let _srv2 = timeout(T, s.sessions.recv()).await.unwrap().unwrap();
    c2.sender
        .send(Message::Ping(Ping { t_ms: 1 }))
        .await
        .unwrap();
    let env = timeout(T, c2.inbound.recv()).await.unwrap().unwrap();
    assert!(matches!(env.msg, Message::Pong(_)));
}

#[tokio::test]
async fn unknown_device_without_token_rejected() {
    let s = start_server().await;
    let phone = DeviceKeys::generate();
    let mut c = connect(&s.url, &phone, &s.laptop_pk, "Evil", None)
        .await
        .unwrap();
    c.sender
        .send(Message::Ping(Ping { t_ms: 1 }))
        .await
        .unwrap();
    expect_closed(&mut c.inbound).await;
    assert!(!s.trust.lock().await.is_trusted(&phone.public_b64()));
}

#[tokio::test]
async fn wrong_pinned_key_rejected() {
    let s = start_server().await;
    let phone = DeviceKeys::generate();
    let other = DeviceKeys::generate().public_b64();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let err = connect(&s.url, &phone, &other, "Pixel", Some(token))
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("pinned"), "{err}");
}

#[tokio::test]
async fn token_reuse_rejected() {
    let s = start_server().await;
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    connect(
        &s.url,
        &DeviceKeys::generate(),
        &s.laptop_pk,
        "A",
        Some(token.clone()),
    )
    .await
    .unwrap();
    let b = DeviceKeys::generate();
    assert!(
        connect(&s.url, &b, &s.laptop_pk, "B", Some(token))
            .await
            .is_err()
    );
    assert!(!s.trust.lock().await.is_trusted(&b.public_b64()));
}

#[tokio::test]
async fn expired_token_rejected() {
    let s = start_server().await;
    let (token, _) = s.pairing.issue(0);
    assert!(
        connect(
            &s.url,
            &DeviceKeys::generate(),
            &s.laptop_pk,
            "A",
            Some(token)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn replayed_seq_rejected() {
    let s = start_server().await;
    let phone = DeviceKeys::generate();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let (mut ch, mut link) = raw_client(&s.url, &phone, &s.laptop_pk).await;
    link.send(
        ch.seal(Message::PairClaim(PairClaim {
            token,
            device_name: "x".into(),
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let env = ch.open(&link.recv_bin().await.unwrap()).unwrap();
    assert!(matches!(
        env.msg,
        Message::PairResult(PairResult { ok: true, .. })
    ));
    ch.session = env.session;
    // seq 2 ok
    link.send(ch.seal(Message::Ping(Ping { t_ms: 1 })).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        ch.open(&link.recv_bin().await.unwrap()).unwrap().msg,
        Message::Pong(_)
    ));
    // seq 2 again (fresh Noise nonce, replayed envelope seq) -> closed
    let replay = Envelope::new(ch.session, 2, Message::Ping(Ping { t_ms: 2 }));
    link.send(ch.seal_envelope(&replay).unwrap()).await.unwrap();
    assert!(link_closed(&mut link).await);
}

#[tokio::test]
async fn reordered_seq_rejected() {
    let s = start_server().await;
    let phone = DeviceKeys::generate();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let (mut ch, mut link) = raw_client(&s.url, &phone, &s.laptop_pk).await;
    let claim = Envelope::new(
        Uuid::nil(),
        10,
        Message::PairClaim(PairClaim {
            token,
            device_name: "x".into(),
        }),
    );
    link.send(ch.seal_envelope(&claim).unwrap()).await.unwrap();
    let _ = link.recv_bin().await.unwrap();
    let old = Envelope::new(Uuid::nil(), 5, Message::Ping(Ping { t_ms: 2 }));
    link.send(ch.seal_envelope(&old).unwrap()).await.unwrap();
    assert!(link_closed(&mut link).await);
}

#[tokio::test]
async fn tampered_ciphertext_closes_session() {
    let mut s = start_server().await;
    let phone = DeviceKeys::generate();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let (mut ch, mut link) = raw_client(&s.url, &phone, &s.laptop_pk).await;
    link.send(
        ch.seal(Message::PairClaim(PairClaim {
            token,
            device_name: "x".into(),
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let _ = link.recv_bin().await.unwrap();
    let mut srv = timeout(T, s.sessions.recv()).await.unwrap().unwrap();
    let mut ct = ch
        .seal(Message::ChatUser(ChatUser {
            text: "rm -rf".into(),
            voice: false,
        }))
        .unwrap();
    ct[5] ^= 0x01;
    link.send(ct).await.unwrap();
    assert!(link_closed(&mut link).await);
    assert!(
        timeout(T, srv.inbound.recv()).await.unwrap().is_none(),
        "nothing delivered"
    );
}

#[tokio::test]
async fn revoked_device_kicked() {
    let mut s = start_server().await;
    let phone = DeviceKeys::generate();
    let (token, _) = s.pairing.issue(PAIRING_TTL_MS);
    let mut c = connect(&s.url, &phone, &s.laptop_pk, "Pixel", Some(token))
        .await
        .unwrap();
    let mut srv = timeout(T, s.sessions.recv()).await.unwrap().unwrap();
    assert!(s.trust.lock().await.revoke(&phone.public_b64()).unwrap());
    expect_closed(&mut c.inbound).await;
    assert!(timeout(T, srv.inbound.recv()).await.unwrap().is_none());
    // and it cannot come back without a new token
    let mut c2 = connect(&s.url, &phone, &s.laptop_pk, "Pixel", None)
        .await
        .unwrap();
    c2.sender
        .send(Message::Ping(Ping { t_ms: 1 }))
        .await
        .unwrap();
    expect_closed(&mut c2.inbound).await;
}

#[tokio::test]
async fn non_ws_path_refused() {
    let s = start_server().await;
    let bad = s.url.replace("/ws", "/other");
    assert!(tokio_tungstenite::connect_async(bad).await.is_err());
}

#[test]
fn pairing_tokens_limits() {
    let p = PairingManager::new();
    let toks: Vec<_> = (0..7).map(|_| p.issue(PAIRING_TTL_MS).0).collect();
    assert_eq!(p.outstanding(), MAX_PENDING_TOKENS);
    assert!(!p.consume(&toks[0]), "oldest tokens evicted");
    assert!(p.consume(&toks[6]));
    assert!(!p.consume(&toks[6]), "single use");
    assert!(!p.consume("garbage!"));
    assert!(!p.consume(""));
}

#[test]
fn keys_persist_with_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub/device.key");
    let a = DeviceKeys::load_or_create(&path).unwrap();
    let b = DeviceKeys::load_or_create(&path).unwrap();
    assert_eq!(a.public, b.public);
    assert_eq!(decode_pk(&a.public_b64()).unwrap(), a.public);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // public derivation agrees with snow
    let kp = noise_builder().unwrap().generate_keypair().unwrap();
    let k = DeviceKeys::from_private(kp.private.as_slice().try_into().unwrap());
    assert_eq!(k.public.as_slice(), kp.public.as_slice());
}

#[test]
fn trust_store_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trusted.json");
    let pk = DeviceKeys::generate().public_b64();
    {
        let mut t = TrustStore::load(&path).unwrap();
        t.add(PairedDevice {
            name: "p".into(),
            pk_b64: pk.clone(),
            paired_at_ms: 1,
        })
        .unwrap();
        assert!(
            t.add(PairedDevice {
                name: "bad".into(),
                pk_b64: "zz".into(),
                paired_at_ms: 1
            })
            .is_err()
        );
    }
    let mut t = TrustStore::load(&path).unwrap();
    assert!(t.is_trusted(&pk));
    assert_eq!(t.list().len(), 1);
    assert!(t.revoke(&pk).unwrap());
    assert!(!t.revoke(&pk).unwrap());
    assert!(!TrustStore::load(&path).unwrap().is_trusted(&pk));
}

#[test]
fn qr_uri_roundtrip() {
    let qr = PairingQr {
        v: 1,
        addrs: vec!["192.168.1.2:7878".into()],
        relay: None,
        laptop_pk: DeviceKeys::generate().public_b64(),
        laptop_name: "lap".into(),
        token: "tok".into(),
        expires_at_ms: 5,
    };
    let (uri, term) = pairing_qr(&qr);
    let d = uri.strip_prefix("autopilot://pair?d=").unwrap();
    let back: PairingQr = serde_json::from_slice(&B64.decode(d).unwrap()).unwrap();
    assert_eq!(back, qr);
    assert!(term.contains('█') || term.contains('▀') || term.contains('▄'));
}

#[test]
fn confirmation_code_format() {
    let c = confirmation_code(&[0u8; 32]);
    assert_eq!(c.len(), 6);
    assert!(c.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(relay_room(&[0u8; 32]).len(), 32);
}

/// Minimal stand-in for services/backend relay: first connection = laptop, second = phone.
async fn fake_relay(listener: TcpListener) {
    let (l, _) = listener.accept().await.unwrap();
    let laptop = tokio_tungstenite::accept_async(l).await.unwrap();
    let (p, _) = listener.accept().await.unwrap();
    let phone = tokio_tungstenite::accept_async(p).await.unwrap();
    let (mut lsink, mut lstream) = laptop.split();
    let (mut psink, mut pstream) = phone.split();
    lsink
        .send(WsMessage::Text("peer-connected".into()))
        .await
        .unwrap();
    let a = async move {
        while let Some(Ok(m)) = pstream.next().await {
            if let WsMessage::Binary(b) = m {
                if lsink.send(WsMessage::Binary(b)).await.is_err() {
                    break;
                }
            }
        }
    };
    let b = async move {
        while let Some(Ok(m)) = lstream.next().await {
            if let WsMessage::Binary(b) = m {
                if psink.send(WsMessage::Binary(b)).await.is_err() {
                    break;
                }
            }
        }
    };
    tokio::join!(a, b);
}

#[tokio::test]
async fn pairing_over_relay() {
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(DeviceKeys::generate());
    let trust = Arc::new(tokio::sync::Mutex::new(
        TrustStore::load(&dir.path().join("t.json")).unwrap(),
    ));
    let pairing = Arc::new(PairingManager::new());
    let (tx, mut sessions) = mpsc::channel(8);
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/relay", relay.local_addr().unwrap());
    tokio::spawn(fake_relay(relay));
    let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let laptop_pk = keys.public_b64();
    tokio::spawn(serve_listener(
        direct,
        Some(relay_url.clone()),
        "lap".into(),
        keys,
        trust,
        pairing.clone(),
        tx,
    ));
    tokio::time::sleep(Duration::from_millis(200)).await; // let the laptop register first
    let (token, _) = pairing.issue(PAIRING_TTL_MS);
    let phone = DeviceKeys::generate();
    let mut c = connect(
        &format!("{relay_url}/room?role=phone"),
        &phone,
        &laptop_pk,
        "P",
        Some(token),
    )
    .await
    .unwrap();
    let mut srv = timeout(T, sessions.recv()).await.unwrap().unwrap();
    c.sender
        .send(Message::ChatUser(ChatUser {
            text: "hi".into(),
            voice: false,
        }))
        .await
        .unwrap();
    assert!(matches!(
        timeout(T, srv.inbound.recv()).await.unwrap().unwrap().msg,
        Message::ChatUser(_)
    ));
    c.sender
        .send(Message::Ping(Ping { t_ms: 3 }))
        .await
        .unwrap();
    assert_eq!(
        timeout(T, c.inbound.recv()).await.unwrap().unwrap().msg,
        Message::Pong(Ping { t_ms: 3 })
    );
}
