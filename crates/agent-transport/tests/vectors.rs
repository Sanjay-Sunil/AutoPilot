//! Deterministic Noise XX test vectors for the TypeScript implementation (apps/mobile).
//! Regenerate with `REGENERATE_VECTORS=1 cargo test -p agent-transport --test vectors`.
use agent_protocol::{Envelope, PairingQr};
use agent_transport::{
    DeviceKeys, NOISE_PARAMS, PROLOGUE, confirmation_code, pairing_qr, relay_room,
};
use serde_json::{Value, json};
use std::path::PathBuf;

const PHONE_STATIC: &str = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
const PHONE_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
const LAPTOP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
const LAPTOP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

const PHONE_TO_LAPTOP: &str = r#"{"v":1,"id":"6f1c7a52-6e1e-4c41-9f1e-2b7d1c0a0001","session":"00000000-0000-0000-0000-000000000000","seq":1,"type":"pair.claim","payload":{"token":"AAECAwQFBgcICQoLDA0ODw","device_name":"Pixel 9"}}"#;
const LAPTOP_TO_PHONE: &str = r#"{"v":1,"id":"6f1c7a52-6e1e-4c41-9f1e-2b7d1c0a0002","session":"3d2f9c1e-8a7b-4c6d-9e5f-0a1b2c3d4e5f","seq":1,"type":"pair.result","payload":{"ok":true,"laptop_name":"zxnj-laptop","reason":null}}"#;

fn key(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn generate() -> Value {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
    let (ps, pe, ls, le) = (
        key(PHONE_STATIC),
        key(PHONE_EPHEMERAL),
        key(LAPTOP_STATIC),
        key(LAPTOP_EPHEMERAL),
    );
    let mut ini = snow::Builder::new(params.clone())
        .prologue(PROLOGUE)
        .unwrap()
        .local_private_key(&ps)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&pe)
        .build_initiator()
        .unwrap();
    let mut res = snow::Builder::new(params)
        .prologue(PROLOGUE)
        .unwrap()
        .local_private_key(&ls)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&le)
        .build_responder()
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let mut out = vec![0u8; 65535];
    let n = ini.write_message(&[], &mut buf).unwrap();
    let m1 = buf[..n].to_vec();
    assert_eq!(res.read_message(&m1, &mut out).unwrap(), 0);
    let n = res.write_message(&[], &mut buf).unwrap();
    let m2 = buf[..n].to_vec();
    assert_eq!(ini.read_message(&m2, &mut out).unwrap(), 0);
    let n = ini.write_message(&[], &mut buf).unwrap();
    let m3 = buf[..n].to_vec();
    assert_eq!(res.read_message(&m3, &mut out).unwrap(), 0);

    let hash = ini.get_handshake_hash().to_vec();
    assert_eq!(hash, res.get_handshake_hash());
    let (phone, laptop) = (DeviceKeys::from_private(ps), DeviceKeys::from_private(ls));
    assert_eq!(ini.get_remote_static().unwrap(), laptop.public.as_slice());
    assert_eq!(res.get_remote_static().unwrap(), phone.public.as_slice());

    let mut ini = ini.into_transport_mode().unwrap();
    let mut res = res.into_transport_mode().unwrap();
    // Both plaintexts must be valid envelopes.
    Envelope::from_json(PHONE_TO_LAPTOP.as_bytes()).unwrap();
    Envelope::from_json(LAPTOP_TO_PHONE.as_bytes()).unwrap();
    let n = ini
        .write_message(PHONE_TO_LAPTOP.as_bytes(), &mut buf)
        .unwrap();
    let c1 = buf[..n].to_vec();
    let k = res.read_message(&c1, &mut out).unwrap();
    assert_eq!(&out[..k], PHONE_TO_LAPTOP.as_bytes());
    let n = res
        .write_message(LAPTOP_TO_PHONE.as_bytes(), &mut buf)
        .unwrap();
    let c2 = buf[..n].to_vec();
    let k = ini.read_message(&c2, &mut out).unwrap();
    assert_eq!(&out[..k], LAPTOP_TO_PHONE.as_bytes());

    let qr = PairingQr {
        v: 1,
        addrs: vec!["192.168.1.20:7878".into()],
        relay: Some("wss://relay.example/relay".into()),
        laptop_pk: laptop.public_b64(),
        laptop_name: "zxnj-laptop".into(),
        token: "AAECAwQFBgcICQoLDA0ODw".into(),
        expires_at_ms: 1_760_000_000_000,
    };
    let (uri, _) = pairing_qr(&qr);

    json!({
        "description": "AutoPilot Noise XX vector. Phone = initiator, laptop = responder. All handshake payloads empty. Transport messages use nonce 0 in each direction. Keys are X25519 private scalars (unclamped bytes as stored; clamping happens inside X25519).",
        "protocol_name": NOISE_PARAMS,
        "prologue_ascii": std::str::from_utf8(PROLOGUE).unwrap(),
        "prologue_hex": hex::encode(PROLOGUE),
        "initiator": {
            "role": "phone",
            "static_private_hex": PHONE_STATIC,
            "static_public_hex": hex::encode(phone.public),
            "static_public_b64url": phone.public_b64(),
            "ephemeral_private_hex": PHONE_EPHEMERAL,
        },
        "responder": {
            "role": "laptop",
            "static_private_hex": LAPTOP_STATIC,
            "static_public_hex": hex::encode(laptop.public),
            "static_public_b64url": laptop.public_b64(),
            "ephemeral_private_hex": LAPTOP_EPHEMERAL,
        },
        "handshake": [
            { "from": "initiator", "payload_hex": "", "message_hex": hex::encode(&m1) },
            { "from": "responder", "payload_hex": "", "message_hex": hex::encode(&m2) },
            { "from": "initiator", "payload_hex": "", "message_hex": hex::encode(&m3) },
        ],
        "handshake_hash_hex": hex::encode(&hash),
        "confirmation_code": confirmation_code(&hash),
        "confirmation_code_formula": "u32_be(BLAKE2s-256(handshake_hash)[0..4]) % 1000000, zero-padded to 6 digits",
        "relay_room": relay_room(&laptop.public),
        "relay_room_formula": "hex(BLAKE2s-256(laptop_static_pk))[0..32]",
        "transport": [
            { "from": "initiator", "nonce": 0, "plaintext_utf8": PHONE_TO_LAPTOP, "ciphertext_hex": hex::encode(&c1) },
            { "from": "responder", "nonce": 0, "plaintext_utf8": LAPTOP_TO_PHONE, "ciphertext_hex": hex::encode(&c2) },
        ],
        "pairing_qr": { "json": serde_json::to_value(&qr).unwrap(), "uri": uri },
    })
}

#[test]
fn xx_vector_matches_file() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/xx_vector.json");
    let fresh = generate();
    // Deterministic: generating twice yields the same bytes.
    assert_eq!(fresh, generate());
    if std::env::var_os("REGENERATE_VECTORS").is_some() || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut s = serde_json::to_string_pretty(&fresh).unwrap();
        s.push('\n');
        std::fs::write(&path, s).unwrap();
    }
    let on_disk: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        on_disk, fresh,
        "xx_vector.json is stale; rerun with REGENERATE_VECTORS=1"
    );
}
