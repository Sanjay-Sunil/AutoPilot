# Wire protocol (v1)

Source of truth for message types: `crates/agent-protocol` (TS bindings in `apps/mobile/src/protocol/`).

## Transport

WebSocket, **binary frames only**. Two ways to reach the laptop:

1. **Direct** (LAN / Tailscale): `ws://<addr>/ws`, laptop daemon listens on `0.0.0.0:7878` by default.
2. **Relay** (different networks): both sides connect to `wss://<backend>/relay/<room>`, where
   `room = hex(BLAKE2s-256(laptop_static_pk))[0..32]`. Laptop connects with `?role=laptop`, phone with
   `?role=phone`. The relay pipes binary frames 1:1 between the laptop and one phone and never sees
   plaintext (it only ever sees Noise messages).

## Noise handshake

- Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` (snow on Rust; `@noble/*` on TS).
- Prologue: ASCII `autopilot/1`.
- Phone = initiator, laptop = responder. Frames 1-3 are the raw handshake messages, empty payloads.
- After message 2 the phone MUST check that the laptop's static key equals the `laptop_pk` it pinned
  (from the pairing QR); otherwise abort.
- After message 3 the laptop knows the phone static key:
  - trusted (in trust store) -> session established;
  - unknown -> the first transport message MUST be `pair.claim` with a valid one-time token, else close.
- Confirmation code (shown on both screens during pairing):
  `code = (u32_be(BLAKE2s-256(handshake_hash)[0..4]) % 1_000_000)` zero-padded to 6 digits.

## Transport messages

- Every WS frame after the handshake = one Noise transport message = encrypt(UTF-8 JSON `Envelope`).
- Plaintext max 65_519 bytes (65_535 - 16 tag). Larger payloads (screen frames) are split by the
  sender into `screen.frame` parts.
- `seq` starts at 1 and strictly increases per sender; receivers drop and close on replay.
- `session` = uuid chosen by the laptop and sent in `pair.result` / first laptop message; phones echo it.
  (Phones may send nil uuid before they learn it.)
- Keepalive: phone sends `ping` every 25 s; laptop answers `pong`. Either side closes after 60 s silence.

## Pairing QR

`PairingQr` JSON, base64url (no padding) encoded, prefixed by `autopilot://pair?d=`.
Token is single use, expires in 5 minutes.

## Approvals

`approval.request` -> phone shows tool, risk, preview -> `approval.response`. Unanswered requests expire
(`expires_at_ms`) and count as deny. Approvals are bound to `approval_id` (one action) and are only
accepted from an authenticated session (Noise static key of a trusted phone).

## Screen

`screen.request{action: snapshot|start|stop}`. Frames are JPEG, default 1280px wide, quality 60,
2 fps when streaming (cap 15). The laptop shows a desktop notification while streaming.
