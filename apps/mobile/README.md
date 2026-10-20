# AutoPilot mobile (Expo dev client)

Phone app for driving the AutoPilot laptop agent: chat/voice, approvals, live screen, files, kill switch.
Everything after the WebSocket is end-to-end encrypted with `Noise_XX_25519_ChaChaPoly_BLAKE2s`
(pure TS in `src/noise/`, checked against the cacophony/snow vectors and the Rust
`crates/agent-transport/tests/vectors/xx_vector.json`). See `docs/protocol.md`.

## Layout

| Path | What |
| --- | --- |
| `src/protocol/` | Generated from Rust via ts-rs. **Do not edit.** |
| `src/noise/` | CipherState / SymmetricState / HandshakeState (Noise rev 34) |
| `src/transport/` | `SecureSession` (WS + handshake + key pin + seq guard + ping), QR parsing, frame reassembly, confirmation code |
| `src/services/` | Connection manager (AppState-aware reconnect), file transfer, voice, settings |
| `src/store/` | zustand store |
| `src/app/` | expo-router screens: pairing, chat, screen, files, settings; approval sheet is global |

## Develop

```bash
npm ci            # .npmrc sets legacy-peer-deps (expo-router web peer conflict)
npm run typecheck
npm run lint
npm test
```

## Build the dev client

The app uses native modules (camera, secure store, speech recognition, biometrics), so Expo Go will not work.

**Android, phone over USB** (needs Android SDK + JDK 17; enable USB debugging):

```bash
npx expo run:android          # prebuilds android/, builds and installs the dev client
npm start                     # Metro for the dev client (if not already running)
```

**EAS (cloud) build:**

```bash
npx eas-cli@latest build --profile development --platform android   # or ios
```

Install the resulting APK/IPA, then `npm start` and open the project from the dev client.

Note: Android is configured with `usesCleartextTraffic` so direct `ws://<lan-ip>:7878/ws` connections work.
This is fine because every frame is a Noise message; TLS (`wss://`) is used for the relay.

## Pair

1. On the laptop run the daemon's pair command; it prints a QR code (`autopilot://pair?d=...`).
2. In the app: scan the QR (or paste the link, or open it as a deep link).
3. The app connects (direct addresses first, then the relay room), pins the laptop key from the QR,
   completes the Noise handshake and sends `pair.claim`.
4. Compare the 6-digit code on the phone with the one on the laptop terminal. Cancel if they differ.
5. Once the laptop answers `pair.result{ok}`, the laptop (key, name, addresses, relay) is stored in
   the secure store. The phone's X25519 device key is generated once and kept in Keychain/Keystore.

## Behaviour notes

- Connection is open only while the app is in the foreground; backgrounding closes it (battery).
  Reconnect uses jittered exponential backoff. Relay close code 4000 (replaced by a newer phone) does not reconnect.
- Ping every 25 s; the session closes after 60 s of silence. Inbound `seq` replays close the session.
- Screen frames only flow on demand: Snapshot, or Live (2 fps), which stops when you leave the tab.
- Destructive approvals require biometric/device-passcode confirmation before `approve` is sent.
