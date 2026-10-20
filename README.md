# AutoPilot

Control your own laptop from your phone by chatting with an agent that runs **on the laptop**.
A local decision model (Laya) handles most requests; Claude, OpenAI, or Gemini are called only when
the deterministic router allows it, after redaction. Risky actions need approval on the phone, and a
kill switch always works. Linux (Hyprland/Wayland first-class, X11) and Windows.

- **Phone** (`apps/mobile`): Expo / React Native — chat, approvals, on-demand screen view, files.
- **Daemon** (`crates/autopilotd` + `crates/agent-*`): Rust/tokio, event-driven, no polling.
- **Tray app** (`apps/desktop`): Tauri 2 — pairing QR, devices, kill switch (Ctrl+Alt+Shift+K), logs.
- **Relay** (`services/backend`): Axum blind WebSocket relay; sees only Noise ciphertext.

Transport: Noise XX over WebSocket — direct (LAN/Tailscale) or via the relay. Screen: on-demand JPEG.

## Quickstart

```sh
# daemon
cargo build --release -p autopilotd
install -Dm755 target/release/autopilotd ~/.local/bin/
autopilotd keys set claude        # optional cloud brain (also: openai, gemini)
autopilotd run &                  # or the systemd user unit, see docs/runbook.md
autopilotd pair                   # scan the QR with the phone app

# relay (optional, for phone and laptop on different networks)
cargo run -p backend              # BIND=0.0.0.0:8080 by default
# or: cd services/infra && cp .env.example .env && docker compose up -d --build

# phone dev client
cd apps/mobile && npm ci && npx expo run:android
```

Full setup (Laya venv, systemd, Hyprland kill bind, mobile dev client): [docs/runbook.md](docs/runbook.md).

## Docs

- [Architecture](docs/architecture.md) — components, decision pipeline, battery/latency strategy
- [Protocol](docs/protocol.md) — wire format, Noise handshake, relay
- [Threat model](docs/threat-model.md)
- [Decisions](docs/decisions.md) — ADR log
- [Plans](docs/plans/) — M0..M6

## Status

Pre-alpha, milestone M0/M1. Working: protocol crate + TS bindings, blind relay backend with tests,
docker-compose infra, CI. In progress: transport (Noise), agent core, capture/input, mobile app,
tray app. Not for production use yet.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

License: MIT.
