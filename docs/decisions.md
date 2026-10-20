# Decision log (ADRs)

Format: context → decision → consequences. Newest last. Spec §3 decisions not listed here stand.

## ADR-001 — Laya as the local decision model / router

- **Context:** The spec calls for a small local tool-calling model (Ollama, Qwen3-class) as the first
  stop for every message. Owner wants the Jev-style "System 1" decision layer.
- **Decision:** Use **Laya** (`convaiinnovations/laya`) served locally by `laya-serve` with the
  Jev-compatible `POST /v1/systemone` API as the decision model. It emits the structured decision
  (intent, plan, route, sensitivity, risk, confidence). A rules fast path runs before it; deterministic
  router code has the final word. Ollama remains optional for local generation.
- **Consequences:** Python venv at `~/.local/share/autopilot/laya-venv`; daemon manages the process
  (spawn on demand, unload after 5 min idle). Decision schema must stay compatible with Laya output.

## ADR-002 — Noise XX over WebSocket before WebRTC

- **Context:** Spec locks WebRTC + DTLS + Noise. webrtc-rs maturity is a listed risk; battery and
  complexity matter on phones; owner uses Tailscale/LAN often.
- **Decision:** v1 transport = Noise `XX_25519_ChaChaPoly_BLAKE2s` over WebSocket binary frames, direct
  (LAN/Tailscale) or through the backend's **blind relay**. Kept behind a transport trait; WebRTC
  (with coturn) is a later upgrade, mainly for video.
- **Consequences:** Relay traffic costs server bandwidth (no P2P hole punching); simpler, debuggable,
  works through any HTTPS-capable network. coturn stays in compose under a profile.

## ADR-003 — Hyprland/Wayland first-class

- **Context:** Spec defers Wayland. The owner's machine runs Hyprland.
- **Decision:** Linux Wayland on Hyprland is first-class alongside Windows and X11. Capture with
  `grim` (wlr-screencopy), input via virtual keyboard/pointer protocols or `wtype`/`ydotool`,
  window management via `hyprctl`. GNOME/KDE Wayland via portals later.
- **Consequences:** Platform matrix grows; CI cannot test Wayland capture (manual test checklist).

## ADR-004 — On-demand JPEG frames instead of an H.264 video track

- **Context:** Spec suggests openh264/VP8 720p15. The main use is "show me the screen now".
- **Decision:** Screen = on-demand JPEG snapshots (default 1280 px, q60) and an optional low-fps
  stream (2 fps, cap 15) of JPEG frames over the Noise session. No video encoder in v1.
- **Consequences:** Much lower CPU/battery when idle or for occasional views; no continuous encoder;
  higher bandwidth per frame at high fps — acceptable at 2 fps. Hardware video via WebRTC later.

## ADR-005 — Cloud providers: Claude, OpenAI, Gemini

- **Context:** Spec lists Claude and Gemini. Owner adds OpenAI.
- **Decision:** Three cloud providers behind one trait in `agent-llm` (chat, stream, structured
  output, vision, tool calling). `preferred_cloud` config picks the default; fallback order configurable.
  Keys in the OS keystore via `autopilotd keys set <provider>`.
- **Consequences:** Three API surfaces to maintain; provider differences hidden behind the trait;
  per-provider cost accounting.

## ADR-006 — Backend relay runs without a database

- **Context:** The registry/passkeys (spec §11) are not needed for Noise pairing, which is peer-to-peer.
- **Decision:** The relay is stateless; Postgres migrations exist behind the `db` feature and
  `DATABASE_URL` is optional.
- **Consequences:** Self-hosting is a single small binary; account features come in v1 follow-ups.

## ADR-007 — MCP plugins: stdio only, policy in our config

- **Context:** M5 needs MCP plugins (first: Odoo) with per-server permission scopes. Servers are
  third-party code returning untrusted names, descriptions, annotations and results.
- **Decision:** Own minimal client in `agent-mcp` (newline JSON-RPC over stdio, protocol 2025-06-18,
  no client capabilities except ping) rather than an SDK. Risk tier per tool comes from config globs
  (`read_tools`, `destructive_tools`, `default_risk`, `allow`/`deny`); annotations may only raise risk.
  Servers start lazily, stop after idle, run with a cleared environment, and their tool lists are
  cached so startup spawns nothing. Results are labelled untrusted; images are dropped for now.
- **Consequences:** Small dependency surface and low idle cost. No Streamable HTTP, sampling,
  elicitation or resources yet; tool-list changes need a daemon restart.
