# Threat model

Scope: AutoPilot v1 — phone app, laptop daemon (`autopilotd`), tray app, blind relay backend,
local models (Laya, optional Ollama), cloud LLM providers. Method: STRIDE per component, then
residual risks. Wire details: [protocol.md](protocol.md).

## Assets

1. Control of the laptop (input, shell, files, browser profile).
2. Laptop data: files in shared roots, screen contents, clipboard, audit log.
3. Secrets: device static keys, provider API keys, pairing tokens.
4. Conversation content and approvals.

## Trust boundaries

- Phone ⇄ laptop: authenticated only by Noise XX static keys (pinned laptop key from QR; phone key in
  laptop trust store). Everything between them (Wi-Fi, Tailscale, relay, Caddy, ISP) is untrusted.
- Laptop daemon ⇄ local processes: the control socket.
- Daemon ⇄ models: Laya/Ollama are local but their *outputs* are untrusted; cloud providers see only
  redacted, policy-approved content.
- Daemon ⇄ the world it reads: web pages, files, command output are attacker-controllable data.

## STRIDE

### Pairing (QR → `pair.claim`)

| Threat | Mitigation |
| --- | --- |
| **S** Attacker pairs their phone | QR shown only on the laptop screen/tray; token is 16 random bytes, single use, 5 min TTL, constant-time compare. Unknown static key must send a valid `pair.claim` as the first transport message or is dropped. 6-digit confirmation code from the handshake hash shown on both sides. |
| **S** Phone talks to a fake laptop | Phone pins `laptop_pk` from the QR and aborts after handshake message 2 if it differs. |
| **T** QR modified / photographed | Photo of a QR gives a token that expires in 5 min and is consumed on first use; a second claim fails and is visible in the device list. |
| **R** "I never paired that phone" | Pairing written to the audit log with the phone key fingerprint and name. |
| **I** Token leaks via logs | Tokens never logged; audit stores only a hash prefix. |
| **D** Token brute force | 128-bit token; failed claim closes the connection; relay rate limit. |
| **E** Paired phone = full control | By design, but still bounded by risk-tier approvals; revoke from tray "Devices" or the phone. |

### Session setup (Noise XX)

| Threat | Mitigation |
| --- | --- |
| **S** Impersonating a trusted phone | Requires the phone's static private key (device keystore). |
| **T** Tampering / injection | ChaCha20-Poly1305 AEAD per frame; any decrypt failure closes the session. |
| **T** Replay | `seq` strictly increasing per sender; Noise nonces; replay → drop + close. |
| **I** Eavesdropping | Forward secrecy from ephemeral X25519; relay sees ciphertext only. |
| **D** Handshake floods | Relay per-IP rate limit; direct listener bound per config (LAN/Tailscale); handshake state is per-connection and bounded. |

### Relay (services/backend)

| Threat | Mitigation |
| --- | --- |
| **S** Attacker joins a room | Room id is derived from the laptop *public* key, so it is not secret. Joining gives only ciphertext; Noise authentication prevents any command injection. |
| **T** Relay modifies frames | AEAD — detected, session closed. |
| **R** Abuse attribution | Debug logs record only room-id prefix, role, close code. No content, no full room ids at info level. |
| **I** Relay operator reads traffic | Impossible without device keys; metadata (timing, sizes, IPs) is visible — see residual risks. |
| **D** Kicking the laptop/phone | A newer connection of the same role replaces the old one, so anyone who knows the room can disconnect the peer (availability only). Mitigations: rate limit, idle timeout, max rooms, 70 000-byte frame cap, bounded queues. Planned: laptop authenticates to the relay with a signed challenge (registry, v1 follow-up). |
| **D** Memory exhaustion | Frames > 70 000 bytes close the socket; tungstenite hard limit; 64-frame bounded queues with backpressure and a timeout. |
| **E** Relay host compromise | Still only ciphertext; the relay holds no keys or secrets other than its DB password and TLS key. Distroless, non-root, read-only rootfs, `cap_drop: ALL`. |

### Approvals

| Threat | Mitigation |
| --- | --- |
| **S** Forged approval | Only accepted inside an authenticated Noise session from a trusted phone static key. |
| **T** Approval reused for another action | Bound to one `approval_id` (one tool call with exact args); single use. |
| **R** Disputed action | Audit log (hash-chained) records request, preview, response, actor. |
| **D** Approval spam fatigue | Read tier auto-runs; "always allow for this task" only for `write`, never `destructive`. |
| **E** Model downgrades risk | Risk tier comes from the tool definition (code), not the model's `risk` field; the higher of the two wins. Expired = deny. |

### Kill switch

| Threat | Mitigation |
| --- | --- |
| **D** Kill unavailable when remote path is down | Multiple independent paths: phone `control.kill`, tray button, global hotkey (Ctrl+Alt+Shift+K), `autopilotd kill` CLI, Hyprland bind. All go through the local control socket or the session. |
| **T** Task ignores kill | Kill is a cancellation token checked by the agent loop and every tool; screen stream stopped; pending approvals denied. |
| **S** Unauthenticated kill | Kill is safe-by-default (only stops things), so accepting it from any local user process is acceptable. |

### Local control socket (`~/.local/share/autopilot/control.sock`)

| Threat | Mitigation |
| --- | --- |
| **S/E** Other local users drive the daemon | Socket in a 0700 directory, socket mode 0600, peer UID check (`SO_PEERCRED`). Windows: named pipe with an owner-only DACL. |
| **I** `pair` leaks a token to malware running as the same user | Same-user malware already owns the session; documented residual risk. The `pair` command only returns a short-lived token. |
| **T** Malformed JSON | Line-length limit, strict serde parsing, unknown commands rejected. |

### Cloud calls and redaction

| Threat | Mitigation |
| --- | --- |
| **I** Secrets sent to a provider | Redaction layer (`agent-audit` redaction helper) strips keys/tokens/emails/paths before every cloud call; `sensitivity=high` never goes to the cloud without category consent (tested). |
| **I** API keys exfiltrated | Keys stored in the OS keystore, sent only to their own provider's HTTPS endpoint, never to the phone or backend, never logged. |
| **T** Provider returns malicious tool calls | Same as prompt injection below: tool calls are proposals, policy + approvals decide. |

### Prompt injection (web pages, files, command output, MCP results)

- All tool output is wrapped and labelled as **untrusted data** when given to Laya or a cloud model;
  it is never concatenated into the system prompt.
- Instructions inside data cannot change policy: risk tiers, approvals, shell allowlist, shared roots,
  and cloud routing are enforced in code after the model proposes a call.
- `write`/`destructive` actions proposed after reading untrusted content still require phone approval
  with a preview showing the exact action; the preview flags "proposed after reading external content".
- File tools are confined to shared roots (canonicalized, symlink-escape checks); the browser uses a
  dedicated profile without the user's main cookies.
- Agent loop step cap and per-task budget limit runaway loops.

## Residual risks

1. **Traffic metadata** visible to the relay/network (timing, sizes, IPs, room id ↔ laptop key).
2. **Room hijack DoS**: anyone who learns `laptop_pk` can kick connections in that room until relay
   auth lands.
3. **Same-user malware** on the laptop can talk to the control socket, read the device key file
   (until keyring storage), and inject input — out of scope for a user-level agent.
4. **Phone compromise** (unlocked, malware) = attacker has a trusted device; mitigated by approvals,
   optional biometric for destructive approvals, and fast revocation.
5. **Prompt injection** may still trick the user into approving a harmful action; previews and
   risk labelling reduce, not eliminate, this.
6. **Cloud provider retention** of redacted prompts per their policies.
7. **Wayland input tools** (`ydotool`) use a privileged uinput daemon; document and restrict to the user.
8. No independent security audit yet (M6).
