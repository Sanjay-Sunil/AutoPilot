# Runbook

Commands assume Linux (Hyprland) unless noted. Rust via mise (`mise exec rust -- cargo ...`) or rustup.

## 1. Build and install the daemon

```sh
cargo build --release -p autopilotd
install -Dm755 target/release/autopilotd ~/.local/bin/autopilotd
autopilotd --help
```

Runtime dependencies on Hyprland: `grim` (screen), `wl-clipboard`, `wtype` (or `ydotool`), `hyprctl`.
On X11: `libxcb`, `libxrandr`. Data dir: `~/.local/share/autopilot/`.

## 2. Laya (local decision model)

```sh
python3 -m venv ~/.local/share/autopilot/laya-venv
~/.local/share/autopilot/laya-venv/bin/pip install --upgrade pip
~/.local/share/autopilot/laya-venv/bin/pip install "git+https://github.com/convaiinnovations/laya"
# (follow Laya's README if its install steps differ; the daemon only needs `laya-serve` in this venv)
# smoke test (the daemon normally starts/stops it itself and unloads it after 5 min idle)
~/.local/share/autopilot/laya-venv/bin/laya-serve --host 127.0.0.1 --port 8765 &
curl -s http://127.0.0.1:8765/v1/systemone -H 'content-type: application/json' \
  -d '{"query":"turn the volume down"}'   # request shape: see Laya / agent-llm docs
```

The daemon talks to `laya_url` (default `http://127.0.0.1:8765`). Bind Laya to localhost only.
Optional Ollama: set `ollama_url`/`ollama_model` in the config; requests use `keep_alive` so the model
unloads when idle.

## 3. Cloud API keys

Keys go into the OS keystore (Secret Service on Linux, Credential Manager on Windows), never into
config files:

```sh
autopilotd keys set claude     # prompts for the key, no echo
autopilotd keys set openai
autopilotd keys set gemini
autopilotd keys list           # shows which providers are configured, never the key
```

Cloud use is policy-gated (`cloud_enabled`, `cloud_allow_high_sensitivity`, `preferred_cloud`).

## 4. systemd user units

`~/.config/systemd/user/autopilotd.service`:

```ini
[Unit]
Description=AutoPilot agent daemon
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=%h/.local/bin/autopilotd run
Restart=on-failure
RestartSec=3
# Hardening (user unit compatible)
NoNewPrivileges=yes
PrivateTmp=yes
Environment=RUST_LOG=info

[Install]
WantedBy=graphical-session.target
```

Make sure the session environment (`WAYLAND_DISPLAY`, `HYPRLAND_INSTANCE_SIGNATURE`) reaches systemd,
e.g. in `hyprland.conf`: `exec-once = systemctl --user import-environment WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE XDG_CURRENT_DESKTOP`.

```sh
systemctl --user daemon-reload
systemctl --user enable --now autopilotd
journalctl --user -u autopilotd -f
```

Optional tray app unit (`autopilot-tray.service`) with `ExecStart=%h/.local/bin/autopilot-desktop`,
same `[Install]` section. Windows: register `autopilotd run` with Task Scheduler "At log on".

## 5. Kill switch

- Phone: kill button. Tray: **KILL SWITCH**. Tray global shortcut: `Ctrl+Alt+Shift+K`.
- CLI: `autopilotd kill`.
- Hyprland bind (add to your own `~/.config/hypr/hyprland.conf` / bindings file):

```
bind = CTRL ALT SHIFT, K, exec, autopilotd kill
```

(If the tray app is running it also registers the same shortcut; use one or the other to avoid a
conflict — the Hyprland bind works even without the tray.)

## 6. Pair the phone

1. On the laptop: tray → **Pair phone** (QR window), or `autopilotd pair` (QR in the terminal),
   or `autopilotd pair --json` for `{uri, code, expires_at_ms}`.
2. Phone app → Pair → scan. The phone pins the laptop key from the QR.
3. Compare the 6-digit confirmation code on both screens.
4. The token expires in 5 minutes and is single use. Revoke devices from tray → Devices.

Direct path: phone and laptop on the same LAN or Tailscale tailnet (`ws://<laptop>:7878/ws`). Relay
path: set `relay` in the daemon config to `wss://<your-domain>/relay`.

## 7. Self-host the relay

```sh
cd services/infra
cp .env.example .env   # set DOMAIN, POSTGRES_PASSWORD (and TURN_SECRET for --profile turn)
docker compose up -d --build
curl https://$DOMAIN/health
```

The relay works without Postgres too: `BIND=0.0.0.0:8080 cargo run -p backend`.
Tunables: `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_BURST`, `RELAY_IDLE_SECS`, `RELAY_MAX_FRAME`, `MAX_ROOMS`,
`TRUST_FORWARDED` (only behind Caddy).

## 8. Mobile dev client

```sh
cd apps/mobile
npm ci
npx expo prebuild            # generates android/ ios/ (dev client, native modules)
npx expo run:android         # or: npx expo run:ios  (macOS only)
npx expo start --dev-client  # Metro; open the dev client on the phone
```

Android: enable USB debugging, or `eas build --profile development` for a cloud-built dev client.

## 9. Tray app

```sh
cd apps/desktop/src-tauri
cargo build --release   # needs webkit2gtk-4.1, libayatana-appindicator3 (Linux)
```

## 10. Logs and troubleshooting

- Daemon: `journalctl --user -u autopilotd`; data/logs in `~/.local/share/autopilot/`.
- Audit log: `~/.local/share/autopilot/audit.db` (hash-chained; `autopilotd audit verify`).
- Relay: `docker compose logs backend` (never contains frame contents; `RUST_LOG=debug` adds room-id
  prefixes and close codes).
- Relay close codes: 4000 replaced, 4404 laptop offline, 4408 idle, 4410 laptop gone, 1003 text frame,
  1009 frame too large, 1013 relay full.
