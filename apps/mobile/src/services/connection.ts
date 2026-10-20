import { randomBytes } from "@noble/hashes/utils.js";
import { AppState, AppStateStatus, Platform } from "react-native";
import type { Envelope } from "../protocol/Envelope";
import type { Message } from "../protocol/Message";
import type { PairingQr } from "../protocol/PairingQr";
import { getDeviceKey } from "../keys/deviceKey";
import { clearLaptop, loadLaptop, PairedLaptop, saveLaptop } from "../keys/laptopStore";
import { useApp } from "../store/useApp";
import { backoffMs } from "../transport/backoff";
import { relayRoom } from "../transport/confirm";
import { candidateUrls } from "../transport/qr";
import { PinMismatchError, SecureSession } from "../transport/session";
import { fromBase64 } from "../util/bytes";
import { handleFileMessage, failAllTransfers } from "./files";
import { loadSettings } from "./settings";
import { speak } from "./voice";

/** Relay close codes (services/backend): 4000 replaced by newer phone, 4404 no laptop, 4410 laptop left. */
const RELAY_REPLACED = 4000;

let session: SecureSession | null = null;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let attempt = 0;
let foreground = AppState.currentState === "active";
let appStateSub: { remove(): void } | null = null;
/** Pairing attempt in progress (QR data), so reconnects don't kick in meanwhile. */
let pairingQr: PairingQr | null = null;

const st = () => useApp.getState();

export async function boot(): Promise<void> {
  const [laptop] = await Promise.all([loadLaptop(), loadSettings(), getDeviceKey()]);
  st().set({ laptop, booted: true });
  if (!appStateSub) appStateSub = AppState.addEventListener("change", onAppState);
  if (laptop && foreground) connect();
}

function onAppState(s: AppStateStatus): void {
  const fg = s === "active";
  if (fg === foreground) return;
  foreground = fg;
  if (fg) {
    attempt = 0;
    if (st().laptop) connect();
  } else {
    // Battery: no sockets, timers or screen frames while backgrounded.
    disconnect("app in background");
  }
}

function urlsFor(pk: Uint8Array, addrs: string[], relay: string | null): string[] {
  return candidateUrls(addrs, relay, relayRoom(pk));
}

export function isOpen(): boolean {
  return !!session?.isOpen;
}

export function send(msg: Message): boolean {
  if (!session?.isOpen) return false;
  try {
    session.send(msg);
    return true;
  } catch {
    return false;
  }
}

function clearRetry(): void {
  if (retryTimer) clearTimeout(retryTimer);
  retryTimer = null;
}

export function disconnect(reason: string): void {
  clearRetry();
  const s = session;
  session = null;
  s?.close(reason);
  failAllTransfers("disconnected");
  st().set({ conn: "idle", live: false, screenActive: false });
}

function scheduleRetry(): void {
  clearRetry();
  if (!foreground || !st().laptop || pairingQr) return;
  const delay = backoffMs(attempt++);
  retryTimer = setTimeout(() => connect(), delay);
}

export async function connect(): Promise<void> {
  const laptop = st().laptop;
  if (!laptop || session || !foreground) return;
  clearRetry();
  const key = await getDeviceKey();
  const pk = fromBase64(laptop.pk);
  st().set({ conn: "connecting", connError: null });
  const s = new SecureSession(
    { urls: urlsFor(pk, laptop.addrs, laptop.relay), deviceKey: key, laptopPk: pk, random: randomBytes },
    {
      onOpen: ({ url }) => {
        attempt = 0;
        st().set({ conn: "open", connUrl: url });
        pushSettings();
      },
      onMessage: dispatch,
      onFrame: (frame) => st().set({ frame }),
      onClose: (reason, _wasOpen, code) => {
        if (session !== s) return;
        session = null;
        failAllTransfers(reason);
        if (code === RELAY_REPLACED) {
          // A newer phone took the relay room; do not fight it. Reconnects on next foreground.
          st().set({ conn: "offline", connError: "Another phone connected to this laptop", live: false, screenActive: false });
          return;
        }
        st().set({ conn: "offline", connError: reason, live: false, screenActive: false });
        scheduleRetry();
      },
    },
  );
  session = s;
  try {
    await s.start();
  } catch (e) {
    if (session !== s) return;
    session = null;
    const msg = e instanceof PinMismatchError ? "Laptop identity changed — re-pair required" : (e as Error).message;
    st().set({ conn: "offline", connError: msg });
    if (!(e instanceof PinMismatchError)) scheduleRetry();
  }
}

/** Pair using a scanned QR. Resolves when the laptop accepts (or rejects) the claim. */
export async function pair(qr: PairingQr): Promise<void> {
  disconnect("pairing");
  pairingQr = qr;
  const key = await getDeviceKey();
  const pk = fromBase64(qr.laptop_pk);
  st().set({ pairing: { code: null, status: "connecting" } });
  const s = new SecureSession(
    {
      urls: urlsFor(pk, qr.addrs, qr.relay),
      deviceKey: key,
      laptopPk: pk,
      random: randomBytes,
      claim: { token: qr.token, device_name: `${Platform.OS === "ios" ? "iPhone" : "Android"} (AutoPilot)` },
    },
    {
      onOpen: ({ code, url }) => {
        st().set({ pairing: { code, status: "confirm" }, conn: "open", connUrl: url });
      },
      onMessage: async (env) => {
        if (env.type === "pair.result") {
          if (env.payload.ok) {
            const laptop: PairedLaptop = {
              pk: qr.laptop_pk,
              name: env.payload.laptop_name || qr.laptop_name,
              addrs: qr.addrs,
              relay: qr.relay,
              pairedAt: Date.now(),
            };
            await saveLaptop(laptop);
            pairingQr = null;
            const code = st().pairing?.code ?? null;
            st().set({ laptop, pairing: { code, status: "ok" } });
            pushSettings();
          } else {
            st().set({ pairing: { code: st().pairing?.code ?? null, status: "failed", error: env.payload.reason ?? "Rejected by laptop" } });
            pairingQr = null;
            disconnect("pairing rejected");
          }
          return;
        }
        dispatch(env);
      },
      onFrame: (frame) => st().set({ frame }),
      onClose: (reason) => {
        if (session !== s) return;
        session = null;
        const p = st().pairing;
        if (p && p.status !== "ok") st().set({ pairing: { ...p, status: "failed", error: reason } });
        st().set({ conn: "offline", connError: reason, live: false });
        pairingQr = null;
        scheduleRetry();
      },
    },
  );
  session = s;
  try {
    await s.start();
  } catch (e) {
    if (session === s) session = null;
    pairingQr = null;
    st().set({ pairing: { code: null, status: "failed", error: (e as Error).message }, conn: "offline" });
  }
}

export function cancelPairing(): void {
  if (pairingQr) {
    pairingQr = null;
    disconnect("pairing cancelled");
  }
  st().set({ pairing: null });
}

export async function unpair(): Promise<void> {
  disconnect("unpaired");
  await clearLaptop();
  st().set({ laptop: null, items: [], tasks: {}, approvals: [], frame: null, pairing: null, conn: "idle" });
}

export function pushSettings(): void {
  const s = st().settings;
  send({ type: "settings.update", payload: { ...s } });
}

function dispatch(env: Envelope): void {
  const a = st();
  switch (env.type) {
    case "chat.agent": {
      const finalText = a.addAgent(env.payload);
      if (finalText && a.settings.voice_replies) speak(finalText);
      break;
    }
    case "task.update":
      a.upsertTask(env.payload);
      break;
    case "approval.request":
      a.pushApproval(env.payload);
      break;
    case "screen.state":
      a.set({ screenActive: env.payload.active, live: env.payload.active ? a.live : false });
      break;
    case "notify":
      a.addNotice(env.payload.text, env.payload.level);
      break;
    case "error":
      a.addNotice(`${env.payload.code}: ${env.payload.message}`, "error");
      break;
    case "settings.update": {
      const p = env.payload;
      a.set({
        settings: {
          cloud_enabled: p.cloud_enabled ?? a.settings.cloud_enabled,
          cloud_allow_high_sensitivity: p.cloud_allow_high_sensitivity ?? a.settings.cloud_allow_high_sensitivity,
          preferred_cloud: p.preferred_cloud ?? a.settings.preferred_cloud,
          voice_replies: p.voice_replies ?? a.settings.voice_replies,
        },
      });
      break;
    }
    case "file.offer":
    case "file.accept":
    case "file.chunk":
    case "file.done":
      void handleFileMessage(env);
      break;
    case "pair.result":
      if (!env.payload.ok) a.addNotice(env.payload.reason ?? "Laptop rejected this phone", "error");
      break;
    default:
      break;
  }
}
