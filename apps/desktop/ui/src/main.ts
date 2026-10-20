// Tiny vanilla UI. Talks to Rust commands via the global Tauri API (app.withGlobalTauri).

type Json = Record<string, unknown>;

declare global {
  interface Window {
    __TAURI__: { core: { invoke<T = Json>(cmd: string, args?: Json): Promise<T> } };
  }
}

const invoke = <T = Json>(cmd: string, args?: Json): Promise<T> =>
  window.__TAURI__.core.invoke<T>(cmd, args);

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};

function showError(e: unknown): void {
  const el = $("error");
  el.textContent = e ? String(e) : "";
  el.hidden = !e;
}

async function loadStatus(): Promise<void> {
  try {
    const s = await invoke("status");
    $("status-out").textContent = JSON.stringify(s, null, 2);
    showError(null);
  } catch (e) {
    $("status-out").textContent = "Daemon not reachable.";
    showError(e);
  }
}

let expiryTimer: number | undefined;

async function loadPair(): Promise<void> {
  try {
    const r = await invoke<{ uri: string; code?: string; expires_at_ms?: number; svg: string }>("pair");
    $<HTMLImageElement>("qr").src = "data:image/svg+xml;base64," + btoa(r.svg);
    $("pair-code").textContent = r.code ?? "shown after scan";
    window.clearInterval(expiryTimer);
    if (r.expires_at_ms) {
      const tick = (): void => {
        const left = Math.max(0, Math.round(((r.expires_at_ms ?? 0) - Date.now()) / 1000));
        $("pair-expiry").textContent = left > 0 ? `Expires in ${left}s (single use)` : "Expired — get a new code";
      };
      tick();
      expiryTimer = window.setInterval(tick, 1000);
    }
    showError(null);
  } catch (e) {
    showError(e);
  }
}

interface Device {
  name: string;
  pk_b64: string;
  paired_at_ms?: number;
}

async function loadDevices(): Promise<void> {
  const list = $("device-list");
  list.replaceChildren();
  try {
    const r = await invoke<{ devices?: Device[] } | Device[]>("devices");
    const devices = Array.isArray(r) ? r : (r.devices ?? []);
    if (devices.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No paired devices.";
      list.append(li);
    }
    for (const d of devices) {
      const li = document.createElement("li");
      const info = document.createElement("div");
      info.textContent = d.name;
      const small = document.createElement("small");
      small.textContent = `${d.pk_b64.slice(0, 16)}…` + (d.paired_at_ms ? ` · ${new Date(d.paired_at_ms).toLocaleString()}` : "");
      info.append(small);
      const btn = document.createElement("button");
      btn.textContent = "Revoke";
      btn.onclick = async () => {
        if (!confirm(`Revoke ${d.name}? Its sessions end immediately.`)) return;
        try {
          await invoke("revoke", { pk: d.pk_b64 });
          await loadDevices();
        } catch (e) {
          showError(e);
        }
      };
      li.append(info, btn);
      list.append(li);
    }
    showError(null);
  } catch (e) {
    showError(e);
  }
}

const views: Record<string, () => Promise<void>> = {
  status: loadStatus,
  pair: loadPair,
  devices: loadDevices,
};

function route(): void {
  const name = location.hash.replace("#", "") || "status";
  for (const v of Object.keys(views)) {
    $(`view-${v}`).hidden = v !== name;
  }
  document.querySelectorAll("nav a").forEach((a) => {
    a.classList.toggle("active", a.getAttribute("href") === `#${name}`);
  });
  if (name !== "pair") window.clearInterval(expiryTimer);
  void (views[name] ?? loadStatus)();
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", () => {
  $("kill").onclick = async () => {
    try {
      await invoke("kill");
      showError("KILL SENT — all actions stopped.");
    } catch (e) {
      showError(e);
    }
  };
  $("status-refresh").onclick = () => void loadStatus();
  $("pair-new").onclick = () => void loadPair();
  $("devices-refresh").onclick = () => void loadDevices();
  route();
});

export {};
