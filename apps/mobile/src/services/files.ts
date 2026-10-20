import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import * as DocumentPicker from "expo-document-picker";
import { Directory, File, FileHandle, FileMode, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import type { Envelope } from "../protocol/Envelope";
import { useApp } from "../store/useApp";
import { uuidv4 } from "../transport/envelope";
import { fromBase64, toBase64, toHex } from "../util/bytes";
import { send } from "./connection";
import { safeFileName } from "./fileName";

export const CHUNK = 32 * 1024;

type Hasher = ReturnType<typeof sha256.create>;

interface Download {
  file: File;
  handle: FileHandle;
  hasher: Hasher;
  next: number;
  size: number;
  sha: string;
  lastReport: number;
}

interface Upload {
  file: File;
  size: number;
  sha: string;
  accept: (offset: number) => void;
}

const downloads = new Map<string, Download>();
const uploads = new Map<string, Upload>();


const st = () => useApp.getState();

function inbox(): Directory {
  const d = new Directory(Paths.cache, "autopilot-inbox");
  if (!d.exists) d.create({ intermediates: true });
  return d;
}

export function requestFile(path: string): boolean {
  return send({ type: "file.request", payload: { path } });
}

export async function handleFileMessage(env: Envelope): Promise<void> {
  switch (env.type) {
    case "file.offer": {
      const { transfer_id, name, size, sha256: sha } = env.payload;
      if (downloads.has(transfer_id)) return;
      const file = new File(inbox(), safeFileName(name));
      if (file.exists) file.delete();
      file.create();
      const handle = file.open(FileMode.ReadWrite);
      downloads.set(transfer_id, { file, handle, hasher: sha256.create(), next: 0, size, sha: sha.toLowerCase(), lastReport: 0 });
      st().putTransfer({ id: transfer_id, name, direction: "down", size, done: 0, state: "active" });
      send({ type: "file.accept", payload: { transfer_id, offset: 0 } });
      return;
    }
    case "file.chunk": {
      const d = downloads.get(env.payload.transfer_id);
      if (!d) return;
      if (env.payload.offset !== d.next) return failDownload(env.payload.transfer_id, "out-of-order chunk");
      const bytes = fromBase64(env.payload.data_b64);
      if (d.next + bytes.length > d.size) return failDownload(env.payload.transfer_id, "more data than offered");
      d.handle.writeBytesSync(bytes);
      d.hasher.update(bytes);
      d.next += bytes.length;
      if (d.next - d.lastReport >= Math.max(CHUNK * 8, d.size / 50) || d.next === d.size) {
        d.lastReport = d.next;
        st().patchTransfer(env.payload.transfer_id, { done: d.next });
      }
      return;
    }
    case "file.done": {
      const id = env.payload.transfer_id;
      const up = uploads.get(id);
      if (up) {
        uploads.delete(id);
        st().patchTransfer(id, env.payload.ok ? { state: "ok", done: up.size } : { state: "failed", error: env.payload.reason ?? "rejected" });
        return;
      }
      const d = downloads.get(id);
      if (!d) return;
      downloads.delete(id);
      d.handle.close();
      const got = toHex(d.hasher.digest());
      if (!env.payload.ok) return markFailed(d, id, env.payload.reason ?? "laptop aborted transfer");
      if (d.next !== d.size || got !== d.sha || got !== env.payload.sha256.toLowerCase()) {
        return markFailed(d, id, "checksum mismatch");
      }
      st().patchTransfer(id, { state: "ok", done: d.size, uri: d.file.uri });
      await shareFile(d.file.uri);
      return;
    }
    case "file.accept": {
      uploads.get(env.payload.transfer_id)?.accept(env.payload.offset);
      return;
    }
    default:
      return;
  }
}

function markFailed(d: Download, id: string, reason: string): void {
  try {
    d.file.delete();
  } catch {
    /* ignore */
  }
  st().patchTransfer(id, { state: "failed", error: reason });
}

function failDownload(id: string, reason: string): void {
  const d = downloads.get(id);
  if (!d) return;
  downloads.delete(id);
  try {
    d.handle.close();
  } catch {
    /* ignore */
  }
  markFailed(d, id, reason);
  send({ type: "file.done", payload: { transfer_id: id, ok: false, sha256: "", reason } });
}

export function failAllTransfers(reason: string): void {
  for (const id of [...downloads.keys()]) {
    const d = downloads.get(id)!;
    downloads.delete(id);
    try {
      d.handle.close();
    } catch {
      /* ignore */
    }
    markFailed(d, id, reason);
  }
  for (const id of [...uploads.keys()]) {
    uploads.delete(id);
    st().patchTransfer(id, { state: "failed", error: reason });
  }
}

export async function shareFile(uri: string): Promise<void> {
  if (await Sharing.isAvailableAsync()) await Sharing.shareAsync(uri);
}

async function hashFile(file: File): Promise<string> {
  const h = sha256.create();
  const handle = file.open(FileMode.ReadOnly);
  try {
    for (;;) {
      const b = await handle.readBytes(256 * 1024);
      if (b.length === 0) break;
      h.update(b);
    }
  } finally {
    handle.close();
  }
  return toHex(h.digest());
}

/** Pick a document and stream it to the laptop: file.offer, wait for file.accept, 32 KB chunks, file.done. */
export async function pickAndSend(): Promise<void> {
  const res = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false });
  if (res.canceled || !res.assets?.[0]) return;
  const asset = res.assets[0];
  const file = new File(asset.uri);
  const size = file.size ?? asset.size ?? 0;
  const id = uuidv4(randomBytes);
  st().putTransfer({ id, name: asset.name, direction: "up", size, done: 0, state: "waiting" });
  const sha = await hashFile(file);
  const accepted = new Promise<number>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("laptop did not accept the file")), 60_000);
    uploads.set(id, { file, size, sha, accept: (o) => (clearTimeout(t), resolve(o)) });
  });
  if (!send({ type: "file.offer", payload: { transfer_id: id, name: safeFileName(asset.name), size, sha256: sha } })) {
    uploads.delete(id);
    st().patchTransfer(id, { state: "failed", error: "not connected" });
    return;
  }
  let offset: number;
  try {
    offset = await accepted;
  } catch (e) {
    uploads.delete(id);
    st().patchTransfer(id, { state: "failed", error: (e as Error).message });
    return;
  }
  st().patchTransfer(id, { state: "active", done: offset });
  const handle = file.open(FileMode.ReadOnly);
  try {
    handle.offset = offset;
    let pos = offset;
    let lastReport = pos;
    while (pos < size) {
      if (!uploads.has(id)) return; // cancelled / disconnected
      const b = await handle.readBytes(Math.min(CHUNK, size - pos));
      if (b.length === 0) break;
      if (!send({ type: "file.chunk", payload: { transfer_id: id, offset: pos, data_b64: toBase64(b) } })) {
        throw new Error("connection lost");
      }
      pos += b.length;
      if (pos - lastReport >= CHUNK * 8 || pos === size) {
        lastReport = pos;
        st().patchTransfer(id, { done: pos });
      }
    }
    send({ type: "file.done", payload: { transfer_id: id, ok: true, sha256: sha, reason: null } });
    // Keep the entry so a laptop-side file.done{ok:false} can still flip it to failed.
    st().patchTransfer(id, { state: "ok", done: size });
  } catch (e) {
    uploads.delete(id);
    st().patchTransfer(id, { state: "failed", error: (e as Error).message });
  } finally {
    handle.close();
  }
}
