import type { PairingQr } from "../protocol/PairingQr";
import { fromBase64, utf8Decode } from "../util/bytes";

export const PAIR_PREFIX = "autopilot://pair?d=";

export class QrError extends Error {}

/** Parses `autopilot://pair?d=<base64url(json PairingQr)>` and validates its fields. */
export function parsePairingUri(uri: string, nowMs: number = Date.now()): PairingQr {
  const s = uri.trim();
  if (!s.startsWith(PAIR_PREFIX)) throw new QrError("Not an AutoPilot pairing code");
  const d = decodeURIComponent(s.slice(PAIR_PREFIX.length).split("&")[0]);
  let obj: unknown;
  try {
    obj = JSON.parse(utf8Decode(fromBase64(d)));
  } catch {
    throw new QrError("Pairing code is corrupted");
  }
  const q = obj as Partial<PairingQr>;
  if (!q || typeof q !== "object") throw new QrError("Pairing code is corrupted");
  if (q.v !== 1) throw new QrError(`Unsupported pairing version ${String(q.v)}`);
  if (!Array.isArray(q.addrs) || !q.addrs.every((a) => typeof a === "string")) throw new QrError("Invalid addresses");
  if (q.relay !== null && q.relay !== undefined && typeof q.relay !== "string") throw new QrError("Invalid relay");
  if (q.relay && !/^wss?:\/\//.test(q.relay)) throw new QrError("Relay must be a ws:// or wss:// URL");
  if (typeof q.laptop_pk !== "string") throw new QrError("Missing laptop key");
  let pk: Uint8Array;
  try {
    pk = fromBase64(q.laptop_pk);
  } catch {
    throw new QrError("Invalid laptop key");
  }
  if (pk.length !== 32) throw new QrError("Invalid laptop key");
  if (typeof q.token !== "string" || q.token.length === 0) throw new QrError("Missing pairing token");
  if (typeof q.laptop_name !== "string") throw new QrError("Missing laptop name");
  if (typeof q.expires_at_ms !== "number") throw new QrError("Missing expiry");
  if (q.expires_at_ms < nowMs) throw new QrError("Pairing code expired; generate a new one on the laptop");
  if (q.addrs.length === 0 && !q.relay) throw new QrError("No way to reach the laptop");
  return {
    v: 1,
    addrs: q.addrs,
    relay: q.relay ?? null,
    laptop_pk: q.laptop_pk,
    laptop_name: q.laptop_name,
    token: q.token,
    expires_at_ms: q.expires_at_ms,
  };
}

/** Candidate WebSocket URLs in order: direct addrs, then relay room. */
export function candidateUrls(addrs: string[], relay: string | null, room: string): string[] {
  const out = addrs.map((a) => (/^wss?:\/\//.test(a) ? a : `ws://${a}/ws`));
  if (relay) out.push(`${relay.replace(/\/+$/, "")}/${room}?role=phone`);
  return out;
}
