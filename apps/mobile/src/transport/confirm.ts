import { blake2s } from "@noble/hashes/blake2.js";
import { toHex } from "../util/bytes";

/** code = u32_be(BLAKE2s-256(handshake_hash)[0..4]) % 1_000_000, zero-padded to 6 digits. */
export function confirmationCode(handshakeHash: Uint8Array): string {
  const d = blake2s(handshakeHash);
  const n = ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3];
  return String(n % 1_000_000).padStart(6, "0");
}

/** Relay room = hex(BLAKE2s-256(laptop_static_pk))[0..32]. */
export function relayRoom(laptopPk: Uint8Array): string {
  return toHex(blake2s(laptopPk)).slice(0, 32);
}
