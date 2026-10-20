// Noise_25519_ChaChaPoly_BLAKE2s primitive set (Noise spec rev 34, section 12).
import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake2s } from "@noble/hashes/blake2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { concat } from "../util/bytes";

export const DHLEN = 32;
export const HASHLEN = 32;
export const TAGLEN = 16;
export const MAX_MESSAGE = 65535;

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function keyPairFromPrivate(privateKey: Uint8Array): KeyPair {
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function dh(kp: KeyPair, pub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(kp.privateKey, pub);
}

export function hash(data: Uint8Array): Uint8Array {
  return blake2s(data);
}

/** 96-bit nonce: 32 bits of zeros followed by little-endian 64-bit n. */
export function nonceBytes(n: number): Uint8Array {
  const out = new Uint8Array(12);
  let lo = n >>> 0;
  let hi = Math.floor(n / 0x100000000) >>> 0;
  for (let i = 0; i < 4; i++) {
    out[4 + i] = lo & 0xff;
    lo >>>= 8;
  }
  for (let i = 0; i < 4; i++) {
    out[8 + i] = hi & 0xff;
    hi >>>= 8;
  }
  return out;
}

export function encrypt(k: Uint8Array, n: number, ad: Uint8Array, pt: Uint8Array): Uint8Array {
  return chacha20poly1305(k, nonceBytes(n), ad).encrypt(pt);
}

export function decrypt(k: Uint8Array, n: number, ad: Uint8Array, ct: Uint8Array): Uint8Array {
  return chacha20poly1305(k, nonceBytes(n), ad).decrypt(ct);
}

/** HKDF per Noise spec section 4.3 using HMAC-BLAKE2s. */
export function hkdf(ck: Uint8Array, ikm: Uint8Array, outputs: 2 | 3): Uint8Array[] {
  const tempKey = hmac(blake2s, ck, ikm);
  const o1 = hmac(blake2s, tempKey, Uint8Array.of(1));
  const o2 = hmac(blake2s, tempKey, concat(o1, Uint8Array.of(2)));
  if (outputs === 2) return [o1, o2];
  const o3 = hmac(blake2s, tempKey, concat(o2, Uint8Array.of(3)));
  return [o1, o2, o3];
}
