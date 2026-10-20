import { decrypt, encrypt } from "./primitives";

// 2^64-1 is reserved; we can only count to Number.MAX_SAFE_INTEGER, far beyond any session.
const MAX_NONCE = Number.MAX_SAFE_INTEGER;

export class CipherState {
  private k: Uint8Array | null = null;
  private n = 0;

  constructor(key?: Uint8Array) {
    if (key) this.initializeKey(key);
  }

  initializeKey(key: Uint8Array | null): void {
    this.k = key ? Uint8Array.from(key) : null;
    this.n = 0;
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  /** For tests/debugging only. */
  nonce(): number {
    return this.n;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) return plaintext;
    if (this.n >= MAX_NONCE) throw new Error("noise: nonce exhausted");
    const ct = encrypt(this.k, this.n, ad, plaintext);
    this.n++;
    return ct;
  }

  /** Nonce only advances on successful authentication (spec 5.1). */
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) return ciphertext;
    if (this.n >= MAX_NONCE) throw new Error("noise: nonce exhausted");
    const pt = decrypt(this.k, this.n, ad, ciphertext);
    this.n++;
    return pt;
  }

  /** Wipe key material (best effort in JS). */
  clear(): void {
    this.k?.fill(0);
    this.k = null;
  }
}
