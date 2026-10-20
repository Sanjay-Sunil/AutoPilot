import { concat, utf8Encode } from "../util/bytes";
import { CipherState } from "./cipherState";
import { hash, HASHLEN, hkdf } from "./primitives";

export class SymmetricState {
  readonly cs = new CipherState();
  private ck: Uint8Array;
  private h: Uint8Array;

  constructor(protocolName: string) {
    const name = utf8Encode(protocolName);
    if (name.length <= HASHLEN) {
      this.h = new Uint8Array(HASHLEN);
      this.h.set(name);
    } else {
      this.h = hash(name);
    }
    this.ck = Uint8Array.from(this.h);
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, tempK] = hkdf(this.ck, ikm, 2);
    this.ck = ck;
    this.cs.initializeKey(tempK);
  }

  mixHash(data: Uint8Array): void {
    this.h = hash(concat(this.h, data));
  }

  getHandshakeHash(): Uint8Array {
    return Uint8Array.from(this.h);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ct = this.cs.encryptWithAd(this.h, plaintext);
    this.mixHash(ct);
    return ct;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const pt = this.cs.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return pt;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0), 2);
    this.ck.fill(0);
    return [new CipherState(k1), new CipherState(k2)];
  }
}
