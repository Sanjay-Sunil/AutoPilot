import { concat, equalBytes } from "../util/bytes";
import { CipherState } from "./cipherState";
import { dh, DHLEN, generateKeyPair, KeyPair, MAX_MESSAGE, TAGLEN } from "./primitives";
import { SymmetricState } from "./symmetricState";

export const PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

type Token = "e" | "s" | "ee" | "es" | "se" | "ss";

/** XX: -> e ; <- e, ee, s, es ; -> s, se */
const XX: Token[][] = [["e"], ["e", "ee", "s", "es"], ["s", "se"]];

export interface HandshakeOptions {
  initiator: boolean;
  prologue: Uint8Array;
  s: KeyPair;
  /** Fixed ephemeral, for test vectors only. */
  e?: KeyPair;
}

export interface TransportPair {
  send: CipherState;
  recv: CipherState;
  handshakeHash: Uint8Array;
  remoteStatic: Uint8Array;
}

export class HandshakeState {
  private ss: SymmetricState;
  private readonly initiator: boolean;
  private readonly s: KeyPair;
  private e: KeyPair | null;
  private rs: Uint8Array | null = null;
  private re: Uint8Array | null = null;
  private msgIndex = 0;
  private result: TransportPair | null = null;

  constructor(opts: HandshakeOptions) {
    this.initiator = opts.initiator;
    this.s = opts.s;
    this.e = opts.e ?? null;
    this.ss = new SymmetricState(PROTOCOL_NAME);
    this.ss.mixHash(opts.prologue);
  }

  isFinished(): boolean {
    return this.result !== null;
  }

  /** True when it is our turn to write. */
  isMyTurn(): boolean {
    return (this.msgIndex % 2 === 0) === this.initiator;
  }

  remoteStatic(): Uint8Array | null {
    return this.rs ? Uint8Array.from(this.rs) : null;
  }

  handshakeHash(): Uint8Array {
    return this.ss.getHandshakeHash();
  }

  transport(): TransportPair {
    if (!this.result) throw new Error("noise: handshake not finished");
    return this.result;
  }

  writeMessage(payload: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (this.result || this.msgIndex >= XX.length) throw new Error("noise: handshake already finished");
    if (!this.isMyTurn()) throw new Error("noise: not our turn to write");
    const parts: Uint8Array[] = [];
    for (const t of XX[this.msgIndex]) {
      switch (t) {
        case "e": {
          if (!this.e) this.e = generateKeyPair();
          parts.push(this.e.publicKey);
          this.ss.mixHash(this.e.publicKey);
          break;
        }
        case "s":
          parts.push(this.ss.encryptAndHash(this.s.publicKey));
          break;
        default:
          this.mixDh(t);
      }
    }
    parts.push(this.ss.encryptAndHash(payload));
    const msg = concat(...parts);
    if (msg.length > MAX_MESSAGE) throw new Error("noise: message too long");
    this.advance();
    return msg;
  }

  readMessage(message: Uint8Array): Uint8Array {
    if (this.result || this.msgIndex >= XX.length) throw new Error("noise: handshake already finished");
    if (this.isMyTurn()) throw new Error("noise: not our turn to read");
    if (message.length > MAX_MESSAGE) throw new Error("noise: message too long");
    let off = 0;
    const take = (n: number): Uint8Array => {
      if (off + n > message.length) throw new Error("noise: message too short");
      const out = message.subarray(off, off + n);
      off += n;
      return out;
    };
    for (const t of XX[this.msgIndex]) {
      switch (t) {
        case "e": {
          this.re = Uint8Array.from(take(DHLEN));
          this.ss.mixHash(this.re);
          break;
        }
        case "s": {
          const len = this.ss.cs.hasKey() ? DHLEN + TAGLEN : DHLEN;
          this.rs = Uint8Array.from(this.ss.decryptAndHash(take(len)));
          break;
        }
        default:
          this.mixDh(t);
      }
    }
    const payload = this.ss.decryptAndHash(message.subarray(off));
    this.advance();
    return payload;
  }

  private mixDh(t: Token): void {
    const need = (v: KeyPair | Uint8Array | null, what: string) => {
      if (!v) throw new Error(`noise: missing ${what}`);
      return v;
    };
    // Tokens name (initiator key, responder key).
    const local = (c: "e" | "s"): KeyPair => (c === "e" ? (need(this.e, "e") as KeyPair) : this.s);
    const remote = (c: "e" | "s"): Uint8Array => (c === "e" ? (need(this.re, "re") as Uint8Array) : (need(this.rs, "rs") as Uint8Array));
    const [i, r] = [t[0] as "e" | "s", t[1] as "e" | "s"];
    const out = this.initiator ? dh(local(i), remote(r)) : dh(local(r), remote(i));
    this.ss.mixKey(out);
  }

  private advance(): void {
    this.msgIndex++;
    if (this.msgIndex === XX.length) {
      const [c1, c2] = this.ss.split();
      const rs = this.rs;
      if (!rs) throw new Error("noise: no remote static after handshake");
      this.result = {
        send: this.initiator ? c1 : c2,
        recv: this.initiator ? c2 : c1,
        handshakeHash: this.ss.getHandshakeHash(),
        remoteStatic: Uint8Array.from(rs),
      };
      this.e?.privateKey.fill(0);
    }
  }
}

/** Constant-time pin check helper. */
export function sameKey(a: Uint8Array | null, b: Uint8Array): boolean {
  return a !== null && equalBytes(a, b);
}
