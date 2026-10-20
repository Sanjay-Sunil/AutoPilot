import type { Envelope } from "../protocol/Envelope";
import type { Message } from "../protocol/Message";
import { utf8Decode, utf8Encode } from "../util/bytes";

export const NIL_UUID = "00000000-0000-0000-0000-000000000000";
export const MAX_PLAINTEXT = 65_519;

export function uuidv4(rand: (n: number) => Uint8Array): string {
  const b = rand(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Produces outbound envelopes with a strictly increasing seq starting at 1. */
export class EnvelopeWriter {
  private seq = 0;
  session = NIL_UUID;

  constructor(private readonly rand: (n: number) => Uint8Array) {}

  next(msg: Message): Envelope {
    this.seq += 1;
    return { v: 1, id: uuidv4(this.rand), session: this.session, seq: this.seq, ...msg } as Envelope;
  }

  lastSeq(): number {
    return this.seq;
  }
}

export function encodeEnvelope(env: Envelope): Uint8Array {
  const bytes = utf8Encode(JSON.stringify(env));
  if (bytes.length > MAX_PLAINTEXT) throw new Error(`envelope too large (${bytes.length} bytes)`);
  return bytes;
}

export class ProtocolError extends Error {}

export function decodeEnvelope(bytes: Uint8Array): Envelope {
  let v: unknown;
  try {
    v = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new ProtocolError("invalid JSON");
  }
  const e = v as Partial<Envelope>;
  if (!e || typeof e !== "object") throw new ProtocolError("not an object");
  if (e.v !== 1) throw new ProtocolError("unsupported version");
  if (typeof e.seq !== "number" || !Number.isSafeInteger(e.seq) || e.seq < 1) throw new ProtocolError("bad seq");
  if (typeof e.type !== "string" || typeof e.id !== "string" || typeof e.session !== "string") {
    throw new ProtocolError("missing fields");
  }
  if (typeof e.payload !== "object" || e.payload === null) throw new ProtocolError("missing payload");
  return e as Envelope;
}

/** Rejects replayed or reordered envelopes: seq must strictly increase. */
export class SeqGuard {
  private last = 0;

  /** Returns true if accepted. A false return means the session must be closed. */
  accept(seq: number): boolean {
    if (!Number.isSafeInteger(seq) || seq <= this.last) return false;
    this.last = seq;
    return true;
  }

  reset(): void {
    this.last = 0;
  }
}
