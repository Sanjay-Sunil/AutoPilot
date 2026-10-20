import type { Envelope } from "../protocol/Envelope";
import type { Message } from "../protocol/Message";
import type { PairClaim } from "../protocol/PairClaim";
import { CipherState, HandshakeState, KeyPair, sameKey } from "../noise";
import { utf8Encode } from "../util/bytes";
import { confirmationCode } from "./confirm";
import { decodeEnvelope, encodeEnvelope, EnvelopeWriter, SeqGuard } from "./envelope";
import { FrameAssembler, FullFrame } from "./frames";

export const PROLOGUE = utf8Encode("autopilot/1");
export const PING_INTERVAL_MS = 25_000;
export const SILENCE_TIMEOUT_MS = 60_000;
export const CONNECT_TIMEOUT_MS = 8_000;
/** After the handshake we ping at once; no reply within this window = dead session (relay goes silent). */
export const FIRST_REPLY_TIMEOUT_MS = 10_000;

/** The subset of the WebSocket API we use (RN global WebSocket satisfies it). */
export interface WebSocketLike {
  binaryType: string;
  readyState: number;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onclose: ((ev: { code?: number; reason?: string }) => void) | null;
  send(data: ArrayBuffer): void;
  close(code?: number, reason?: string): void;
}

export type WebSocketFactory = (url: string) => WebSocketLike;

export interface SessionHandlers {
  onOpen?(info: { url: string; code: string; handshakeHash: Uint8Array }): void;
  onMessage?(env: Envelope): void;
  onFrame?(frame: FullFrame): void;
  /** `code` is the WebSocket close code when the peer/relay closed us (e.g. relay 4000 = replaced by a newer phone). */
  onClose?(reason: string, wasOpen: boolean, code?: number): void;
}

export interface SessionOptions {
  urls: string[];
  deviceKey: KeyPair;
  /** Pinned laptop static key; handshake aborts if msg 2 carries a different key. */
  laptopPk: Uint8Array;
  /** Sent as the first transport message when pairing a new phone. */
  claim?: PairClaim;
  random: (n: number) => Uint8Array;
  wsFactory?: WebSocketFactory;
  connectTimeoutMs?: number;
  pingIntervalMs?: number;
  silenceTimeoutMs?: number;
  firstReplyTimeoutMs?: number;
  now?: () => number;
}

export class PinMismatchError extends Error {
  constructor() {
    super("Laptop key does not match the paired key");
  }
}

function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

function toBytes(data: unknown): Uint8Array | null {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return null; // text frames are not allowed
}

/**
 * One end-to-end encrypted session to the laptop. Tries each URL in order; the first one that
 * completes the Noise XX handshake with the pinned laptop key wins. No reconnect logic here —
 * see services/connection.ts.
 */
export class SecureSession {
  private ws: WebSocketLike | null = null;
  private send_: CipherState | null = null;
  private recv: CipherState | null = null;
  private readonly writer: EnvelopeWriter;
  private readonly guard = new SeqGuard();
  private readonly frames = new FrameAssembler();
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private firstReplyTimer: ReturnType<typeof setTimeout> | null = null;
  private lastRx = 0;
  private closed = false;
  private open_ = false;
  private readonly now: () => number;

  constructor(private readonly opts: SessionOptions, private readonly h: SessionHandlers = {}) {
    this.writer = new EnvelopeWriter(opts.random);
    this.now = opts.now ?? Date.now;
  }

  get isOpen(): boolean {
    return this.open_;
  }

  get sessionId(): string {
    return this.writer.session;
  }

  /** Resolves once the session is open; rejects if every candidate URL failed. */
  async start(): Promise<void> {
    let lastErr: unknown = new Error("no addresses to try");
    for (const url of this.opts.urls) {
      if (this.closed) throw new Error("closed");
      try {
        await this.attempt(url);
        return;
      } catch (e) {
        lastErr = e;
        if (e instanceof PinMismatchError) break; // never fall through to other routes on a MITM signal
      }
    }
    this.closed = true;
    throw lastErr;
  }

  send(msg: Message): void {
    if (!this.open_ || !this.ws || !this.send_) throw new Error("not connected");
    const pt = encodeEnvelope(this.writer.next(msg));
    this.ws.send(toArrayBuffer(this.send_.encryptWithAd(new Uint8Array(0), pt)));
  }

  close(reason = "closed by app"): void {
    if (this.closed && !this.ws) return;
    this.closed = true;
    this.teardown(reason);
  }

  private attempt(url: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const factory = this.opts.wsFactory ?? ((u: string) => new WebSocket(u) as unknown as WebSocketLike);
      let ws: WebSocketLike;
      try {
        ws = factory(url);
      } catch (e) {
        reject(e);
        return;
      }
      ws.binaryType = "arraybuffer";
      this.ws = ws;
      const hs = new HandshakeState({ initiator: true, prologue: PROLOGUE, s: this.opts.deviceKey });
      let settled = false;
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        detach();
        try {
          ws.close(1000, "handshake failed");
        } catch {
          /* ignore */
        }
        if (this.ws === ws) this.ws = null;
        reject(err);
      };
      const detach = () => {
        ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      };
      const timer = setTimeout(() => fail(new Error(`timeout connecting to ${url}`)), this.opts.connectTimeoutMs ?? CONNECT_TIMEOUT_MS);

      ws.onopen = () => {
        try {
          ws.send(toArrayBuffer(hs.writeMessage()));
        } catch (e) {
          fail(e as Error);
        }
      };
      ws.onerror = () => fail(new Error(`cannot reach ${url}`));
      ws.onclose = () => fail(new Error(`connection to ${url} closed during handshake`));
      ws.onmessage = (ev) => {
        const bytes = toBytes(ev.data);
        if (!bytes) return fail(new Error("unexpected text frame"));
        try {
          hs.readMessage(bytes); // msg 2: <- e, ee, s, es
          if (!sameKey(hs.remoteStatic(), this.opts.laptopPk)) throw new PinMismatchError();
          ws.send(toArrayBuffer(hs.writeMessage())); // msg 3: -> s, se
        } catch (e) {
          return fail(e instanceof Error ? e : new Error(String(e)));
        }
        settled = true;
        clearTimeout(timer);
        const t = hs.transport();
        this.send_ = t.send;
        this.recv = t.recv;
        this.open_ = true;
        this.lastRx = this.now();
        ws.onmessage = (m) => this.onFrame(m.data);
        ws.onerror = () => this.teardown("network error");
        ws.onclose = (c) => this.teardown(c.reason || `connection closed (${c.code ?? "?"})`, c.code);
        if (this.opts.claim) this.send({ type: "pair.claim", payload: this.opts.claim });
        // Paired laptops send nothing after the handshake: ping now to learn the session id and to
        // detect a session the laptop rejected (over the relay it just goes silent).
        this.send({ type: "ping", payload: { t_ms: this.now() } });
        this.firstReplyTimer = setTimeout(() => this.teardown("no reply from laptop after handshake"), this.opts.firstReplyTimeoutMs ?? FIRST_REPLY_TIMEOUT_MS);
        this.startPing();
        this.h.onOpen?.({ url, code: confirmationCode(t.handshakeHash), handshakeHash: t.handshakeHash });
        resolve();
      };
    });
  }

  private onFrame(data: unknown): void {
    const bytes = toBytes(data);
    if (!bytes || !this.recv) return this.teardown("protocol violation: text frame");
    let env: Envelope;
    try {
      env = decodeEnvelope(this.recv.decryptWithAd(new Uint8Array(0), bytes));
    } catch {
      return this.teardown("decryption or decode failure");
    }
    if (!this.guard.accept(env.seq)) return this.teardown("replayed message");
    this.lastRx = this.now();
    this.clearFirstReply();
    if (this.writer.session !== env.session && /^[0-9a-f-]{36}$/i.test(env.session)) this.writer.session = env.session;
    if (env.type === "pong") return;
    if (env.type === "screen.frame") {
      const full = this.frames.push(env.payload);
      if (full) this.h.onFrame?.(full);
      return;
    }
    this.h.onMessage?.(env);
  }

  private clearFirstReply(): void {
    if (this.firstReplyTimer) clearTimeout(this.firstReplyTimer);
    this.firstReplyTimer = null;
  }

  private startPing(): void {
    this.pingTimer = setInterval(() => {
      if (this.now() - this.lastRx > (this.opts.silenceTimeoutMs ?? SILENCE_TIMEOUT_MS)) {
        this.teardown("laptop silent for too long");
        return;
      }
      try {
        this.send({ type: "ping", payload: { t_ms: this.now() } });
      } catch {
        this.teardown("send failed");
      }
    }, this.opts.pingIntervalMs ?? PING_INTERVAL_MS);
  }

  private teardown(reason: string, code?: number): void {
    const wasOpen = this.open_;
    this.open_ = false;
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    this.clearFirstReply();
    const ws = this.ws;
    this.ws = null;
    if (ws && !wasOpen && ws.onclose) {
      // Abort an in-flight handshake attempt so start() settles.
      ws.onclose({ reason });
      return;
    }
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      try {
        ws.close(1000, reason);
      } catch {
        /* ignore */
      }
    }
    this.send_?.clear();
    this.recv?.clear();
    this.send_ = this.recv = null;
    this.frames.reset();
    if (wasOpen || this.closed) {
      this.closed = true;
      this.h.onClose?.(reason, wasOpen, code);
    }
  }
}
