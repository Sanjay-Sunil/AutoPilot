import { randomBytes } from "@noble/hashes/utils.js";
import type { Envelope } from "../../protocol/Envelope";
import { CipherState, generateKeyPair, HandshakeState, KeyPair } from "../../noise";
import { toBase64 } from "../../util/bytes";
import { confirmationCode } from "../confirm";
import { decodeEnvelope, encodeEnvelope, EnvelopeWriter } from "../envelope";
import { PROLOGUE, SecureSession, WebSocketLike } from "../session";

/** In-memory fake laptop that speaks the responder side over a fake WebSocket. */
class FakeLaptop implements WebSocketLike {
  binaryType = "blob";
  readyState = 0;
  onopen: WebSocketLike["onopen"] = null;
  onmessage: WebSocketLike["onmessage"] = null;
  onerror: WebSocketLike["onerror"] = null;
  onclose: WebSocketLike["onclose"] = null;
  hs: HandshakeState;
  tx: CipherState | null = null;
  rx: CipherState | null = null;
  received: Envelope[] = [];
  writer = new EnvelopeWriter(randomBytes);
  closedWith: string | null = null;
  code: string | null = null;

  constructor(public key: KeyPair) {
    this.hs = new HandshakeState({ initiator: false, prologue: PROLOGUE, s: key });
    this.writer.session = "11111111-2222-4333-8444-555555555555";
    setTimeout(() => this.onopen?.({}), 0);
  }

  send(data: ArrayBuffer): void {
    const b = new Uint8Array(data);
    if (!this.hs.isFinished()) {
      this.hs.readMessage(b);
      if (this.hs.isFinished()) {
        const t = this.hs.transport();
        this.tx = t.send;
        this.rx = t.recv;
        this.code = confirmationCode(t.handshakeHash);
      } else {
        const m2 = this.hs.writeMessage();
        setTimeout(() => this.onmessage?.({ data: m2.buffer }), 0);
      }
      return;
    }
    this.received.push(decodeEnvelope(this.rx!.decryptWithAd(new Uint8Array(0), b)));
  }

  push(env: Envelope): void {
    const ct = this.tx!.encryptWithAd(new Uint8Array(0), encodeEnvelope(env));
    this.onmessage?.({ data: ct.buffer });
  }

  close(_code?: number, reason?: string): void {
    this.closedWith = reason ?? "";
  }
}

const tick = () => new Promise((r) => setTimeout(r, 1));

describe("SecureSession", () => {
  it("handshakes, pins, claims, exchanges messages, reassembles frames", async () => {
    const laptopKey = generateKeyPair();
    const phoneKey = generateKeyPair();
    let laptop: FakeLaptop | null = null;
    const got: Envelope[] = [];
    const frames: string[] = [];
    let code = "";
    const s = new SecureSession(
      {
        urls: ["ws://dead/ws", "ws://ok/ws"],
        deviceKey: phoneKey,
        laptopPk: laptopKey.publicKey,
        claim: { token: "tok", device_name: "Pixel" },
        random: randomBytes,
        wsFactory: (url) => {
          if (url.includes("dead")) throw new Error("unreachable");
          laptop = new FakeLaptop(laptopKey);
          return laptop;
        },
      },
      { onMessage: (e) => got.push(e), onFrame: (f) => frames.push(f.jpegB64), onOpen: (i) => (code = i.code) },
    );
    await s.start();
    const l = laptop!;
    expect(l.binaryType).toBe("arraybuffer");
    expect(code).toBe(l.code);
    expect(l.received[0].type).toBe("pair.claim");
    expect(l.received[0].seq).toBe(1);

    l.push(l.writer.next({ type: "pair.result", payload: { ok: true, laptop_name: "lap", reason: null } }));
    expect(got[0].type).toBe("pair.result");
    expect(s.sessionId).toBe(l.writer.session);

    s.send({ type: "chat.user", payload: { text: "hi", voice: false } });
    expect(l.received[1]).toMatchObject({ type: "chat.user", seq: 2, session: l.writer.session });

    const b64 = toBase64(Uint8Array.from({ length: 30 }, (_, i) => i));
    l.push(l.writer.next({ type: "screen.frame", payload: { frame_id: 1, part: 1, parts: 2, width: 1, height: 1, data_b64: b64.slice(20) } }));
    l.push(l.writer.next({ type: "screen.frame", payload: { frame_id: 1, part: 0, parts: 2, width: 1, height: 1, data_b64: b64.slice(0, 20) } }));
    expect(frames).toEqual([b64]);
    s.close();
  });

  it("aborts when the laptop key does not match the pin", async () => {
    const laptopKey = generateKeyPair();
    const s = new SecureSession({
      urls: ["ws://a/ws", "ws://b/ws"],
      deviceKey: generateKeyPair(),
      laptopPk: generateKeyPair().publicKey,
      random: randomBytes,
      wsFactory: () => new FakeLaptop(laptopKey),
    });
    await expect(s.start()).rejects.toThrow(/does not match/);
  });

  it("closes on replayed message", async () => {
    const laptopKey = generateKeyPair();
    let laptop: FakeLaptop | null = null;
    let closed = "";
    const s = new SecureSession(
      {
        urls: ["ws://ok/ws"],
        deviceKey: generateKeyPair(),
        laptopPk: laptopKey.publicKey,
        random: randomBytes,
        wsFactory: () => (laptop = new FakeLaptop(laptopKey)),
      },
      { onClose: (r) => (closed = r) },
    );
    await s.start();
    const env = laptop!.writer.next({ type: "notify", payload: { level: "info", text: "x" } });
    laptop!.push(env);
    laptop!.push({ ...env });
    await tick();
    expect(closed).toMatch(/replayed/);
    expect(s.isOpen).toBe(false);
  });
});
