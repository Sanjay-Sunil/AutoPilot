import { blake2s } from "@noble/hashes/blake2.js";
import { fromBase64, toBase64, toBase64Url, toHex, utf8Decode, utf8Encode } from "../../util/bytes";
import { backoffMs } from "../backoff";
import { confirmationCode, relayRoom } from "../confirm";
import { decodeEnvelope, encodeEnvelope, EnvelopeWriter, ProtocolError, SeqGuard } from "../envelope";
import { FrameAssembler } from "../frames";
import { candidateUrls, parsePairingUri, QrError } from "../qr";

let ctr = 0;
const rand = (n: number) => Uint8Array.from({ length: n }, () => ctr++ & 0xff);

describe("confirmation code", () => {
  it("follows u32_be(blake2s(h)[0..4]) % 1e6", () => {
    const h = new Uint8Array(32).fill(0xab);
    const d = blake2s(h);
    const n = ((d[0] * 2 ** 24) + (d[1] << 16) + (d[2] << 8) + d[3]) % 1_000_000;
    expect(confirmationCode(h)).toBe(String(n).padStart(6, "0"));
    expect(confirmationCode(h)).toMatch(/^\d{6}$/);
  });

  it("zero pads", () => {
    // Search for an input whose code begins with 0 to exercise padding.
    for (let i = 0; i < 5000; i++) {
      const c = confirmationCode(Uint8Array.of(i & 0xff, i >> 8));
      expect(c).toHaveLength(6);
    }
  });

  it("room is 32 hex chars of blake2s(pk)", () => {
    const pk = new Uint8Array(32).fill(9);
    expect(relayRoom(pk)).toBe(toHex(blake2s(pk)).slice(0, 32));
    expect(relayRoom(pk)).toHaveLength(32);
  });
});

describe("envelope", () => {
  it("round-trips and increments seq from 1", () => {
    const w = new EnvelopeWriter(rand);
    const a = w.next({ type: "chat.user", payload: { text: "héllo 🌍", voice: false } });
    const b = w.next({ type: "ping", payload: { t_ms: 5 } });
    expect(a.seq).toBe(1);
    expect(b.seq).toBe(2);
    expect(a.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const back = decodeEnvelope(encodeEnvelope(a));
    expect(back).toEqual(a);
  });

  it("rejects malformed envelopes", () => {
    expect(() => decodeEnvelope(utf8Encode("nope"))).toThrow(ProtocolError);
    expect(() => decodeEnvelope(utf8Encode(JSON.stringify({ v: 2, seq: 1 })))).toThrow(ProtocolError);
    expect(() =>
      decodeEnvelope(utf8Encode(JSON.stringify({ v: 1, id: "x", session: "y", seq: 0, type: "ping", payload: {} }))),
    ).toThrow(ProtocolError);
  });

  it("refuses oversized plaintext", () => {
    const w = new EnvelopeWriter(rand);
    expect(() => encodeEnvelope(w.next({ type: "chat.user", payload: { text: "x".repeat(70_000), voice: false } }))).toThrow();
  });

  it("seq guard drops replays and reorders", () => {
    const g = new SeqGuard();
    expect(g.accept(1)).toBe(true);
    expect(g.accept(2)).toBe(true);
    expect(g.accept(2)).toBe(false);
    expect(g.accept(1)).toBe(false);
    expect(g.accept(10)).toBe(true);
    expect(g.accept(9)).toBe(false);
    expect(g.accept(1.5)).toBe(false);
  });
});

describe("pairing QR", () => {
  const qr = {
    v: 1,
    addrs: ["192.168.1.20:7878"],
    relay: "wss://relay.example.com/relay",
    laptop_pk: toBase64Url(new Uint8Array(32).fill(3)),
    laptop_name: "zx-laptop",
    token: "tok_abc",
    expires_at_ms: 2_000_000_000_000,
  };
  const uri = "autopilot://pair?d=" + toBase64Url(utf8Encode(JSON.stringify(qr)));

  it("parses a valid URI", () => {
    expect(parsePairingUri(uri, 1)).toEqual(qr);
  });

  it("rejects bad input", () => {
    expect(() => parsePairingUri("https://evil", 1)).toThrow(QrError);
    expect(() => parsePairingUri("autopilot://pair?d=!!!", 1)).toThrow(QrError);
    expect(() => parsePairingUri(uri, 3_000_000_000_000)).toThrow(/expired/);
    const bad = { ...qr, laptop_pk: toBase64Url(new Uint8Array(31)) };
    expect(() => parsePairingUri("autopilot://pair?d=" + toBase64Url(utf8Encode(JSON.stringify(bad))), 1)).toThrow(/key/);
  });

  it("orders candidate urls direct first, then relay", () => {
    expect(candidateUrls(qr.addrs, qr.relay, "ab".repeat(16))).toEqual([
      "ws://192.168.1.20:7878/ws",
      `wss://relay.example.com/relay/${"ab".repeat(16)}?role=phone`,
    ]);
  });
});

describe("frame reassembly", () => {
  const jpeg = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7) & 0xff);
  const split = (bytes: Uint8Array, size: number) => {
    const out: string[] = [];
    for (let i = 0; i < bytes.length; i += size) out.push(toBase64(bytes.subarray(i, i + size)));
    return out;
  };
  const frame = (id: number, parts: string[], i: number) => ({
    frame_id: id, part: i, parts: parts.length, width: 10, height: 5, data_b64: parts[i],
  });

  it("reassembles out-of-order parts (aligned split)", () => {
    const parts = split(jpeg, 300);
    const fa = new FrameAssembler();
    expect(fa.push(frame(1, parts, 2))).toBeNull();
    expect(fa.push(frame(1, parts, 0))).toBeNull();
    expect(fa.push(frame(1, parts, 3))).toBeNull();
    const done = fa.push(frame(1, parts, 1));
    expect(done && toHex(fromBase64(done.jpegB64))).toBe(toHex(jpeg));
  });

  it("reassembles unaligned split with padding", () => {
    const parts = split(jpeg, 333 + 1);
    const fa = new FrameAssembler();
    let done: ReturnType<FrameAssembler["push"]> = null;
    parts.forEach((_, i) => (done = fa.push(frame(4, parts, i)) ?? done));
    expect(done).not.toBeNull();
    expect(toHex(fromBase64(done!.jpegB64))).toBe(toHex(jpeg));
  });

  it("drops stale frames when a newer one starts", () => {
    const parts = split(jpeg, 500);
    const fa = new FrameAssembler();
    fa.push(frame(1, parts, 0));
    fa.push(frame(2, parts, 0));
    expect(fa.push(frame(1, parts, 1))).toBeNull();
    expect(fa.push(frame(2, parts, 1))?.frameId).toBe(2);
    expect(fa.push(frame(2, parts, 1))).toBeNull();
  });

  it("single-part frame", () => {
    const fa = new FrameAssembler();
    expect(fa.push({ frame_id: 0, part: 0, parts: 1, width: 1, height: 1, data_b64: "AAEC" })?.jpegB64).toBe("AAEC");
  });
});

describe("bytes", () => {
  it("utf8 + base64 roundtrip", () => {
    const s = "AutoPilot ✈️ ünïcode";
    expect(utf8Decode(utf8Encode(s))).toBe(s);
    expect(Buffer.from(utf8Encode(s)).toString("utf8")).toBe(s);
    const b = Uint8Array.from({ length: 257 }, (_, i) => i & 0xff);
    expect(toBase64(b)).toBe(Buffer.from(b).toString("base64"));
    expect(toBase64Url(b)).toBe(Buffer.from(b).toString("base64url"));
    expect(toHex(fromBase64(toBase64Url(b)))).toBe(toHex(b));
  });

  it("backoff is bounded", () => {
    expect(backoffMs(0, () => 0)).toBe(250);
    expect(backoffMs(50, () => 1)).toBe(30_000);
  });
});
