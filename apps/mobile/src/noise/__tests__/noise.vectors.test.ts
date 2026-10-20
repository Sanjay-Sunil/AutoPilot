import { fromHex, toHex } from "../../util/bytes";
import { CipherState } from "../cipherState";
import { HandshakeState, PROTOCOL_NAME } from "../handshakeState";
import { keyPairFromPrivate, nonceBytes } from "../primitives";
import fixture from "./fixtures/xx_25519_chachapoly_blake2s.json";

interface Vector {
  protocol_name: string;
  source: string;
  init_prologue: string;
  init_static: string;
  init_ephemeral: string;
  resp_prologue: string;
  resp_static: string;
  resp_ephemeral: string;
  handshake_hash?: string;
  messages: { payload: string; ciphertext: string }[];
}

const vectors = (fixture as { vectors: Vector[] }).vectors;

describe("Noise XX test vectors", () => {
  it("has XX vectors from cacophony and snow", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(2);
    for (const v of vectors) expect(v.protocol_name).toBe(PROTOCOL_NAME);
  });

  it.each(vectors.map((v) => [v.source, v] as const))("%s", (_src, v) => {
    const init = new HandshakeState({
      initiator: true,
      prologue: fromHex(v.init_prologue),
      s: keyPairFromPrivate(fromHex(v.init_static)),
      e: keyPairFromPrivate(fromHex(v.init_ephemeral)),
    });
    const resp = new HandshakeState({
      initiator: false,
      prologue: fromHex(v.resp_prologue),
      s: keyPairFromPrivate(fromHex(v.resp_static)),
      e: keyPairFromPrivate(fromHex(v.resp_ephemeral)),
    });

    let iSend: CipherState | null = null;
    let iRecv: CipherState | null = null;
    let rSend: CipherState | null = null;
    let rRecv: CipherState | null = null;

    v.messages.forEach((m, idx) => {
      const fromInit = idx % 2 === 0;
      const payload = fromHex(m.payload);
      let ct: Uint8Array;
      let pt: Uint8Array;
      if (idx < 3) {
        const [w, r] = fromInit ? [init, resp] : [resp, init];
        ct = w.writeMessage(payload);
        expect(toHex(ct)).toBe(m.ciphertext);
        pt = r.readMessage(ct);
        if (idx === 2) {
          expect(init.isFinished()).toBe(true);
          expect(resp.isFinished()).toBe(true);
          const ih = init.transport();
          const rh = resp.transport();
          expect(toHex(ih.handshakeHash)).toBe(toHex(rh.handshakeHash));
          if (v.handshake_hash) expect(toHex(ih.handshakeHash)).toBe(v.handshake_hash);
          expect(toHex(ih.remoteStatic)).toBe(toHex(keyPairFromPrivate(fromHex(v.resp_static)).publicKey));
          expect(toHex(rh.remoteStatic)).toBe(toHex(keyPairFromPrivate(fromHex(v.init_static)).publicKey));
          iSend = ih.send;
          iRecv = ih.recv;
          rSend = rh.send;
          rRecv = rh.recv;
        }
      } else {
        const w = (fromInit ? iSend : rSend)!;
        const r = (fromInit ? rRecv : iRecv)!;
        ct = w.encryptWithAd(new Uint8Array(0), payload);
        expect(toHex(ct)).toBe(m.ciphertext);
        pt = r.decryptWithAd(new Uint8Array(0), ct);
      }
      expect(toHex(pt)).toBe(m.payload);
    });
  });
});

describe("Noise details", () => {
  it("formats nonces as 4 zero bytes + LE u64", () => {
    expect(toHex(nonceBytes(0))).toBe("000000000000000000000000");
    expect(toHex(nonceBytes(1))).toBe("000000000100000000000000");
    expect(toHex(nonceBytes(0x0102030405))).toBe("000000000504030201000000");
  });

  it("rejects tampered ciphertext without advancing the nonce", () => {
    const cs = new CipherState(new Uint8Array(32).fill(7));
    const rx = new CipherState(new Uint8Array(32).fill(7));
    const ct = cs.encryptWithAd(new Uint8Array(0), Uint8Array.of(1, 2, 3));
    const bad = Uint8Array.from(ct);
    bad[0] ^= 1;
    expect(() => rx.decryptWithAd(new Uint8Array(0), bad)).toThrow();
    expect(rx.nonce()).toBe(0);
    expect(Array.from(rx.decryptWithAd(new Uint8Array(0), ct))).toEqual([1, 2, 3]);
  });

  it("fails the handshake when keys mismatch prologue", () => {
    const a = new HandshakeState({ initiator: true, prologue: Uint8Array.of(1), s: keyPairFromPrivate(new Uint8Array(32).fill(1)) });
    const b = new HandshakeState({ initiator: false, prologue: Uint8Array.of(2), s: keyPairFromPrivate(new Uint8Array(32).fill(2)) });
    b.readMessage(a.writeMessage());
    const m2 = b.writeMessage();
    expect(() => a.readMessage(m2)).toThrow();
  });
});
