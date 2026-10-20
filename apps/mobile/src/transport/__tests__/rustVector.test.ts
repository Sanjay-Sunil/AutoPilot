/**
 * Cross-implementation check against the Rust transport's vector
 * (crates/agent-transport/tests/vectors/xx_vector.json). Skips if the file is absent.
 */
import * as fs from "fs";
import * as path from "path";
import { HandshakeState, keyPairFromPrivate } from "../../noise";
import { fromBase64, fromHex, toBase64Url, toHex, utf8Decode, utf8Encode } from "../../util/bytes";
import { confirmationCode, relayRoom } from "../confirm";
import { decodeEnvelope } from "../envelope";
import { parsePairingUri } from "../qr";
import { PROLOGUE } from "../session";

const file = path.resolve(__dirname, "../../../../../crates/agent-transport/tests/vectors/xx_vector.json");
const exists = fs.existsSync(file);
const d = exists ? JSON.parse(fs.readFileSync(file, "utf8")) : null;

(exists ? describe : describe.skip)("Rust xx_vector.json interop", () => {
  it("uses the same prologue", () => {
    expect(toHex(PROLOGUE)).toBe(d.prologue_hex);
  });

  it("reproduces handshake, hash, code, room and transport ciphertexts", () => {
    const phoneS = keyPairFromPrivate(fromHex(d.initiator.static_private_hex));
    const laptopS = keyPairFromPrivate(fromHex(d.responder.static_private_hex));
    expect(toHex(phoneS.publicKey)).toBe(d.initiator.static_public_hex);
    expect(toBase64Url(laptopS.publicKey)).toBe(d.responder.static_public_b64url);

    const phone = new HandshakeState({ initiator: true, prologue: PROLOGUE, s: phoneS, e: keyPairFromPrivate(fromHex(d.initiator.ephemeral_private_hex)) });
    const laptop = new HandshakeState({ initiator: false, prologue: PROLOGUE, s: laptopS, e: keyPairFromPrivate(fromHex(d.responder.ephemeral_private_hex)) });
    for (const m of d.handshake as { from: string; message_hex: string; payload_hex: string }[]) {
      const [w, r] = m.from === "initiator" ? [phone, laptop] : [laptop, phone];
      const ct = w.writeMessage(fromHex(m.payload_hex));
      expect(toHex(ct)).toBe(m.message_hex);
      expect(toHex(r.readMessage(ct))).toBe(m.payload_hex);
    }
    const p = phone.transport();
    const l = laptop.transport();
    expect(toHex(p.handshakeHash)).toBe(d.handshake_hash_hex);
    expect(confirmationCode(p.handshakeHash)).toBe(d.confirmation_code);
    expect(relayRoom(laptopS.publicKey)).toBe(d.relay_room);
    expect(toHex(p.remoteStatic)).toBe(d.responder.static_public_hex);

    for (const t of d.transport as { from: string; plaintext_utf8: string; ciphertext_hex: string }[]) {
      const [w, r] = t.from === "initiator" ? [p.send, l.recv] : [l.send, p.recv];
      const ct = w.encryptWithAd(new Uint8Array(0), utf8Encode(t.plaintext_utf8));
      expect(toHex(ct)).toBe(t.ciphertext_hex);
      const pt = r.decryptWithAd(new Uint8Array(0), ct);
      expect(utf8Decode(pt)).toBe(t.plaintext_utf8);
      expect(decodeEnvelope(pt).seq).toBe(1);
    }
  });

  it("parses the Rust-generated pairing URI", () => {
    const qr = parsePairingUri(d.pairing_qr.uri, 0);
    expect(qr).toEqual(d.pairing_qr.json);
    expect(toHex(fromBase64(qr.laptop_pk))).toBe(d.responder.static_public_hex);
  });
});
