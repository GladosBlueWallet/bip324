import type { CipherSession } from "../crypto/session-keys.ts";

const LENGTH_FIELD_LEN = 3;
const HEADER_LEN = 1;
const IGNORE_BIT_POS = 7;

export type EncodePacketOpts = {
  aad?: Uint8Array;
  ignore?: boolean;
};

/** Encrypt a BIP-324 packet (length || AEAD(header||contents)). */
export function encodePacket(
  session: CipherSession,
  contents: Uint8Array,
  opts: EncodePacketOpts = {},
): Uint8Array {
  if (contents.length > 0xffffff) {
    throw new Error(`contents too large: ${contents.length}`);
  }
  const aad = opts.aad ?? new Uint8Array(0);
  const ignore = opts.ignore ?? false;
  const header = new Uint8Array(HEADER_LEN);
  header[0] = ignore ? 1 << IGNORE_BIT_POS : 0;
  const plaintext = new Uint8Array(HEADER_LEN + contents.length);
  plaintext.set(header, 0);
  plaintext.set(contents, HEADER_LEN);
  const aeadCiphertext = session.sendP.encrypt(aad, plaintext);
  const lenBytes = new Uint8Array(LENGTH_FIELD_LEN);
  lenBytes[0] = contents.length & 0xff;
  lenBytes[1] = (contents.length >>> 8) & 0xff;
  lenBytes[2] = (contents.length >>> 16) & 0xff;
  const encLen = session.sendL.encrypt(lenBytes);
  const out = new Uint8Array(encLen.length + aeadCiphertext.length);
  out.set(encLen, 0);
  out.set(aeadCiphertext, encLen.length);
  return out;
}
