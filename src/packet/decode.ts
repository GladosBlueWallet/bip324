import { destroySession, type CipherSession } from "../crypto/session-keys.ts";
import { AuthenticationError } from "../errors.ts";
import { readExactly, type ByteReader } from "../io/read-exactly.ts";

const LENGTH_FIELD_LEN = 3;
const HEADER_LEN = 1;
const IGNORE_BIT_POS = 7;
const CHACHA20POLY1305_EXPANSION = 16;

/**
 * Default cap on decrypted packet contents. Bitcoin Core rejects application
 * messages above `MAX_PROTOCOL_MESSAGE_LENGTH` (4_000_000); the extra 13
 * bytes cover the largest BIP-324 message-type prefix (long command form).
 * Without a cap, three length bytes could force a ~16 MiB allocation.
 */
export const MAX_CONTENTS_LEN = 4_000_013;

export type { ByteReader } from "../io/read-exactly.ts";

export type DecodePacketOpts = {
  aad?: Uint8Array;
  /** Override the contents-length cap (defaults to {@link MAX_CONTENTS_LEN}). */
  maxContentsLen?: number;
};

/**
 * Decrypt packets until a non-decoy contents buffer is returned.
 * Matches BIP reference `v2_receive_packet` (skips ignore-bit packets).
 */
export async function decodePacket(
  session: CipherSession,
  reader: ByteReader,
  opts: DecodePacketOpts = {},
): Promise<Uint8Array> {
  try {
    let aad = opts.aad ?? new Uint8Array(0);
    const maxContentsLen = opts.maxContentsLen ?? MAX_CONTENTS_LEN;
    for (;;) {
      const encLen = await readExactly(reader, LENGTH_FIELD_LEN);
      const lenBytes = session.recvL.decrypt(encLen);
      const contentsLen = lenBytes[0]! | (lenBytes[1]! << 8) | (lenBytes[2]! << 16);
      if (contentsLen > maxContentsLen) {
        throw new Error(
          `packet contents length ${contentsLen} exceeds max ${maxContentsLen}`,
        );
      }
      const aeadLen = HEADER_LEN + contentsLen + CHACHA20POLY1305_EXPANSION;
      const aeadCiphertext = await readExactly(reader, aeadLen);
      const plaintext = session.recvP.decrypt(aad, aeadCiphertext);
      if (plaintext === null) throw new AuthenticationError();
      aad = new Uint8Array(0);
      const header = plaintext[0]!;
      const contents = plaintext.slice(HEADER_LEN);
      if ((header & (1 << IGNORE_BIT_POS)) === 0) return contents;
    }
  } catch (error) {
    destroySession(session);
    throw error;
  }
}
