import { concatBytes, equalBytes } from "../crypto/bytes.ts";
import { ellswiftCreate } from "../crypto/ellswift.ts";
import type { CipherSession } from "../crypto/session-keys.ts";
import { deriveSessionKeys, destroySession } from "../crypto/session-keys.ts";
import { v2Ecdh } from "../crypto/v2-ecdh.ts";
import { utf8ToBytes } from "../crypto/utf8.ts";
import type { ByteDuplex } from "../io/byte-duplex.ts";
import { readExactly } from "../io/read-exactly.ts";
import type { Network } from "../networks/networks.ts";
import { decodePacket } from "../packet/decode.ts";
import { encodePacket } from "../packet/encode.ts";

export type Role = "initiator" | "responder";

export type V2HandshakeResult = {
  transport: "v2";
  session: CipherSession;
  role: Role;
};

export type V1HandshakeResult = {
  transport: "v1";
  /** Bytes already consumed from the stream; prepend these for a v1 parser. */
  buffered: Uint8Array;
};

export type HandshakeResult = V2HandshakeResult | V1HandshakeResult;

export type HandshakeOptions = {
  role: Role;
  network: Network;
  garbage?: Uint8Array;
  /** Injectable only to support deterministic transcript/interoperability tests. */
  createKeyPair?: typeof ellswiftCreate;
};

const MAX_GARBAGE = 4095;

function v1Prefix(magic: Uint8Array): Uint8Array {
  const cmd = utf8ToBytes("version");
  const padded = new Uint8Array(12);
  padded.set(cmd);
  return concatBytes(magic, padded);
}

async function readUntilTerminator(
  duplex: ByteDuplex,
  terminator: Uint8Array,
): Promise<Uint8Array> {
  let buf = new Uint8Array(0);
  while (buf.length < terminator.length) {
    buf = new Uint8Array(concatBytes(buf, await readExactly(duplex, 1)));
  }
  for (let i = 0; i < MAX_GARBAGE + 1; i++) {
    if (equalBytes(buf.subarray(buf.length - terminator.length), terminator)) {
      return new Uint8Array(buf.subarray(0, buf.length - terminator.length));
    }
    buf = new Uint8Array(concatBytes(buf, await readExactly(duplex, 1)));
  }
  throw new Error("garbage terminator not found");
}

/**
 * Complete BIP-324 handshake over a duplex.
 * Negotiates empty transport version packets after key exchange.
 */
export async function performHandshake(
  duplex: ByteDuplex,
  opts: HandshakeOptions,
): Promise<HandshakeResult> {
  const garbage = opts.garbage ?? new Uint8Array(0);
  if (garbage.length > MAX_GARBAGE) throw new Error("garbage too long");

  if (opts.role === "initiator") {
    return initiatorHandshake(duplex, opts.network, garbage, opts.createKeyPair);
  }
  return responderHandshake(duplex, opts.network, garbage, opts.createKeyPair);
}

async function initiatorHandshake(
  duplex: ByteDuplex,
  network: Network,
  sentGarbage: Uint8Array,
  createKeyPair: typeof ellswiftCreate = ellswiftCreate,
): Promise<V2HandshakeResult> {
  const { privateKey, publicKey } = createKeyPair();
  let ecdh: Uint8Array | undefined;
  let session: CipherSession | undefined;
  try {
    await duplex.write(concatBytes(publicKey, sentGarbage));

    const ellswiftTheirs = await readExactly(duplex, 64);
    ecdh = v2Ecdh(privateKey, ellswiftTheirs, publicKey, true);
    session = deriveSessionKeys(ecdh, network.magic, true);
    ecdh.fill(0);
    ecdh = undefined;

    await duplex.write(session.sendGarbageTerminator);
    await duplex.write(encodePacket(session, new Uint8Array(0), { aad: sentGarbage }));

    const receivedGarbage = await readUntilTerminator(duplex, session.recvGarbageTerminator);
    await decodePacket(session, duplex, { aad: receivedGarbage });
    return { transport: "v2", session, role: "initiator" };
  } catch (error) {
    if (session) destroySession(session);
    throw error;
  } finally {
    ecdh?.fill(0);
    privateKey.fill(0);
  }
}

async function responderHandshake(
  duplex: ByteDuplex,
  network: Network,
  sentGarbage: Uint8Array,
  createKeyPair: typeof ellswiftCreate = ellswiftCreate,
): Promise<HandshakeResult> {
  const prefixWanted = v1Prefix(network.magic);
  let receivedPrefix = new Uint8Array(0);
  while (receivedPrefix.length < prefixWanted.length) {
    const b = await readExactly(duplex, 1);
    receivedPrefix = new Uint8Array(concatBytes(receivedPrefix, b));
    if (receivedPrefix[receivedPrefix.length - 1] !== prefixWanted[receivedPrefix.length - 1]) {
      break;
    }
  }
  if (receivedPrefix.length === prefixWanted.length && equalBytes(receivedPrefix, prefixWanted)) {
    return { transport: "v1", buffered: receivedPrefix };
  }

  // BIP-324 requires the responder to answer as soon as v2 is distinguishable
  // from the local network's v1 prefix, before waiting for the remainder.
  const { privateKey, publicKey } = createKeyPair();
  let ecdh: Uint8Array | undefined;
  let session: CipherSession | undefined;

  // Finish receiving initiator ellswift public key (64 bytes total)
  try {
    await duplex.write(concatBytes(publicKey, sentGarbage));
    const remaining = 64 - receivedPrefix.length;
    const rest = remaining > 0 ? await readExactly(duplex, remaining) : new Uint8Array(0);
    const ellswiftTheirs = concatBytes(receivedPrefix, rest);
    if (ellswiftTheirs.length !== 64) throw new Error("incomplete ellswift key");

    const versionPad = new Uint8Array(12);
    versionPad.set(utf8ToBytes("version"));
    if (equalBytes(ellswiftTheirs.subarray(4, 16), versionPad)) {
      throw new Error("peer appears to be v1 on a different network");
    }

    ecdh = v2Ecdh(privateKey, ellswiftTheirs, publicKey, false);
    session = deriveSessionKeys(ecdh, network.magic, false);
    ecdh.fill(0);
    ecdh = undefined;

    await duplex.write(session.sendGarbageTerminator);
    await duplex.write(encodePacket(session, new Uint8Array(0), { aad: sentGarbage }));

    const receivedGarbage = await readUntilTerminator(duplex, session.recvGarbageTerminator);
    await decodePacket(session, duplex, { aad: receivedGarbage });
    return { transport: "v2", session, role: "responder" };
  } catch (error) {
    if (session) destroySession(session);
    throw error;
  } finally {
    ecdh?.fill(0);
    privateKey.fill(0);
  }
}
