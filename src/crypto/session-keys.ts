import { concatBytes } from "./bytes.ts";
import { FSChaCha20 } from "./fs-chacha20.ts";
import { FSChaCha20Poly1305 } from "./fs-chacha20-poly1305.ts";
import { hkdfSha256 } from "./hash.ts";
import { utf8ToBytes } from "./utf8.ts";

export type SessionKeyMaterial = {
  sessionId: Uint8Array;
  initiatorL: Uint8Array;
  initiatorP: Uint8Array;
  responderL: Uint8Array;
  responderP: Uint8Array;
  initiatorGarbageTerminator: Uint8Array;
  responderGarbageTerminator: Uint8Array;
};

export type CipherSession = {
  sessionId: Uint8Array;
  sendL: FSChaCha20;
  sendP: FSChaCha20Poly1305;
  recvL: FSChaCha20;
  recvP: FSChaCha20Poly1305;
  sendGarbageTerminator: Uint8Array;
  recvGarbageTerminator: Uint8Array;
};

/** Derive BIP-324 transport keys from ECDH secret and network magic. */
export function deriveSessionKeys(
  ecdhSecret: Uint8Array,
  networkMagic: Uint8Array,
  initiating: boolean,
): CipherSession {
  const salt = concatBytes(utf8ToBytes("bitcoin_v2_shared_secret"), networkMagic);
  const expand = (info: string, length: number) => hkdfSha256(ecdhSecret, salt, info, length);

  const initiatorL = expand("initiator_L", 32);
  const initiatorP = expand("initiator_P", 32);
  const responderL = expand("responder_L", 32);
  const responderP = expand("responder_P", 32);
  const garbageTerminators = expand("garbage_terminators", 32);
  const sessionId = expand("session_id", 32);
  const initiatorGarbageTerminator = garbageTerminators.slice(0, 16);
  const responderGarbageTerminator = garbageTerminators.slice(16);

  const session: CipherSession = initiating
    ? {
      sessionId,
      sendL: new FSChaCha20(initiatorL),
      sendP: new FSChaCha20Poly1305(initiatorP),
      recvL: new FSChaCha20(responderL),
      recvP: new FSChaCha20Poly1305(responderP),
      sendGarbageTerminator: initiatorGarbageTerminator,
      recvGarbageTerminator: responderGarbageTerminator,
      }
    : {
      sessionId,
      sendL: new FSChaCha20(responderL),
      sendP: new FSChaCha20Poly1305(responderP),
      recvL: new FSChaCha20(initiatorL),
      recvP: new FSChaCha20Poly1305(initiatorP),
      sendGarbageTerminator: responderGarbageTerminator,
      recvGarbageTerminator: initiatorGarbageTerminator,
    };

  initiatorL.fill(0);
  initiatorP.fill(0);
  responderL.fill(0);
  responderP.fill(0);
  garbageTerminators.fill(0);
  return session;
}

/** Best-effort erasure of all transport secrets held by a session. */
export function destroySession(session: CipherSession): void {
  session.sendL.destroy();
  session.sendP.destroy();
  session.recvL.destroy();
  session.recvP.destroy();
  session.sessionId.fill(0);
  session.sendGarbageTerminator.fill(0);
  session.recvGarbageTerminator.fill(0);
}

/** Expose mid-state key material for vector tests. */
export function deriveKeyMaterial(
  ecdhSecret: Uint8Array,
  networkMagic: Uint8Array,
): SessionKeyMaterial {
  const salt = concatBytes(utf8ToBytes("bitcoin_v2_shared_secret"), networkMagic);
  const expand = (info: string, length: number) => hkdfSha256(ecdhSecret, salt, info, length);
  const garbageTerminators = expand("garbage_terminators", 32);
  return {
    sessionId: expand("session_id", 32),
    initiatorL: expand("initiator_L", 32),
    initiatorP: expand("initiator_P", 32),
    responderL: expand("responder_L", 32),
    responderP: expand("responder_P", 32),
    initiatorGarbageTerminator: garbageTerminators.slice(0, 16),
    responderGarbageTerminator: garbageTerminators.slice(16),
  };
}
