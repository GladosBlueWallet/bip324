import { elligatorSwift } from "@scure/btc-signer/p2p.js";
import { bytesToHex, hexToBytes } from "./bytes.ts";

/** Decode a 64-byte ElligatorSwift encoding to a 32-byte x-only pubkey. */
export function ellswiftDecode(ellswift: Uint8Array): Uint8Array {
  if (ellswift.length !== 64) {
    throw new Error(`ellswift must be 64 bytes, got ${ellswift.length}`);
  }
  return elligatorSwift.decode(ellswift);
}

/** Generate ephemeral (privateKey, ellswiftPublicKey) pair. */
export function ellswiftCreate(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const kp = elligatorSwift.keygen();
  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

/**
 * X-only ECDH: shared X coordinate from our privkey and their ellswift pubkey.
 * Matches BIP reference `ellswift_ecdh_xonly`.
 */
export function ellswiftEcdhXonly(pubkeyTheirs: Uint8Array, privkey: Uint8Array): Uint8Array {
  return elligatorSwift.getSharedSecret(privkey, pubkeyTheirs);
}

/**
 * Low-level xswiftec inverse used by ElligatorSwift encoding.
 * Returns undefined when the selected inverse branch has no solution.
 */
export function xswiftecInv(
  x: Uint8Array,
  u: Uint8Array,
  ellCase: number,
): Uint8Array | undefined {
  if (x.length !== 32 || u.length !== 32) throw new Error("x and u must be 32 bytes");
  if (!Number.isInteger(ellCase) || ellCase < 0 || ellCase > 7) {
    throw new Error(`ElligatorSwift case must be in [0, 7], got ${ellCase}`);
  }
  const result = elligatorSwift._inv(
    BigInt(`0x${bytesToHex(x)}`),
    BigInt(`0x${bytesToHex(u)}`),
    ellCase,
  );
  if (result === undefined) return undefined;
  return hexToBytes(result.toString(16).padStart(64, "0"));
}
