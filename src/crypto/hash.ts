import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "./bytes.ts";
import { utf8ToBytes } from "./utf8.ts";

/** Single SHA-256. */
export function sha256Once(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/** Double SHA-256 (Bitcoin txid / block hash / merkle). */
export function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/** BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||data) */
export function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, data));
}

/** HKDF-SHA256 extract+expand to `length` bytes. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array | string,
  length: number,
): Uint8Array {
  const infoBytes = typeof info === "string" ? utf8ToBytes(info) : info;
  return hkdf(sha256, ikm, salt, infoBytes, length);
}
