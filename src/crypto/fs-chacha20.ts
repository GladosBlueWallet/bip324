import { chacha20 } from "@noble/ciphers/chacha.js";
import { concatBytes, u32le, u64le } from "./bytes.ts";

export const REKEY_INTERVAL = 224;

/** ChaCha20 block: 64 keystream bytes for (key, 12-byte nonce, counter). */
export function chacha20Block(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  return chacha20(key, nonce, new Uint8Array(64), undefined, counter);
}

/**
 * Rekeying stream cipher for BIP-324 length encryption.
 * Matches reference.py `FSChaCha20`.
 */
export class FSChaCha20 {
  private key: Uint8Array;
  private blockCounter = 0;
  private chunkCounter = 0;
  private keystream = new Uint8Array(0);
  private destroyed = false;

  constructor(initialKey: Uint8Array) {
    if (initialKey.length !== 32) throw new Error("FSChaCha20 key must be 32 bytes");
    this.key = new Uint8Array(initialKey);
  }

  private getKeystreamBytes(nbytes: number): Uint8Array {
    while (this.keystream.length < nbytes) {
      const nonce = concatBytes(u32le(0), u64le(Math.floor(this.chunkCounter / REKEY_INTERVAL)));
      const block = chacha20Block(this.key, nonce, this.blockCounter);
      this.blockCounter += 1;
      this.keystream = new Uint8Array(concatBytes(this.keystream, block));
    }
    const ret = this.keystream.slice(0, nbytes);
    this.keystream = new Uint8Array(this.keystream.subarray(nbytes));
    return ret;
  }

  crypt(chunk: Uint8Array): Uint8Array {
    if (this.destroyed) throw new Error("FSChaCha20 instance is destroyed");
    const ks = this.getKeystreamBytes(chunk.length);
    const ret = new Uint8Array(chunk.length);
    for (let i = 0; i < chunk.length; i++) ret[i] = chunk[i]! ^ ks[i]!;
    if ((this.chunkCounter + 1) % REKEY_INTERVAL === 0) {
      const nextKey = new Uint8Array(this.getKeystreamBytes(32));
      this.key.fill(0);
      this.key = nextKey;
      this.blockCounter = 0;
    }
    this.chunkCounter += 1;
    return ret;
  }

  encrypt(chunk: Uint8Array): Uint8Array {
    return this.crypt(chunk);
  }

  decrypt(chunk: Uint8Array): Uint8Array {
    return this.crypt(chunk);
  }

  /** Best-effort key erasure; JavaScript runtimes may retain internal copies. */
  destroy(): void {
    this.key.fill(0);
    this.keystream.fill(0);
    this.keystream = new Uint8Array(0);
    this.destroyed = true;
  }
}
