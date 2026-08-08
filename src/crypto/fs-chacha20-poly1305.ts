import { chacha20, chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes, u32le, u64le } from "./bytes.ts";
import { REKEY_INTERVAL } from "./fs-chacha20.ts";

/**
 * Rekeying AEAD for BIP-324 packet content.
 * Matches reference.py `FSChaCha20Poly1305`.
 */
export class FSChaCha20Poly1305 {
  private key: Uint8Array;
  private packetCounter = 0;
  private destroyed = false;

  constructor(initialKey: Uint8Array) {
    if (initialKey.length !== 32) throw new Error("FSChaCha20Poly1305 key must be 32 bytes");
    this.key = new Uint8Array(initialKey);
  }

  private nonce(): Uint8Array {
    return concatBytes(
      u32le(this.packetCounter % REKEY_INTERVAL),
      u64le(Math.floor(this.packetCounter / REKEY_INTERVAL)),
    );
  }

  private maybeRekey(): void {
    if ((this.packetCounter + 1) % REKEY_INTERVAL === 0) {
      const nonce = this.nonce();
      const rekeyNonce = concatBytes(new Uint8Array([0xff, 0xff, 0xff, 0xff]), nonce.slice(4));
      // Equivalent to encrypting 32 zero bytes and taking first 32 of ciphertext (sans tag),
      // which is also bytes 0..31 of ChaCha20 block counter=1.
      const nextKey = new Uint8Array(
        chacha20(this.key, rekeyNonce, new Uint8Array(32), undefined, 1),
      );
      this.key.fill(0);
      this.key = nextKey;
    }
    this.packetCounter += 1;
  }

  encrypt(aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (this.destroyed) throw new Error("FSChaCha20Poly1305 instance is destroyed");
    const cipher = chacha20poly1305(this.key, this.nonce(), aad);
    const out = cipher.encrypt(plaintext);
    this.maybeRekey();
    return out;
  }

  /** Returns null on authentication failure (matches BIP reference). */
  decrypt(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array | null {
    if (this.destroyed) throw new Error("FSChaCha20Poly1305 instance is destroyed");
    try {
      const cipher = chacha20poly1305(this.key, this.nonce(), aad);
      return cipher.decrypt(ciphertext);
    } catch {
      return null;
    } finally {
      // The BIP-324 reference consumes a packet nonce even when authentication fails.
      this.maybeRekey();
    }
  }

  /** Best-effort key erasure; JavaScript runtimes may retain internal copies. */
  destroy(): void {
    this.key.fill(0);
    this.destroyed = true;
  }
}
