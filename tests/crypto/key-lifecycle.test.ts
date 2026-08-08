import { expect, test } from "bun:test";
import { FSChaCha20 } from "../../src/crypto/fs-chacha20.ts";
import { FSChaCha20Poly1305 } from "../../src/crypto/fs-chacha20-poly1305.ts";

test("destroyed forward-secure ciphers reject further use", () => {
  const stream = new FSChaCha20(new Uint8Array(32).fill(1));
  const aead = new FSChaCha20Poly1305(new Uint8Array(32).fill(2));

  stream.destroy();
  aead.destroy();

  expect(() => stream.encrypt(new Uint8Array(3))).toThrow("destroyed");
  expect(() => aead.encrypt(new Uint8Array(0), new Uint8Array(1))).toThrow("destroyed");
  expect(() => aead.decrypt(new Uint8Array(0), new Uint8Array(17))).toThrow("destroyed");
});

test("failed AEAD authentication still advances the packet counter", () => {
  const key = new Uint8Array(32).fill(3);
  const sender = new FSChaCha20Poly1305(key);
  const receiver = new FSChaCha20Poly1305(key);
  const first = sender.encrypt(new Uint8Array(0), new Uint8Array([1]));
  const second = sender.encrypt(new Uint8Array(0), new Uint8Array([2]));
  first[first.length - 1] = first[first.length - 1]! ^ 1;

  expect(receiver.decrypt(new Uint8Array(0), first)).toBeNull();
  expect(receiver.decrypt(new Uint8Array(0), second)).toEqual(new Uint8Array([2]));
});
