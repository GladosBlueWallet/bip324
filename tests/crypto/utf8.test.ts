import { expect, test } from "bun:test";
import { bytesToUtf8, utf8ToBytes } from "../../src/crypto/utf8.ts";

test("runtime-neutral UTF-8 codec handles Unicode and rejects malformed bytes", () => {
  const value = "bip324 π 🚀";
  expect(bytesToUtf8(utf8ToBytes(value))).toBe(value);
  expect(() => bytesToUtf8(new Uint8Array([0xc0, 0x80]))).toThrow("UTF-8");
  expect(() => bytesToUtf8(new Uint8Array([0xed, 0xa0, 0x80]))).toThrow("UTF-8");
  expect(() => bytesToUtf8(new Uint8Array([0xf4, 0x90, 0x80, 0x80]))).toThrow("UTF-8");
  expect(() => bytesToUtf8(new Uint8Array([0xe2, 0x82]))).toThrow("UTF-8");
});
