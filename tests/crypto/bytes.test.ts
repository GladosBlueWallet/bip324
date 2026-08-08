import { expect, test } from "bun:test";
import { hexToBytes } from "../../src/crypto/bytes.ts";

test("hexToBytes rejects non-hex input instead of silently producing zeros", () => {
  expect(() => hexToBytes("0g")).toThrow("invalid hex");
  expect(() => hexToBytes("zz")).toThrow("invalid hex");
});
