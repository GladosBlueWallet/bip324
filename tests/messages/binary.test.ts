import { describe, expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "../../src/crypto/bytes.ts";
import { PayloadReader, PayloadWriter } from "../../src/messages/binary.ts";

describe("Bitcoin CompactSize", () => {
  const vectors: Array<[bigint, string]> = [
    [0n, "00"],
    [252n, "fc"],
    [253n, "fdfd00"],
    [65_535n, "fdffff"],
    [65_536n, "fe00000100"],
    [4_294_967_296n, "ff0000000001000000"],
  ];

  for (const [value, hex] of vectors) {
    test(`${value}`, () => {
      const writer = new PayloadWriter();
      writer.compactSize(value);
      expect(bytesToHex(writer.finish())).toBe(hex);
      const reader = new PayloadReader(hexToBytes(hex));
      expect(reader.compactSizeBigInt()).toBe(value);
      reader.finish();
    });
  }

  test("rejects non-canonical and truncated encodings", () => {
    expect(() => new PayloadReader(hexToBytes("fdfc00")).compactSizeBigInt())
      .toThrow("non-canonical");
    expect(() => new PayloadReader(hexToBytes("feffff0000")).compactSizeBigInt())
      .toThrow("non-canonical");
    expect(() => new PayloadReader(hexToBytes("ffffffffff00000000")).compactSizeBigInt())
      .toThrow("non-canonical");
    expect(() => new PayloadReader(hexToBytes("fd")).compactSizeBigInt())
      .toThrow("truncated");
  });

  test("number conversion rejects values above Number.MAX_SAFE_INTEGER", () => {
    const reader = new PayloadReader(hexToBytes(`ff${"ff".repeat(8)}`));
    expect(() => reader.compactSize()).toThrow("safe integer");
  });
});
