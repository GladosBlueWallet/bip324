import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { ellswiftDecode } from "../../src/crypto/ellswift.ts";
import { bytesToHex, hexToBytes, parseCsv } from "../helpers/csv.ts";

describe("ellswiftDecode BIP vectors", () => {
  const rows = parseCsv(
    join(import.meta.dir, "../../testdata/bip324/ellswift_decode_test_vectors.csv"),
  );
  for (const row of rows) {
    test(`ellswift=${row.ellswift!.slice(0, 16)}…`, () => {
      const got = ellswiftDecode(hexToBytes(row.ellswift!));
      expect(bytesToHex(got)).toBe(row.x!);
    });
  }
});
