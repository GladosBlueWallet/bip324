import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { bytesToHex } from "../../src/crypto/bytes.ts";
import { xswiftecInv } from "../../src/crypto/ellswift.ts";
import { hexToBytes, parseCsv } from "../helpers/csv.ts";

describe("xswiftec inverse BIP vectors", () => {
  const rows = parseCsv(
    join(import.meta.dir, "../../testdata/bip324/xswiftec_inv_test_vectors.csv"),
  );

  for (const [rowIndex, row] of rows.entries()) {
    for (let ellCase = 0; ellCase < 8; ellCase++) {
      const expected = row[`case${ellCase}_t`];
      test(`row=${rowIndex} case=${ellCase}`, () => {
        const actual = xswiftecInv(
          hexToBytes(row.x!),
          hexToBytes(row.u!),
          ellCase,
        );
        if (expected) {
          expect(actual).toBeDefined();
          expect(bytesToHex(actual!)).toBe(expected);
        } else {
          expect(actual).toBeUndefined();
        }
      });
    }
  }
});
