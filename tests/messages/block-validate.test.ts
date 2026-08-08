import { expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "../../src/crypto/bytes.ts";
import {
  assertBlockPayload,
  transactionId,
  transactionMerkleRoot,
} from "../../src/messages/block-validate.ts";
import { decodeBlock, type Transaction } from "../../src/messages/payloads.ts";

const GENESIS_BLOCK_HEX =
  "01000000" +
  "0000000000000000000000000000000000000000000000000000000000000000" +
  "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
  "29ab5f49ffff001d1dac2b7c" +
  "01" +
  "01000000" +
  "01" +
  "0000000000000000000000000000000000000000000000000000000000000000" +
  "ffffffff" +
  "4d" +
  "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" +
  "ffffffff" +
  "01" +
  "00f2052a01000000" +
  "43" +
  "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac" +
  "00000000";

test("known Bitcoin genesis block validates txid, merkle root, and header hash", () => {
  const block = decodeBlock(hexToBytes(GENESIS_BLOCK_HEX));
  const expectedHash =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  const expectedTxid =
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

  expect(
    bytesToHex(transactionId(block.transactions[0]!).slice().reverse()),
  ).toBe(expectedTxid);
  expect(bytesToHex(transactionMerkleRoot(block.transactions))).toBe(
    bytesToHex(block.header.merkleRoot),
  );
  expect(() => assertBlockPayload(block, expectedHash)).not.toThrow();
});

test("transaction IDs exclude witness and empty blocks have no merkle root", () => {
  const base: Transaction = {
    version: 2,
    inputs: [
      {
        previousOutput: {
          hash: new Uint8Array(32).fill(1),
          index: 0,
        },
        scriptSig: new Uint8Array([0x51]),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ value: 1n, scriptPubKey: new Uint8Array([0x51]) }],
    lockTime: 0,
  };
  const witnessed: Transaction = {
    ...base,
    inputs: base.inputs.map((input) => ({
      ...input,
      witness: [new Uint8Array([1, 2, 3])],
    })),
  };

  expect(transactionId(witnessed)).toEqual(transactionId(base));
  expect(() => transactionMerkleRoot([])).toThrow(
    "block contains no transactions",
  );
});

test("valid odd-width merkle levels are padded but explicit duplicate pairs are rejected", () => {
  const genesis = decodeBlock(hexToBytes(GENESIS_BLOCK_HEX));
  const first = genesis.transactions[0]!;
  const second = { ...first, lockTime: 1 };
  const third = { ...first, lockTime: 2 };

  expect(() =>
    transactionMerkleRoot([first, second, third]),
  ).not.toThrow();
  expect(() =>
    transactionMerkleRoot([first, second, third, third]),
  ).toThrow(/mutated merkle tree/);
});
