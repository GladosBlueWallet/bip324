import { bytesToHex, equalBytes } from "../crypto/bytes.ts";
import { sha256d } from "../crypto/hash.ts";
import {
  encodeBlockHeader,
  encodeTransaction,
  type BlockPayload,
  type Transaction,
} from "./payloads.ts";

export class BlockValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlockValidationError";
  }
}

function transactionWithoutWitness(
  transaction: Transaction,
): Transaction {
  return {
    ...transaction,
    inputs: transaction.inputs.map(
      ({ witness: _witness, ...input }) => input,
    ),
  };
}

/** Bitcoin txid (double-SHA256 of the non-witness serialization), internal order. */
export function transactionId(transaction: Transaction): Uint8Array {
  return sha256d(
    encodeTransaction(transactionWithoutWitness(transaction)),
  );
}

/**
 * Transaction merkle root (internal byte order).
 * Rejects empty blocks and CVE-2012-2458-style explicit duplicate pairs.
 */
export function transactionMerkleRoot(
  transactions: readonly Transaction[],
): Uint8Array {
  if (transactions.length === 0) {
    throw new BlockValidationError("block contains no transactions");
  }
  let level = transactions.map(transactionId);
  while (level.length > 1) {
    for (let index = 0; index + 1 < level.length; index += 2) {
      if (equalBytes(level[index]!, level[index + 1]!)) {
        throw new BlockValidationError(
          "mutated merkle tree contains an explicit duplicate pair",
        );
      }
    }
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]!.slice());
    }
    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const pair = new Uint8Array(64);
      pair.set(level[index]!, 0);
      pair.set(level[index + 1]!, 32);
      next.push(sha256d(pair));
    }
    level = next;
  }
  return level[0]!;
}

/** Verify header hash (display order) and transaction merkle root. */
export function assertBlockPayload(
  payload: BlockPayload,
  expectedHashDisplay: string,
): void {
  const actualHashDisplay = bytesToHex(
    sha256d(encodeBlockHeader(payload.header)).slice().reverse(),
  );
  if (actualHashDisplay !== expectedHashDisplay) {
    throw new BlockValidationError(
      `block header hash ${actualHashDisplay} does not match requested ${expectedHashDisplay}`,
    );
  }
  const actualMerkleRoot = transactionMerkleRoot(payload.transactions);
  if (!equalBytes(actualMerkleRoot, payload.header.merkleRoot)) {
    throw new BlockValidationError(
      `block ${expectedHashDisplay} transaction merkle root mismatch`,
    );
  }
}
