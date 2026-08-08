import { utf8ToBytes } from "../crypto/utf8.ts";
import { PayloadReader, PayloadWriter } from "./binary.ts";

const MAX_ADDR_COUNT = 1_000;
const MAX_LOCATOR_HASHES = 101;
const MAX_HEADERS = 2_000;
const MAX_INVENTORY = 50_000;
const MAX_ADDR_V2_LENGTH = 512;
const MAX_FIELD_LENGTH = 0x00ff_ffff;
// These exceed the maximum counts possible in a consensus-valid 4 MWU block,
// while bounding eager JavaScript object allocation for malformed P2P payloads.
const MAX_EAGER_INPUTS = 25_000;
const MAX_EAGER_OUTPUTS = 125_000;
const MAX_EAGER_TRANSACTIONS = 100_000;

export type NetworkAddress = {
  services: bigint;
  ip: Uint8Array;
  port: number;
};

export type VersionPayload = {
  version: number;
  services: bigint;
  timestamp: bigint;
  receiver: NetworkAddress;
  sender: NetworkAddress;
  nonce: bigint;
  userAgent: string;
  startHeight: number;
  relay?: boolean;
};

export type AddrPayload = {
  addresses: Array<NetworkAddress & { time: number }>;
};

export type NetworkAddressV2 = {
  time: number;
  services: bigint;
  networkId: number;
  address: Uint8Array;
  port: number;
};

export type AddrV2Payload = {
  addresses: NetworkAddressV2[];
};

export type GetHeadersPayload = {
  version: number;
  locatorHashes: Uint8Array[];
  stopHash: Uint8Array;
};

export type BlockHeader = {
  version: number;
  previousBlockHash: Uint8Array;
  merkleRoot: Uint8Array;
  timestamp: number;
  bits: number;
  nonce: number;
};

export type HeadersPayload = {
  headers: BlockHeader[];
};

export type InventoryVector = {
  type: number;
  hash: Uint8Array;
};

export type InventoryPayload = {
  inventory: InventoryVector[];
};

export type OutPoint = {
  hash: Uint8Array;
  index: number;
};

/**
 * Lazily decoded witness items. This avoids allocating millions of tiny typed
 * arrays for compact but adversarial witness stacks.
 */
export class WitnessStack implements Iterable<Uint8Array> {
  readonly #encodedItems: Uint8Array;

  constructor(
    readonly length: number,
    encodedItems: Uint8Array,
  ) {
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("invalid witness length");
    const reader = new PayloadReader(encodedItems);
    for (let i = 0; i < length; i++) reader.skipVarBytes(MAX_FIELD_LENGTH);
    reader.finish();
    this.#encodedItems = encodedItems.slice();
  }

  *[Symbol.iterator](): IterableIterator<Uint8Array> {
    const reader = new PayloadReader(this.#encodedItems);
    for (let i = 0; i < this.length; i++) yield reader.varBytes(MAX_FIELD_LENGTH);
    reader.finish();
  }

  toArray(): Uint8Array[] {
    return Array.from(this);
  }

  /** Append this stack without materializing its individual items. */
  writeTo(writer: PayloadWriter): void {
    writer.compactSize(this.length).bytes(this.#encodedItems);
  }
}

export type Witness = readonly Uint8Array[] | WitnessStack;

export type TxInput = {
  previousOutput: OutPoint;
  scriptSig: Uint8Array;
  sequence: number;
  witness?: Witness;
};

export type TxOutput = {
  value: bigint;
  scriptPubKey: Uint8Array;
};

export type Transaction = {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  lockTime: number;
};

export type BlockPayload = {
  header: BlockHeader;
  transactions: Transaction[];
};

export function encodeVersion(payload: VersionPayload): Uint8Array {
  const writer = new PayloadWriter();
  const userAgent = utf8ToBytes(payload.userAgent);
  if (userAgent.length > 256) throw new Error("version user agent exceeds 256 bytes");
  writer.i32le(payload.version).u64le(payload.services).i64le(payload.timestamp);
  writeNetworkAddress(writer, payload.receiver);
  writeNetworkAddress(writer, payload.sender);
  writer.u64le(payload.nonce).varBytes(userAgent).i32le(payload.startHeight);
  if (payload.relay !== undefined) writer.u8(payload.relay ? 1 : 0);
  return writer.finish();
}

export function decodeVersion(bytes: Uint8Array): VersionPayload {
  const reader = new PayloadReader(bytes);
  const payload: VersionPayload = {
    version: reader.i32le(),
    services: reader.u64le(),
    timestamp: reader.i64le(),
    receiver: readNetworkAddress(reader),
    sender: readNetworkAddress(reader),
    nonce: reader.u64le(),
    userAgent: reader.varString(256),
    startHeight: reader.i32le(),
  };
  if (reader.remaining > 0) {
    const relay = reader.u8();
    if (relay > 1) throw new Error("version relay flag must be 0 or 1");
    payload.relay = relay === 1;
  }
  reader.finish();
  return payload;
}

export function encodeAddr(payload: AddrPayload): Uint8Array {
  if (payload.addresses.length > MAX_ADDR_COUNT) throw new Error("too many addr entries");
  const writer = new PayloadWriter().compactSize(payload.addresses.length);
  for (const address of payload.addresses) {
    writer.u32le(address.time);
    writeNetworkAddress(writer, address);
  }
  return writer.finish();
}

export function decodeAddr(bytes: Uint8Array): AddrPayload {
  const reader = new PayloadReader(bytes);
  const count = reader.compactSize(MAX_ADDR_COUNT);
  const addresses: AddrPayload["addresses"] = [];
  for (let i = 0; i < count; i++) {
    addresses.push({ time: reader.u32le(), ...readNetworkAddress(reader) });
  }
  reader.finish();
  return { addresses };
}

export function encodeAddrV2(payload: AddrV2Payload): Uint8Array {
  if (payload.addresses.length > MAX_ADDR_COUNT) throw new Error("too many addrv2 entries");
  const writer = new PayloadWriter().compactSize(payload.addresses.length);
  for (const address of payload.addresses) {
    validateAddrV2(address.networkId, address.address.length);
    writer
      .u32le(address.time)
      .compactSize(address.services)
      .u8(address.networkId)
      .varBytes(address.address)
      .u16be(address.port);
  }
  return writer.finish();
}

export function decodeAddrV2(bytes: Uint8Array): AddrV2Payload {
  const reader = new PayloadReader(bytes);
  const count = reader.compactSize(MAX_ADDR_COUNT);
  const addresses: NetworkAddressV2[] = [];
  for (let i = 0; i < count; i++) {
    const time = reader.u32le();
    const services = reader.compactSizeBigInt();
    const networkId = reader.u8();
    const address = reader.varBytes(MAX_ADDR_V2_LENGTH);
    validateAddrV2(networkId, address.length);
    addresses.push({ time, services, networkId, address, port: reader.u16be() });
  }
  reader.finish();
  return { addresses };
}

export function encodeGetHeaders(payload: GetHeadersPayload): Uint8Array {
  if (payload.locatorHashes.length > MAX_LOCATOR_HASHES) {
    throw new Error("too many block locator hashes");
  }
  assertLength(payload.stopHash, 32, "stop hash");
  const writer = new PayloadWriter()
    .i32le(payload.version)
    .compactSize(payload.locatorHashes.length);
  for (const hash of payload.locatorHashes) {
    assertLength(hash, 32, "locator hash");
    writer.bytes(hash);
  }
  return writer.bytes(payload.stopHash).finish();
}

export function decodeGetHeaders(bytes: Uint8Array): GetHeadersPayload {
  const reader = new PayloadReader(bytes);
  const version = reader.i32le();
  const count = reader.compactSize(MAX_LOCATOR_HASHES);
  const locatorHashes: Uint8Array[] = [];
  for (let i = 0; i < count; i++) locatorHashes.push(reader.bytes(32));
  const stopHash = reader.bytes(32);
  reader.finish();
  return { version, locatorHashes, stopHash };
}

export function encodeHeaders(payload: HeadersPayload): Uint8Array {
  if (payload.headers.length > MAX_HEADERS) throw new Error("too many headers");
  const writer = new PayloadWriter().compactSize(payload.headers.length);
  for (const header of payload.headers) {
    writer.bytes(encodeBlockHeader(header)).compactSize(0);
  }
  return writer.finish();
}

export function decodeHeaders(bytes: Uint8Array): HeadersPayload {
  const reader = new PayloadReader(bytes);
  const count = reader.compactSize(MAX_HEADERS);
  const headers: BlockHeader[] = [];
  for (let i = 0; i < count; i++) {
    headers.push(readBlockHeader(reader));
    if (reader.compactSizeBigInt() !== 0n) {
      throw new Error("headers transaction count must be zero");
    }
  }
  reader.finish();
  return { headers };
}

export function encodeInventory(payload: InventoryPayload): Uint8Array {
  if (payload.inventory.length > MAX_INVENTORY) throw new Error("too many inventory entries");
  const writer = new PayloadWriter().compactSize(payload.inventory.length);
  for (const item of payload.inventory) {
    assertLength(item.hash, 32, "inventory hash");
    writer.u32le(item.type).bytes(item.hash);
  }
  return writer.finish();
}

export function decodeInventory(bytes: Uint8Array): InventoryPayload {
  const reader = new PayloadReader(bytes);
  const count = reader.compactSize(MAX_INVENTORY);
  const inventory: InventoryVector[] = [];
  for (let i = 0; i < count; i++) {
    inventory.push({ type: reader.u32le(), hash: reader.bytes(32) });
  }
  reader.finish();
  return { inventory };
}

export function encodeTransaction(transaction: Transaction): Uint8Array {
  const writer = new PayloadWriter();
  writeTransaction(writer, transaction);
  return writer.finish();
}

export function decodeTransaction(bytes: Uint8Array): Transaction {
  const reader = new PayloadReader(bytes);
  const transaction = readTransaction(reader, new AllocationBudget());
  reader.finish();
  return transaction;
}

export function encodeBlock(payload: BlockPayload): Uint8Array {
  const writer = new PayloadWriter()
    .bytes(encodeBlockHeader(payload.header))
    .compactSize(payload.transactions.length);
  for (const transaction of payload.transactions) writer.bytes(encodeTransaction(transaction));
  return writer.finish();
}

export function decodeBlock(bytes: Uint8Array): BlockPayload {
  const reader = new PayloadReader(bytes);
  const budget = new AllocationBudget();
  const header = readBlockHeader(reader);
  const count = byteBoundedCount(reader, 10, "transactions");
  budget.take("transactions", count);
  const transactions: Transaction[] = [];
  for (let i = 0; i < count; i++) transactions.push(readTransaction(reader, budget));
  reader.finish();
  return { header, transactions };
}

export function encodeBlockHeader(header: BlockHeader): Uint8Array {
  assertLength(header.previousBlockHash, 32, "previous block hash");
  assertLength(header.merkleRoot, 32, "merkle root");
  return new PayloadWriter()
    .i32le(header.version)
    .bytes(header.previousBlockHash)
    .bytes(header.merkleRoot)
    .u32le(header.timestamp)
    .u32le(header.bits)
    .u32le(header.nonce)
    .finish();
}

function readBlockHeader(reader: PayloadReader): BlockHeader {
  return {
    version: reader.i32le(),
    previousBlockHash: reader.bytes(32),
    merkleRoot: reader.bytes(32),
    timestamp: reader.u32le(),
    bits: reader.u32le(),
    nonce: reader.u32le(),
  };
}

function writeTransaction(writer: PayloadWriter, transaction: Transaction): void {
  const hasWitness = transaction.inputs.some(
    (input) => input.witness !== undefined && input.witness.length > 0,
  );
  writer.u32le(transaction.version);
  if (hasWitness) writer.u8(0).u8(1);
  writer.compactSize(transaction.inputs.length);
  for (const input of transaction.inputs) {
    assertLength(input.previousOutput.hash, 32, "outpoint hash");
    if (input.scriptSig.length > MAX_FIELD_LENGTH) throw new Error("scriptSig too long");
    writer
      .bytes(input.previousOutput.hash)
      .u32le(input.previousOutput.index)
      .varBytes(input.scriptSig)
      .u32le(input.sequence);
  }
  writer.compactSize(transaction.outputs.length);
  for (const output of transaction.outputs) {
    if (output.scriptPubKey.length > MAX_FIELD_LENGTH) throw new Error("scriptPubKey too long");
    writer.i64le(output.value).varBytes(output.scriptPubKey);
  }
  if (hasWitness) {
    for (const input of transaction.inputs) {
      const witness = input.witness ?? [];
      if (witness instanceof WitnessStack) {
        witness.writeTo(writer);
        continue;
      }
      writer.compactSize(witness.length);
      for (const item of witness) {
        if (item.length > MAX_FIELD_LENGTH) throw new Error("witness item too long");
        writer.varBytes(item);
      }
    }
  }
  writer.u32le(transaction.lockTime);
}

function readTransaction(reader: PayloadReader, budget: AllocationBudget): Transaction {
  const version = reader.u32le();
  let flags = 0;
  let inputCount = reader.compactSize();
  budget.take("inputs", inputCount);
  if (inputCount === 0) {
    flags = reader.u8();
    if (flags === 0) throw new Error("transaction witness flags must not be zero");
    inputCount = byteBoundedCount(reader, 41, "transaction inputs");
    budget.take("inputs", inputCount);
  } else if (inputCount > Math.floor(reader.remaining / 41)) {
    throw new Error("transaction inputs exceed remaining payload");
  }
  const inputs: TxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    inputs.push({
      previousOutput: { hash: reader.bytes(32), index: reader.u32le() },
      scriptSig: reader.varBytes(MAX_FIELD_LENGTH),
      sequence: reader.u32le(),
    });
  }
  const outputCount = byteBoundedCount(reader, 9, "transaction outputs");
  budget.take("outputs", outputCount);
  const outputs: TxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    outputs.push({
      value: reader.i64le(),
      scriptPubKey: reader.varBytes(MAX_FIELD_LENGTH),
    });
  }
  if ((flags & 1) !== 0) {
    let hasWitness = false;
    for (const input of inputs) {
      const count = byteBoundedCount(reader, 1, "witness items");
      const start = reader.position;
      for (let i = 0; i < count; i++) {
        reader.skipVarBytes(MAX_FIELD_LENGTH);
      }
      if (count > 0) hasWitness = true;
      input.witness = new WitnessStack(count, reader.data.subarray(start, reader.position));
    }
    if (!hasWitness) throw new Error("superfluous transaction witness record");
    flags ^= 1;
  }
  if (flags !== 0) throw new Error(`unsupported transaction witness flags: ${flags}`);
  return { version, inputs, outputs, lockTime: reader.u32le() };
}

function writeNetworkAddress(writer: PayloadWriter, address: NetworkAddress): void {
  assertLength(address.ip, 16, "network address IP");
  writer.u64le(address.services).bytes(address.ip).u16be(address.port);
}

function readNetworkAddress(reader: PayloadReader): NetworkAddress {
  return { services: reader.u64le(), ip: reader.bytes(16), port: reader.u16be() };
}

function validateAddrV2(networkId: number, length: number): void {
  if (!Number.isInteger(networkId) || networkId < 1 || networkId > 255) {
    throw new Error(`invalid addrv2 network ID: ${networkId}`);
  }
  if (length > MAX_ADDR_V2_LENGTH) throw new Error("addrv2 address length exceeds 512");
  const knownLengths: Record<number, number> = {
    1: 4,
    2: 16,
    3: 10,
    4: 32,
    5: 32,
    6: 16,
    7: 16,
  };
  const expected = knownLengths[networkId];
  if (expected !== undefined && length !== expected) {
    throw new Error(`addrv2 network ${networkId} address length must be ${expected}, got ${length}`);
  }
}

function assertLength(bytes: Uint8Array, expected: number, name: string): void {
  if (bytes.length !== expected) throw new Error(`${name} must be ${expected} bytes`);
}

function byteBoundedCount(
  reader: PayloadReader,
  minimumItemBytes: number,
  label: string,
): number {
  const count = reader.compactSize();
  if (count > Math.floor(reader.remaining / minimumItemBytes)) {
    throw new Error(`${label} exceed remaining payload`);
  }
  return count;
}

class AllocationBudget {
  #inputs = MAX_EAGER_INPUTS;
  #outputs = MAX_EAGER_OUTPUTS;
  #transactions = MAX_EAGER_TRANSACTIONS;

  take(kind: "inputs" | "outputs" | "transactions", count: number): void {
    switch (kind) {
      case "inputs":
        if (count > this.#inputs) throw new Error("inputs exceed aggregate allocation limit");
        this.#inputs -= count;
        break;
      case "outputs":
        if (count > this.#outputs) throw new Error("outputs exceed aggregate allocation limit");
        this.#outputs -= count;
        break;
      case "transactions":
        if (count > this.#transactions) {
          throw new Error("transactions exceed aggregate allocation limit");
        }
        this.#transactions -= count;
        break;
    }
  }
}
