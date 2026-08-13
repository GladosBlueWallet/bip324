import { describe, expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "../../src/crypto/bytes.ts";
import { decodeMessage, encodeMessage } from "../../src/messages/codec.ts";
import { WitnessStack, type VersionPayload } from "../../src/messages/payloads.ts";

const IPV4_LOOPBACK = hexToBytes("00000000000000000000ffff7f000001");
const GENESIS_HEADER = [
  "01000000",
  "00".repeat(32),
  "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
  "29ab5f49",
  "ffff001d",
  "1dac2b7c",
].join("");
const GENESIS_TX = [
  "01000000",
  "01",
  "00".repeat(32),
  "ffffffff",
  "4d",
  "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
  "ffffffff",
  "01",
  "00f2052a01000000",
  "43",
  "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
  "00000000",
].join("");

describe("typed Bitcoin P2P payload codecs", () => {
  test("version matches a fixed wire fixture", () => {
    const payload: VersionPayload = {
      version: 70_016,
      services: 1n,
      timestamp: 0n,
      receiver: { services: 1n, ip: IPV4_LOOPBACK, port: 8333 },
      sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
      nonce: 0x0102_0304_0506_0708n,
      userAgent: "/bip324:0.1/",
      startHeight: 100,
      relay: false,
    };
    const expectedPayload = [
      "80110100",
      "0100000000000000",
      "0000000000000000",
      "0100000000000000",
      bytesToHex(IPV4_LOOPBACK),
      "208d",
      "0000000000000000",
      "00".repeat(16),
      "0000",
      "0807060504030201",
      "0c2f6269703332343a302e312f",
      "64000000",
      "00",
    ].join("");

    const wire = encodeMessage({ command: "version", payload });
    expect(bytesToHex(wire.slice(13))).toBe(expectedPayload);
    expect(decodeMessage(wire)).toEqual({ command: "version", payload });
  });

  test("version without a relay byte defaults to BIP-37 relay-enabled", () => {
    const withRelay = encodeMessage({
      command: "version",
      payload: {
        version: 70_016,
        services: 0n,
        timestamp: 0n,
        receiver: { services: 0n, ip: new Uint8Array(16), port: 0 },
        sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
        nonce: 0n,
        userAgent: "/",
        startHeight: 0,
        relay: false,
      },
    });
    const decoded = decodeMessage(withRelay.subarray(0, withRelay.length - 1));
    expect(decoded.command).toBe("version");
    if (decoded.command !== "version") throw new Error("expected version");
    expect(decoded.payload.relay).toBe(true);
  });

  test("addr and addrv2 encode network addresses", () => {
    const addr = {
      command: "addr" as const,
      payload: {
        addresses: [{
          time: 0x0102_0304,
          services: 1n,
          ip: IPV4_LOOPBACK,
          port: 8333,
        }],
      },
    };
    const addrWire = encodeMessage(addr);
    expect(bytesToHex(addrWire)).toBe(
      `01` + `01` + `04030201` + `0100000000000000` + bytesToHex(IPV4_LOOPBACK) + `208d`,
    );
    expect(decodeMessage(addrWire)).toEqual(addr);

    const addrv2 = {
      command: "addrv2" as const,
      payload: {
        addresses: [{
          time: 0x0102_0304,
          services: 2048n,
          networkId: 1,
          address: new Uint8Array([127, 0, 0, 1]),
          port: 8333,
        }],
      },
    };
    const addrv2Wire = encodeMessage(addrv2);
    expect(bytesToHex(addrv2Wire)).toBe("1c0104030201fd000801047f000001208d");
    expect(decodeMessage(addrv2Wire)).toEqual(addrv2);
  });

  test("addrv2 keeps unknown network IDs and only rejects known-ID length mismatches", () => {
    const unknownFuture = hexToBytes(
      "1c01000000000008110200000000000000000000000000000000208d",
    );
    const decodedFuture = decodeMessage(unknownFuture);
    expect(decodedFuture).toEqual({
      command: "addrv2",
      payload: {
        addresses: [{
          time: 0,
          services: 0n,
          networkId: 8,
          address: hexToBytes("0200000000000000000000000000000000"),
          port: 8333,
        }],
      },
    });
    expect(encodeMessage(decodedFuture)).toEqual(unknownFuture);

    const reservedZero = hexToBytes("1c0100000000000001aa208d");
    expect(decodeMessage(reservedZero)).toEqual({
      command: "addrv2",
      payload: {
        addresses: [{
          time: 0,
          services: 0n,
          networkId: 0,
          address: Uint8Array.of(0xaa),
          port: 8333,
        }],
      },
    });

    expect(() => decodeMessage(hexToBytes("1c01000000000001037f0001208d")))
      .toThrow("address length");
    expect(() => decodeMessage(hexToBytes("1c01000000000007110200000000000000000000000000000000208d")))
      .toThrow("address length");
  });

  test("getheaders, headers, and inventory vectors roundtrip", () => {
    const getheaders = {
      command: "getheaders" as const,
      payload: {
        version: 70_016,
        locatorHashes: [new Uint8Array(32).fill(0x11)],
        stopHash: new Uint8Array(32),
      },
    };
    expect(decodeMessage(encodeMessage(getheaders))).toEqual(getheaders);

    const headersWire = hexToBytes(`0d01${GENESIS_HEADER}00`);
    const headers = decodeMessage(headersWire);
    expect(headers.command).toBe("headers");
    if (headers.command !== "headers") throw new Error("expected headers");
    expect(headers.payload.headers).toHaveLength(1);
    expect(headers.payload.headers[0]?.timestamp).toBe(1_231_006_505);
    expect(encodeMessage(headers)).toEqual(headersWire);

    const inv = {
      command: "inv" as const,
      payload: {
        inventory: [{ type: 2, hash: new Uint8Array(32).fill(0x22) }],
      },
    };
    expect(decodeMessage(encodeMessage(inv))).toEqual(inv);
    expect(decodeMessage(encodeMessage({ ...inv, command: "getdata" }))).toEqual({
      ...inv,
      command: "getdata",
    });
    expect(decodeMessage(encodeMessage({ ...inv, command: "notfound" }))).toEqual({
      ...inv,
      command: "notfound",
    });
  });

  test("decodes and re-encodes the real genesis transaction and block", () => {
    const txWire = hexToBytes(`15${GENESIS_TX}`);
    const tx = decodeMessage(txWire);
    expect(tx.command).toBe("tx");
    if (tx.command !== "tx") throw new Error("expected tx");
    expect(tx.payload.inputs).toHaveLength(1);
    expect(tx.payload.outputs[0]?.value).toBe(5_000_000_000n);
    expect(encodeMessage(tx)).toEqual(txWire);

    const blockWire = hexToBytes(`02${GENESIS_HEADER}01${GENESIS_TX}`);
    const block = decodeMessage(blockWire);
    expect(block.command).toBe("block");
    if (block.command !== "block") throw new Error("expected block");
    expect(block.payload.transactions).toHaveLength(1);
    expect(block.payload.header.nonce).toBe(2_083_236_893);
    expect(encodeMessage(block)).toEqual(blockWire);
  });

  test("preserves segregated witness transaction data", () => {
    const witnessTx = [
      "02000000",
      "0001",
      "01",
      "11".repeat(32),
      "00000000",
      "00",
      "ffffffff",
      "01",
      "0100000000000000",
      "01",
      "51",
      "02",
      "01aa",
      "02bbcc",
      "00000000",
    ].join("");
    const wire = hexToBytes(`15${witnessTx}`);
    const decoded = decodeMessage(wire);
    expect(decoded.command).toBe("tx");
    if (decoded.command !== "tx") throw new Error("expected tx");
    expect(Array.from(decoded.payload.inputs[0]?.witness ?? [])).toEqual([
      new Uint8Array([0xaa]),
      new Uint8Array([0xbb, 0xcc]),
    ]);
    expect(encodeMessage(decoded)).toEqual(wire);
  });

  test("preserves unsigned transaction versions and signed output values", () => {
    const unusual = GENESIS_TX
      .replace(/^01000000/, "ffffffff")
      .replace("00f2052a01000000", "ffffffffffffffff");
    const wire = hexToBytes(`15${unusual}`);
    const decoded = decodeMessage(wire);
    expect(decoded.command).toBe("tx");
    if (decoded.command !== "tx") throw new Error("expected tx");
    expect(decoded.payload.version).toBe(0xffff_ffff);
    expect(decoded.payload.outputs[0]?.value).toBe(-1n);
    expect(encodeMessage(decoded)).toEqual(wire);
  });

  test("rejects malformed typed payloads and trailing data", () => {
    expect(() => decodeMessage(hexToBytes("1c01000000000001037f0001208d")))
      .toThrow("address length");
    expect(() => decodeMessage(hexToBytes(`0d01${GENESIS_HEADER}01`)))
      .toThrow("transaction count");
    expect(() => decodeMessage(hexToBytes(`15${GENESIS_TX}00`)))
      .toThrow("trailing");
    const superfluousWitness = [
      "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
      "01", "0100000000000000", "01", "51", "00", "00000000",
    ].join("");
    expect(() => decodeMessage(hexToBytes(superfluousWitness)))
      .toThrow("superfluous");
    const manyWitnessItems = [
      "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
      "01", "0100000000000000", "01", "51",
      "fea1860100", "00".repeat(100_001), "00000000",
    ].join("");
    const manyWitnessDecoded = decodeMessage(hexToBytes(manyWitnessItems));
    expect(manyWitnessDecoded.command).toBe("tx");
    if (manyWitnessDecoded.command !== "tx") throw new Error("expected tx");
    expect(manyWitnessDecoded.payload.inputs[0]?.witness).toBeInstanceOf(WitnessStack);
    expect(manyWitnessDecoded.payload.inputs[0]?.witness).toHaveLength(100_001);
    expect(encodeMessage(manyWitnessDecoded)).toEqual(hexToBytes(manyWitnessItems));
    const impossibleWitnessCount = [
      "15", "02000000", "0001", "01", "11".repeat(32), "00000000", "00", "ffffffff",
      "01", "0100000000000000", "01", "51", "feffffff00",
    ].join("");
    expect(() => decodeMessage(hexToBytes(impossibleWitnessCount)))
      .toThrow("remaining payload");
    const excessiveOutputs = [
      "15", "02000000", "01", "11".repeat(32), "00000000", "00", "ffffffff",
      "fe49e80100", "000000000000000000".repeat(125_001), "00000000",
    ].join("");
    expect(() => decodeMessage(hexToBytes(excessiveOutputs)))
      .toThrow("allocation limit");
    const oneInput = `01${"11".repeat(32)}0000000000ffffffff`;
    const manyOutputsTx =
      `02000000${oneInput}fd25f4${"000000000000000000".repeat(62_501)}00000000`;
    const aggregateOutputsBlock = `02${"00".repeat(80)}02${manyOutputsTx}${manyOutputsTx}`;
    expect(() => decodeMessage(hexToBytes(aggregateOutputsBlock)))
      .toThrow("aggregate allocation");
    expect(() => encodeMessage({
      command: "version",
      payload: {
        version: 70_016,
        services: 0n,
        timestamp: 0n,
        receiver: { services: 0n, ip: new Uint8Array(16), port: 0 },
        sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
        nonce: 0n,
        userAgent: "x".repeat(257),
        startHeight: 0,
      },
    })).toThrow("user agent");
  });
});
