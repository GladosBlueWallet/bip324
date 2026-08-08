import { describe, expect, test } from "bun:test";
import { bytesToHex, concatBytes } from "../../src/crypto/bytes.ts";
import { decodeMessage, encodeMessage } from "../../src/messages/codec.ts";
import { SHORT_ID_TO_COMMAND, SHORT_MESSAGE_IDS } from "../../src/messages/ids.ts";
import { Networks } from "../../src/networks/networks.ts";

describe("v2 message codec", () => {
  test("ping uses short id 18", () => {
    const nonce = new Uint8Array(8).fill(0xab);
    const encoded = encodeMessage({ command: "ping", nonce });
    expect(encoded[0]).toBe(18);
    expect(encoded.length).toBe(9);
    const decoded = decodeMessage(encoded);
    expect(decoded.command).toBe("ping");
    if (decoded.command === "ping") expect(bytesToHex(decoded.nonce)).toBe(bytesToHex(nonce));
  });

  test("getaddr uses long form (no short id in BIP table)", () => {
    const encoded = encodeMessage({ command: "getaddr" });
    expect(encoded[0]).toBe(0);
  });

  test("accepts long-form aliases for commands with short IDs", () => {
    const longPing = new Uint8Array(21);
    longPing[0] = 0;
    longPing.set(new TextEncoder().encode("ping"), 1);
    longPing.fill(0xaa, 13);
    const decoded = decodeMessage(longPing);
    expect(decoded.command).toBe("ping");
    if (decoded.command === "ping") expect(decoded.nonce).toEqual(new Uint8Array(8).fill(0xaa));
  });

  test("roundtrips unknown short IDs without inventing a command name", () => {
    const wire = new Uint8Array([250, 1, 2, 3]);
    const decoded = decodeMessage(wire);
    expect(decoded).toEqual({
      command: "opaque",
      type: { kind: "short", id: 250 },
      payload: new Uint8Array([1, 2, 3]),
    });
    expect(encodeMessage(decoded)).toEqual(wire);
  });

  test("keeps currently undefined ID 29 opaque", () => {
    const decoded = decodeMessage(new Uint8Array([29]));
    expect(decoded).toEqual({
      command: "opaque",
      type: { kind: "short", id: 29 },
      payload: new Uint8Array(0),
    });
  });

  test("rejects malformed long-form command padding and non-printable ASCII", () => {
    const embeddedNul = concatBytes(
      new Uint8Array([0]),
      new Uint8Array([0x70, 0, 0x69]),
      new Uint8Array(9),
    );
    const control = concatBytes(new Uint8Array([0, 0x1f]), new Uint8Array(11));
    const nonAscii = concatBytes(new Uint8Array([0, 0x80]), new Uint8Array(11));
    expect(() => decodeMessage(embeddedNul)).toThrow("padding");
    expect(() => decodeMessage(control)).toThrow("printable ASCII");
    expect(() => decodeMessage(nonAscii)).toThrow("printable ASCII");
    expect(() => decodeMessage(new Uint8Array([0, 0x70]))).toThrow("truncated");
  });

  test("rejects payloads on payloadless commands", () => {
    expect(() => decodeMessage(concatBytes(encodeMessage({ command: "verack" }), new Uint8Array([1]))))
      .toThrow("verack payload must be empty");
    expect(() => decodeMessage(concatBytes(encodeMessage({ command: "getaddr" }), new Uint8Array([1]))))
      .toThrow("getaddr payload must be empty");
  });

  test("exported protocol constants cannot mutate internal framing state", () => {
    expect(Object.isFrozen(SHORT_MESSAGE_IDS)).toBe(true);
    expect(Object.isFrozen(SHORT_ID_TO_COMMAND)).toBe(true);
    const magic = Networks.mainnet.magic;
    magic.fill(0);
    expect(bytesToHex(Networks.mainnet.magic)).toBe("f9beb4d9");
  });
});
