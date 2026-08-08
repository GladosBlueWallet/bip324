import { describe, expect, test } from "bun:test";
import { bytesToHex } from "../../src/crypto/bytes.ts";
import { ellswiftCreate } from "../../src/crypto/ellswift.ts";
import { performHandshake } from "../../src/handshake/handshake.ts";
import { pairedByteDuplexes, type ByteDuplex } from "../../src/io/byte-duplex.ts";
import { Networks } from "../../src/networks/networks.ts";

describe("BIP-324 handshake", () => {
  test("initiator and responder complete with matching session ids", async () => {
    const [left, right] = pairedByteDuplexes();
    const [a, b] = await Promise.all([
      performHandshake(left, { role: "initiator", network: Networks.mainnet }),
      performHandshake(right, { role: "responder", network: Networks.mainnet }),
    ]);
    if (a.transport !== "v2" || b.transport !== "v2") throw new Error("expected v2");
    expect(bytesToHex(a.session.sessionId)).toBe(bytesToHex(b.session.sessionId));
  });

  test("handshake works with optional garbage", async () => {
    const [left, right] = pairedByteDuplexes();
    const [a, b] = await Promise.all([
      performHandshake(left, {
        role: "initiator",
        network: Networks.testnet3,
        garbage: new Uint8Array([1, 2, 3, 4]),
      }),
      performHandshake(right, {
        role: "responder",
        network: Networks.testnet3,
        garbage: new Uint8Array([9, 8, 7]),
      }),
    ]);
    if (a.transport !== "v2" || b.transport !== "v2") throw new Error("expected v2");
    expect(bytesToHex(a.session.sessionId)).toBe(bytesToHex(b.session.sessionId));
  });

  test("returns consumed bytes when the responder detects v1", async () => {
    const prefix = new Uint8Array([
      ...Networks.mainnet.magic,
      ...new TextEncoder().encode("version"),
      0, 0, 0, 0, 0,
    ]);
    let offset = 0;
    const duplex: ByteDuplex = {
      async read(n) {
        const chunk = prefix.slice(offset, offset + n);
        offset += chunk.length;
        return chunk;
      },
      async write() {
        throw new Error("responder must not write before handing v1 back");
      },
      async close() {},
    };

    const result = await performHandshake(duplex, {
      role: "responder",
      network: Networks.mainnet,
    });

    expect(result.transport).toBe("v1");
    if (result.transport !== "v1") throw new Error("expected v1 handoff");
    expect(result.buffered).toEqual(prefix);
  });

  test("responder sends its key as soon as v2 is distinguishable", async () => {
    const [rawInitiator, rawResponder] = pairedByteDuplexes();
    let keyPair = ellswiftCreate();
    while (keyPair.publicKey[0] === Networks.mainnet.magic[0]) {
      keyPair = ellswiftCreate();
    }
    let releaseRest!: () => void;
    const responderWrote = new Promise<void>((resolve) => {
      releaseRest = resolve;
    });
    let firstWrite = true;
    const initiator: ByteDuplex = {
      read: (n) => rawInitiator.read(n),
      async write(bytes) {
        if (!firstWrite) return rawInitiator.write(bytes);
        firstWrite = false;
        await rawInitiator.write(bytes.slice(0, 1));
        await responderWrote;
        await rawInitiator.write(bytes.slice(1));
      },
      close: () => rawInitiator.close(),
    };
    const responder: ByteDuplex = {
      read: (n) => rawResponder.read(n),
      async write(bytes) {
        releaseRest();
        await rawResponder.write(bytes);
      },
      close: () => rawResponder.close(),
    };

    const [a, b] = await Promise.all([
      performHandshake(initiator, {
        role: "initiator",
        network: Networks.mainnet,
        createKeyPair: () => keyPair,
      }),
      performHandshake(responder, { role: "responder", network: Networks.mainnet }),
    ]);

    expect(a.transport).toBe("v2");
    expect(b.transport).toBe("v2");
  });
});
