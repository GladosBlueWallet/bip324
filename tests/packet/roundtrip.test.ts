import { describe, expect, test } from "bun:test";
import { bytesToHex } from "../../src/crypto/bytes.ts";
import { deriveSessionKeys } from "../../src/crypto/session-keys.ts";
import { v2Ecdh } from "../../src/crypto/v2-ecdh.ts";
import { ellswiftCreate } from "../../src/crypto/ellswift.ts";
import { AuthenticationError } from "../../src/errors.ts";
import { Networks } from "../../src/networks/networks.ts";
import { decodePacket } from "../../src/packet/decode.ts";
import { encodePacket } from "../../src/packet/encode.ts";

describe("packet roundtrip", () => {
  test("encode then decode recovers contents", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    expect(bytesToHex(secretA)).toBe(bytesToHex(secretB));

    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);

    const contents = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const packet = encodePacket(send, contents);

    let offset = 0;
    const reader = {
      async read(n: number) {
        const slice = packet.subarray(offset, offset + n);
        offset += n;
        return slice;
      },
    };
    const got = await decodePacket(recv, reader);
    expect(bytesToHex(got)).toBe(bytesToHex(contents));
  });

  test("decode accepts fragmented stream reads", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);
    const contents = new Uint8Array([1, 2, 3, 4, 5]);
    const packet = encodePacket(send, contents);
    let offset = 0;

    const got = await decodePacket(recv, {
      async read(n: number) {
        const length = Math.min(n, 1, packet.length - offset);
        const chunk = packet.slice(offset, offset + length);
        offset += length;
        return chunk;
      },
    });

    expect(got).toEqual(contents);
  });

  test("skips authenticated decoys and applies AAD only to the first packet", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);
    const aad = new Uint8Array([9, 8, 7]);
    const decoy = encodePacket(send, new Uint8Array([0xaa]), { aad, ignore: true });
    const real = encodePacket(send, new Uint8Array([0xbb]));
    const stream = new Uint8Array(decoy.length + real.length);
    stream.set(decoy);
    stream.set(real, decoy.length);
    let offset = 0;

    const got = await decodePacket(
      recv,
      {
        async read(n) {
          const chunk = stream.slice(offset, offset + Math.min(n, 2));
          offset += chunk.length;
          return chunk;
        },
      },
      { aad },
    );

    expect(got).toEqual(new Uint8Array([0xbb]));
    expect(offset).toBe(stream.length);
  });

  test("rejects a run of decoys above the consecutive ignore cap", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);
    const decoy = encodePacket(send, new Uint8Array([0xaa]), { ignore: true });
    const extra = encodePacket(send, new Uint8Array([0xbb]), { ignore: true });
    const real = encodePacket(send, new Uint8Array([0xcc]));
    const stream = new Uint8Array(decoy.length + extra.length + real.length);
    stream.set(decoy);
    stream.set(extra, decoy.length);
    stream.set(real, decoy.length + extra.length);
    let offset = 0;

    await expect(
      decodePacket(
        recv,
        {
          async read(n) {
            const chunk = stream.slice(offset, offset + n);
            offset += chunk.length;
            return chunk;
          },
        },
        { maxIgnorePackets: 1 },
      ),
    ).rejects.toThrow("decoy");
    expect(() => recv.recvL.decrypt(new Uint8Array(3))).toThrow("destroyed");
  });

  test("roundtrips across the 224-packet rekey boundary for both ciphers", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);

    // 300 packets crosses the FSChaCha20 / FSChaCha20Poly1305 rekey at 224.
    const packets: Uint8Array[] = [];
    for (let i = 0; i < 300; i++) {
      const contents = new Uint8Array([i & 0xff, (i >>> 8) & 0xff, 0x42]);
      packets.push(encodePacket(send, contents));
    }
    const stream = new Uint8Array(
      packets.reduce((n, p) => n + p.length, 0),
    );
    let w = 0;
    for (const p of packets) {
      stream.set(p, w);
      w += p.length;
    }

    let offset = 0;
    const reader = {
      async read(n: number) {
        const chunk = stream.subarray(offset, offset + n);
        offset += chunk.length;
        return chunk;
      },
    };
    for (let i = 0; i < 300; i++) {
      const got = await decodePacket(recv, reader);
      expect(got).toEqual(new Uint8Array([i & 0xff, (i >>> 8) & 0xff, 0x42]));
    }
    expect(offset).toBe(stream.length);
  });

  test("rejects oversized packet contents length before allocation", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);
    const packet = encodePacket(send, new Uint8Array([1, 2, 3]));
    let offset = 0;
    const reader = {
      async read(n: number) {
        const chunk = packet.subarray(offset, offset + n);
        offset += chunk.length;
        return chunk;
      },
    };

    await expect(
      decodePacket(recv, reader, { maxContentsLen: 2 }),
    ).rejects.toThrow(/exceeds max 2/);
    // Session hard-fails: no retry with advanced cipher state.
    expect(() => recv.recvL.decrypt(new Uint8Array(3))).toThrow("destroyed");
  });

  test("rejects tampered authenticated ciphertext", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secretA = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const secretB = v2Ecdh(b.privateKey, a.publicKey, b.publicKey, false);
    const send = deriveSessionKeys(secretA, Networks.mainnet.magic, true);
    const recv = deriveSessionKeys(secretB, Networks.mainnet.magic, false);
    const packet = encodePacket(send, new Uint8Array([1, 2, 3]));
    packet[packet.length - 1] = packet[packet.length - 1]! ^ 1;
    let offset = 0;

    await expect(
      decodePacket(recv, {
        async read(n) {
          const chunk = packet.slice(offset, offset + n);
          offset += chunk.length;
          return chunk;
        },
      }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  test("rejects truncated packet streams", async () => {
    const a = ellswiftCreate();
    const b = ellswiftCreate();
    const secret = v2Ecdh(a.privateKey, b.publicKey, a.publicKey, true);
    const send = deriveSessionKeys(secret, Networks.mainnet.magic, true);
    const packet = encodePacket(send, new Uint8Array([1, 2, 3]));
    let offset = 0;

    const receiver = deriveSessionKeys(secret, Networks.mainnet.magic, false);
    await expect(
      decodePacket(receiver, {
        async read(n) {
          const end = Math.min(offset + n, packet.length - 1);
          const chunk = packet.slice(offset, end);
          offset += chunk.length;
          return chunk;
        },
      }),
    ).rejects.toThrow("unexpected EOF");
    expect(() => receiver.recvL.decrypt(new Uint8Array(3))).toThrow("destroyed");
  });
});
