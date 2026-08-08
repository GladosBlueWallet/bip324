import { describe, expect, test } from "bun:test";
import { bytesToHex } from "../../src/crypto/bytes.ts";
import { pairedByteDuplexes, type ByteDuplex } from "../../src/io/byte-duplex.ts";
import { Networks } from "../../src/networks/networks.ts";
import {
  AuthenticationError,
  Protocol,
  ProtocolClosedError,
} from "../../src/session/protocol.ts";

describe("Protocol session", () => {
  test("exchanges ping/pong after handshake", async () => {
    const [left, right] = pairedByteDuplexes();
    const [alice, bob] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);

    expect(bytesToHex(alice.sessionId)).toBe(bytesToHex(bob.sessionId));

    const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await alice.writeMessage({ command: "ping", nonce });
    const got = await bob.readMessage();
    expect(got.command).toBe("ping");
    if (got.command !== "ping") throw new Error("expected ping");
    expect(bytesToHex(got.nonce)).toBe(bytesToHex(nonce));

    await bob.writeMessage({ command: "pong", nonce: got.nonce });
    const pong = await alice.readMessage();
    expect(pong.command).toBe("pong");
  });

  test("authentication failure closes and permanently invalidates the session", async () => {
    const [left, rawRight] = pairedByteDuplexes();
    let tamper = false;
    let reads = 0;
    let closes = 0;
    const right: ByteDuplex = {
      async read(n) {
        const bytes = await rawRight.read(n);
        if (tamper && ++reads === 2) {
          bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
        }
        return bytes;
      },
      write: (bytes) => rawRight.write(bytes),
      async close() {
        closes += 1;
        await rawRight.close();
      },
    };
    const [alice, bob] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);

    tamper = true;
    await alice.writeMessage({ command: "ping", nonce: new Uint8Array(8) });

    expect(bob.readMessage()).rejects.toBeInstanceOf(AuthenticationError);
    expect(bob.isClosed).toBe(true);
    expect(closes).toBe(1);
    expect(bob.readMessage()).rejects.toBeInstanceOf(ProtocolClosedError);
    expect(bob.writeMessage({ command: "getaddr" })).rejects.toBeInstanceOf(ProtocolClosedError);
  });

  test("a failed write closes the session after cipher state advances", async () => {
    const [rawLeft, right] = pairedByteDuplexes();
    let failWrites = false;
    let closes = 0;
    const left: ByteDuplex = {
      read: (n) => rawLeft.read(n),
      async write(bytes) {
        if (failWrites) throw new Error("socket failed");
        await rawLeft.write(bytes);
      },
      async close() {
        closes += 1;
        await rawLeft.close();
      },
    };
    const [alice] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);

    failWrites = true;
    expect(alice.writeMessage({ command: "getaddr" })).rejects.toThrow("socket failed");
    expect(alice.isClosed).toBe(true);
    expect(closes).toBe(1);
  });

  test("sessionId returns a defensive copy", async () => {
    const [left, right] = pairedByteDuplexes();
    const [alice] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);
    const original = alice.sessionId;
    original.fill(0);
    expect(alice.sessionId).not.toEqual(original);
  });

  test("close wakes an active read", async () => {
    const [left, right] = pairedByteDuplexes();
    const [, bob] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);
    const reading = bob.readMessage().then(
      () => "read",
      () => "closed",
    );
    await Promise.resolve();
    await Promise.resolve();
    await bob.close();
    expect(await Promise.race([
      reading,
      new Promise<string>((resolve) => setTimeout(() => resolve("timeout"), 20)),
    ])).toBe("closed");
  });

  test("concurrent close calls await the same transport teardown", async () => {
    const [rawLeft, right] = pairedByteDuplexes();
    let closeCalls = 0;
    let releaseClose!: () => void;
    const closeGate = new Promise<void>((resolve) => {
      releaseClose = resolve;
    });
    const left: ByteDuplex = {
      read: (n) => rawLeft.read(n),
      write: (bytes) => rawLeft.write(bytes),
      async close() {
        closeCalls += 1;
        await closeGate;
        await rawLeft.close();
      },
    };
    const [alice] = await Promise.all([
      Protocol.connect(left, { role: "initiator", network: Networks.regtest }),
      Protocol.connect(right, { role: "responder", network: Networks.regtest }),
    ]);

    let secondSettled = false;
    const first = alice.close();
    const second = alice.close().then(() => {
      secondSettled = true;
    });
    await Promise.resolve();
    expect(closeCalls).toBe(1);
    expect(secondSettled).toBe(false);
    releaseClose();
    await Promise.all([first, second]);
    expect(secondSettled).toBe(true);
  });
});
