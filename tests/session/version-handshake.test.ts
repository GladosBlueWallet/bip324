import { describe, expect, test } from "bun:test";
import {
  Networks,
  Protocol,
  answerPing,
  completeVersionHandshake,
  pairedByteDuplexes,
} from "../../src/index.ts";

async function pairedProtocols(): Promise<[Protocol, Protocol]> {
  const [a, b] = pairedByteDuplexes();
  return Promise.all([
    Protocol.connect(a, { role: "initiator", network: Networks.regtest }),
    Protocol.connect(b, { role: "responder", network: Networks.regtest }),
  ]);
}

describe("completeVersionHandshake", () => {
  test("advertises app identity and returns peer services/startHeight", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      const bobSide = (async () => {
        const inbound = await bob.readMessage();
        expect(inbound.command).toBe("version");
        if (inbound.command === "version") {
          expect(inbound.payload.userAgent).toBe("/wallet:3.1.4/");
        }

        await bob.writeMessage({
          command: "version",
          payload: {
            version: 70_016,
            services: 2048n,
            timestamp: BigInt(Math.floor(Date.now() / 1_000)),
            receiver: { services: 0n, ip: new Uint8Array(16), port: 18444 },
            sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
            nonce: 1n,
            userAgent: "/peer:0/",
            startHeight: 99,
            relay: false,
          },
        });
        await bob.writeMessage({ command: "verack" });

        for (;;) {
          const next = await bob.readMessage();
          if (next.command === "verack") return;
        }
      })();

      const peer = await completeVersionHandshake(alice, {
        port: 18444,
        name: "wallet",
        version: "3.1.4",
        sendAddrV2: false,
      });
      await bobSide;

      expect(peer).toEqual({ services: 2048n, startHeight: 99 });
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});

describe("answerPing", () => {
  test("replies to ping with a matching pong", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, {
          port: 18444,
          name: "a",
          version: "0",
          sendAddrV2: false,
        }),
        completeVersionHandshake(bob, {
          port: 18444,
          name: "b",
          version: "0",
          sendAddrV2: false,
        }),
      ]);
      const nonce = new Uint8Array(8).fill(3);
      const pongWait = bob.readMessage();
      await bob.writeMessage({ command: "ping", nonce });
      const ping = await alice.readMessage();
      expect(ping.command).toBe("ping");
      await answerPing(alice, ping);
      const pong = await pongWait;
      expect(pong.command).toBe("pong");
      if (pong.command === "pong") {
        expect([...pong.nonce]).toEqual([...nonce]);
      }
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});
