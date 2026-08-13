// tests/examples/p2p-helpers.test.ts
import { describe, expect, test } from "bun:test";
import {
  Networks,
  Protocol,
  hexToBytes,
  pairedByteDuplexes,
} from "../../src/index.ts";
import {
  MAINNET_DNS_SEEDS,
  NODE_NETWORK,
  NODE_P2P_V2,
  addrV2ToCandidate,
  collectAddresses,
  completeVersionHandshake,
  displayHashToInternal,
  filterFullV2Peers,
  internalHashToDisplay,
  ipv4BytesToHost,
  ipv6BytesToHost,
  legacyAddrIpToHost,
  legacyAddrToCandidate,
  rankPeerCandidates,
  resolveSeedPeers,
  shuffleInPlace,
  waitForMessage,
  type DnsResolver,
} from "../../examples/lib/p2p-helpers.ts";

async function pairedProtocols(): Promise<[Protocol, Protocol]> {
  const [a, b] = pairedByteDuplexes();
  return Promise.all([
    Protocol.connect(a, { role: "initiator", network: Networks.regtest }),
    Protocol.connect(b, { role: "responder", network: Networks.regtest }),
  ]);
}

describe("hash byte order", () => {
  test("displayHashToInternal reverses RPC/display hash", () => {
    const display = "000000000000000000006f1baf68845265f3d55fd8ec79eda8ccd55c295d1bde";
    const internal = displayHashToInternal(display);
    expect(internalHashToDisplay(internal)).toBe(display);
    expect(internal[0]).toBe(0xde);
    expect(internal[31]).toBe(0x00);
  });
});

describe("address conversion", () => {
  test("ipv4BytesToHost", () => {
    expect(ipv4BytesToHost(Uint8Array.of(1, 2, 3, 4))).toBe("1.2.3.4");
  });

  test("ipv6BytesToHost compresses zeros", () => {
    const bytes = hexToBytes("20010db8000000000000000000000001");
    expect(ipv6BytesToHost(bytes)).toBe("2001:db8::1");
  });

  test("legacyAddrIpToHost accepts IPv4-mapped", () => {
    const ip = hexToBytes("00000000000000000000ffff01020304");
    expect(legacyAddrIpToHost(ip)).toBe("1.2.3.4");
  });

  test("addrV2ToCandidate keeps IPv4/IPv6 only", () => {
    const v4 = addrV2ToCandidate({
      time: 1,
      services: NODE_NETWORK | NODE_P2P_V2,
      networkId: 1,
      address: Uint8Array.of(8, 8, 8, 8),
      port: 8333,
    });
    expect(v4).toEqual({
      host: "8.8.8.8",
      port: 8333,
      services: NODE_NETWORK | NODE_P2P_V2,
      networkId: 1,
      time: 1,
    });
    expect(
      addrV2ToCandidate({
        time: 1,
        services: 0n,
        networkId: 3,
        address: new Uint8Array(10),
        port: 8333,
      }),
    ).toBeUndefined();
  });

  test("legacyAddrToCandidate maps IPv4-mapped addresses", () => {
    const peer = legacyAddrToCandidate({
      time: 1,
      services: NODE_NETWORK | NODE_P2P_V2,
      ip: hexToBytes("00000000000000000000ffff7f000001"),
      port: 8333,
    });
    expect(peer?.host).toBe("127.0.0.1");
  });
});

describe("filterFullV2Peers", () => {
  test("requires NODE_NETWORK and NODE_P2P_V2 and excludes bootstrap", () => {
    const peers = [
      { host: "1.1.1.1", port: 8333, services: NODE_NETWORK | NODE_P2P_V2, networkId: 1 },
      { host: "2.2.2.2", port: 8333, services: NODE_NETWORK, networkId: 1 },
      { host: "3.3.3.3", port: 8333, services: NODE_P2P_V2, networkId: 1 },
      { host: "9.9.9.9", port: 8333, services: NODE_NETWORK | NODE_P2P_V2, networkId: 1 },
    ];
    expect(
      filterFullV2Peers(peers, { excludeHost: "9.9.9.9", excludePort: 8333 }).map((p) => p.host),
    ).toEqual(["1.1.1.1"]);
  });
});

describe("rankPeerCandidates", () => {
  test("prefers IPv4 then newer timestamps", () => {
    const peers = [
      { host: "2001:db8::1", port: 8333, services: 0n, networkId: 2, time: 100 },
      { host: "1.1.1.1", port: 8333, services: 0n, networkId: 1, time: 10 },
      { host: "2.2.2.2", port: 8333, services: 0n, networkId: 1, time: 50 },
      { host: "2001:db8::2", port: 8333, services: 0n, networkId: 2, time: 200 },
    ];
    expect(rankPeerCandidates(peers).map((p) => p.host)).toEqual([
      "2.2.2.2",
      "1.1.1.1",
      "2001:db8::2",
      "2001:db8::1",
    ]);
  });
});

describe("shuffleInPlace", () => {
  test("uses provided RNG and returns same array reference", () => {
    const items = [1, 2, 3, 4];
    const seq = [0.9, 0.1, 0.5];
    let i = 0;
    const out = shuffleInPlace(items, () => seq[i++] ?? 0);
    expect(out).toBe(items);
    expect(out).toHaveLength(4);
    expect(new Set(out)).toEqual(new Set([1, 2, 3, 4]));
  });
});

describe("waitForMessage", () => {
  test("answers ping and returns the matched message", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, {
          port: 18444,
          name: "test",
          version: "0",
        }),
        completeVersionHandshake(bob, {
          port: 18444,
          name: "test",
          version: "0",
        }),
      ]);
      const got = waitForMessage(alice, (m) => m.command === "getaddr", { timeoutMs: 5_000 });
      await bob.writeMessage({ command: "ping", nonce: new Uint8Array(8).fill(1) });
      await bob.writeMessage({ command: "getaddr" });
      const message = await got;
      expect(message.command).toBe("getaddr");
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });

  test("timeout closes the session so an in-flight read cannot steal later messages", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: false,
        }),
        completeVersionHandshake(bob, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: false,
        }),
      ]);
      await expect(waitForMessage(alice, () => false, { timeoutMs: 30 }))
        .rejects.toThrow("timed out waiting for message");
      expect(alice.isClosed).toBe(true);
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });

  test("a matched read cancels the timeout instead of rejecting later", async () => {
    const [alice, bob] = await pairedProtocols();
    const rejections: unknown[] = [];
    const onUnhandled = (error: unknown) => {
      rejections.push(error);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      await Promise.all([
        completeVersionHandshake(alice, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: false,
        }),
        completeVersionHandshake(bob, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: false,
        }),
      ]);
      const got = waitForMessage(alice, (m) => m.command === "getaddr", { timeoutMs: 80 });
      await bob.writeMessage({ command: "getaddr" });
      expect((await got).command).toBe("getaddr");
      expect(alice.isClosed).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 120));
      expect(rejections).toEqual([]);
      await alice.writeMessage({ command: "ping", nonce: new Uint8Array(8) });
      expect((await bob.readMessage()).command).toBe("ping");
    } finally {
      process.off("unhandledRejection", onUnhandled);
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});

describe("resolveSeedPeers", () => {
  test("lists MAINNET_DNS_SEEDS", () => {
    expect(MAINNET_DNS_SEEDS).toContain("seed.bitcoin.sipa.be");
    expect(MAINNET_DNS_SEEDS.length).toBeGreaterThanOrEqual(5);
  });

  test("merges A/AAAA and shuffles", async () => {
    const resolver: DnsResolver = {
      async resolve4(host) {
        expect(host).toBe("seed.example");
        return ["1.1.1.1", "2.2.2.2"];
      },
      async resolve6(host) {
        expect(host).toBe("seed.example");
        return ["2001:db8::1"];
      },
    };
    const peers = await resolveSeedPeers(["seed.example"], {
      port: 8333,
      resolver,
      random: () => 0, // deterministic Fisher-Yates with always-0 swap index
    });
    expect(peers).toHaveLength(3);
    expect(peers.every((p) => p.port === 8333)).toBe(true);
    // IPv4 first, then IPv6 (order within each family is shuffled).
    expect(peers.slice(0, 2).every((p) => p.networkId === 1)).toBe(true);
    expect(peers[2]?.networkId).toBe(2);
    expect(peers[2]?.host).toBe("2001:db8::1");
    expect(new Set(peers.map((p) => p.host))).toEqual(new Set(["1.1.1.1", "2.2.2.2", "2001:db8::1"]));
    expect(peers.every((p) => p.services === 0n)).toBe(true);
  });

  test("ignores resolver failures per seed", async () => {
    const resolver: DnsResolver = {
      async resolve4(host) {
        if (host === "bad") throw new Error("nxdomain");
        return ["8.8.8.8"];
      },
      async resolve6() {
        return [];
      },
    };
    const peers = await resolveSeedPeers(["bad", "good"], { port: 8333, resolver, random: () => 0 });
    expect(peers.map((p) => p.host)).toEqual(["8.8.8.8"]);
  });
});

describe("collectAddresses", () => {
  test("decodes addrv2 into candidates", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: true,
        }),
        completeVersionHandshake(bob, {
          port: 18444,
          name: "test",
          version: "0",
          sendAddrV2: true,
        }),
      ]);
      const collecting = collectAddresses(alice, { timeoutMs: 5_000 });
      await bob.writeMessage({
        command: "addrv2",
        payload: {
          addresses: [
            {
              time: 1,
              services: NODE_NETWORK | NODE_P2P_V2,
              networkId: 1,
              address: Uint8Array.of(9, 9, 9, 9),
              port: 8333,
            },
          ],
        },
      });
      const peers = await collecting;
      expect(peers).toEqual([
        {
          host: "9.9.9.9",
          port: 8333,
          services: NODE_NETWORK | NODE_P2P_V2,
          networkId: 1,
          time: 1,
        },
      ]);
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});
