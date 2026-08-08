# Mainnet Fetch-Block Example Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Bun example that discovers mainnet peers via DNS seeds + `getaddr`, then fetches a hardcoded recent block over BIP-324 from a second peer.

**Architecture:** Pure helpers in `examples/lib/p2p-helpers.ts` (address conversion, service filtering, handshake/wait loops, injectable DNS). Live orchestration in `examples/mainnet-fetch-block.ts` using `Protocol` + `connectNodeTcp`. Unit-test helpers only; live mainnet stays manual.

**Tech Stack:** TypeScript ESM, Bun, existing `bip324` `Protocol`/`Networks`/`connectNodeTcp`, `node:dns/promises` for seeds.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-23-mainnet-fetch-block-example-design.md`
- Network: `Networks.mainnet` only
- No consensus verification / header sync / v1 fallback
- Target block hardcodes height **959293** and display hash `000000000000000000006f1baf68845265f3d55fd8ec79eda8ccd55c295d1bde` (Blockstream tip as of 2026-07-23; wire/internal order is reversed)
- Second-hop peers require `NODE_NETWORK (1)` and `NODE_P2P_V2 (2048)`
- Connect only IPv4 (`networkId=1`) and IPv6 (`networkId=2`); skip Tor/I2P/CJDNS/Yggdrasil
- Live mainnet traffic must not run inside `bun test`
- Prefer TDD for helpers; commit after each task

## File map

| Path | Responsibility |
|------|----------------|
| `examples/lib/p2p-helpers.ts` | Address formatting, service filter, candidate types, handshake/wait helpers, DNS resolve |
| `tests/examples/p2p-helpers.test.ts` | Unit tests for pure + duplex helpers |
| `examples/mainnet-fetch-block.ts` | Live mainnet orchestration |
| `package.json` | `example:mainnet` script |
| `README.md` | Brief mention of the example |

---

### Task 1: Peer address helpers + unit tests

**Files:**
- Create: `examples/lib/p2p-helpers.ts`
- Create: `tests/examples/p2p-helpers.test.ts`

**Interfaces:**
- Produces:
  - `NODE_NETWORK = 1n`, `NODE_P2P_V2 = 2048n`
  - `type PeerCandidate = { host: string; port: number; services: bigint; networkId: number }`
  - `displayHashToInternal(hex: string): Uint8Array`
  - `internalHashToDisplay(bytes: Uint8Array): string`
  - `ipv4BytesToHost(bytes: Uint8Array): string`
  - `ipv6BytesToHost(bytes: Uint8Array): string`
  - `legacyAddrIpToHost(ip16: Uint8Array): string | undefined` — IPv4-mapped or IPv6; else undefined
  - `addrV2ToCandidate(address: NetworkAddressV2): PeerCandidate | undefined`
  - `legacyAddrToCandidate(address: NetworkAddress & { time: number }): PeerCandidate | undefined`
  - `filterFullV2Peers(peers: PeerCandidate[], opts?: { excludeHost?: string; excludePort?: number }): PeerCandidate[]`
  - `shuffleInPlace<T>(items: T[], random?: () => number): T[]`

- [ ] **Step 1: Write the failing tests**

```ts
// tests/examples/p2p-helpers.test.ts
import { describe, expect, test } from "bun:test";
import { hexToBytes } from "../../src/index.ts";
import {
  NODE_NETWORK,
  NODE_P2P_V2,
  addrV2ToCandidate,
  displayHashToInternal,
  filterFullV2Peers,
  internalHashToDisplay,
  ipv4BytesToHost,
  ipv6BytesToHost,
  legacyAddrIpToHost,
  legacyAddrToCandidate,
  shuffleInPlace,
} from "../../examples/lib/p2p-helpers.ts";

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: FAIL resolving `examples/lib/p2p-helpers.ts` (module not found)

- [ ] **Step 3: Implement helpers**

```ts
// examples/lib/p2p-helpers.ts
import {
  bytesToHex,
  hexToBytes,
  type Message,
  type NetworkAddress,
  type NetworkAddressV2,
  type Protocol,
} from "../../src/index.ts";

export const NODE_NETWORK = 1n;
export const NODE_P2P_V2 = 2048n;

export type PeerCandidate = {
  host: string;
  port: number;
  services: bigint;
  networkId: number;
};

export function displayHashToInternal(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) throw new Error("block hash must be 32 bytes");
  return bytes.reverse();
}

export function internalHashToDisplay(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error("block hash must be 32 bytes");
  return bytesToHex(bytes.slice().reverse());
}

export function ipv4BytesToHost(bytes: Uint8Array): string {
  if (bytes.length !== 4) throw new Error("IPv4 address must be 4 bytes");
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

export function ipv6BytesToHost(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error("IPv6 address must be 16 bytes");
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((bytes[i]! << 8) | bytes[i + 1]!);
  // Compress the longest zero run (RFC 5952-ish).
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= groups.length; i++) {
    if (i < groups.length && groups[i] === 0) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      const len = i - runStart;
      if (len > bestLen) {
        bestStart = runStart;
        bestLen = len;
      }
      runStart = -1;
    }
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(":");
  const head = groups.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const tail = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(":");
  return `${head}::${tail}`;
}

export function legacyAddrIpToHost(ip16: Uint8Array): string | undefined {
  if (ip16.length !== 16) return undefined;
  const mapped = ip16.subarray(0, 12).every((b, i) => b === (i < 10 ? 0 : 0xff));
  if (mapped) return ipv4BytesToHost(ip16.subarray(12));
  // Unspecified / all-zero is not routable for this example.
  if (ip16.every((b) => b === 0)) return undefined;
  return ipv6BytesToHost(ip16);
}

export function addrV2ToCandidate(address: NetworkAddressV2): PeerCandidate | undefined {
  if (address.port <= 0 || address.port > 65535) return undefined;
  if (address.networkId === 1 && address.address.length === 4) {
    return {
      host: ipv4BytesToHost(address.address),
      port: address.port,
      services: address.services,
      networkId: 1,
    };
  }
  if (address.networkId === 2 && address.address.length === 16) {
    const host = ipv6BytesToHost(address.address);
    if (host === "::") return undefined;
    return { host, port: address.port, services: address.services, networkId: 2 };
  }
  return undefined;
}

export function legacyAddrToCandidate(
  address: NetworkAddress & { time: number },
): PeerCandidate | undefined {
  if (address.port <= 0 || address.port > 65535) return undefined;
  const host = legacyAddrIpToHost(address.ip);
  if (!host) return undefined;
  return {
    host,
    port: address.port,
    services: address.services,
    networkId: host.includes(":") ? 2 : 1,
  };
}

export function filterFullV2Peers(
  peers: PeerCandidate[],
  opts: { excludeHost?: string; excludePort?: number } = {},
): PeerCandidate[] {
  return peers.filter((peer) => {
    if ((peer.services & NODE_NETWORK) !== NODE_NETWORK) return false;
    if ((peer.services & NODE_P2P_V2) !== NODE_P2P_V2) return false;
    if (
      opts.excludeHost !== undefined &&
      opts.excludePort !== undefined &&
      peer.host === opts.excludeHost &&
      peer.port === opts.excludePort
    ) {
      return false;
    }
    return true;
  });
}

export function shuffleInPlace<T>(items: T[], random: () => number = Math.random): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
  }
  return items;
}
```

Keep `Protocol` / `Message` imports unused for now if handshake helpers are Task 2; either omit them until Task 2 or add stub exports later. Prefer omitting until Task 2.

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add examples/lib/p2p-helpers.ts tests/examples/p2p-helpers.test.ts
git commit -m "$(cat <<'EOF'
feat: add mainnet example peer-address helpers

EOF
)"
```

---

### Task 2: Handshake / message-wait helpers + duplex tests

**Files:**
- Modify: `examples/lib/p2p-helpers.ts`
- Modify: `tests/examples/p2p-helpers.test.ts`

**Interfaces:**
- Consumes: `Protocol`, `Message`, `Networks`, `pairedByteDuplexes` from `src/`
- Produces:
  - `answerPing(protocol: Protocol, message: Message): Promise<void>`
  - `completeVersionHandshake(protocol: Protocol, options: { port: number; startHeight?: number; sendAddrV2?: boolean }): Promise<void>`
  - `waitForMessage(protocol: Protocol, match: (message: Message) => boolean, options?: { timeoutMs?: number }): Promise<Message>`
  - `collectAddresses(protocol: Protocol, options?: { timeoutMs?: number }): Promise<PeerCandidate[]>`

- [ ] **Step 1: Write failing tests for handshake helpers**

Append to `tests/examples/p2p-helpers.test.ts`:

```ts
import {
  Networks,
  Protocol,
  pairedByteDuplexes,
  type Message,
} from "../../src/index.ts";
import {
  answerPing,
  collectAddresses,
  completeVersionHandshake,
  waitForMessage,
} from "../../examples/lib/p2p-helpers.ts";

async function pairedProtocols(): Promise<[Protocol, Protocol]> {
  const [a, b] = pairedByteDuplexes();
  return Promise.all([
    Protocol.connect(a, { role: "initiator", network: Networks.regtest }),
    Protocol.connect(b, { role: "responder", network: Networks.regtest }),
  ]);
}

describe("completeVersionHandshake", () => {
  test("exchanges version and verack both ways", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, { port: 18444, sendAddrV2: true }),
        completeVersionHandshake(bob, { port: 18444, sendAddrV2: false }),
      ]);
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});

describe("waitForMessage + answerPing", () => {
  test("answers ping while waiting", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, { port: 18444 }),
        completeVersionHandshake(bob, { port: 18444 }),
      ]);
      const waiter = waitForMessage(alice, (m) => m.command === "pong", { timeoutMs: 5_000 });
      await bob.writeMessage({ command: "ping", nonce: new Uint8Array(8).fill(7) });
      // alice's wait loop should not consume unrelated traffic forever; drive pong via answerPing path:
      // bob waits for pong after alice answers.
      const bobPong = waitForMessage(bob, (m) => m.command === "pong", { timeoutMs: 5_000 });
      // Inject a ping toward alice by having bob send ping; alice waitForMessage answers it.
      // Re-structure: alice waits for opaque marker; bob sends ping then marker.
      await bob.writeMessage({
        command: "opaque",
        type: { kind: "long", command: "getaddr" },
        payload: new Uint8Array(0),
      });
      // Simpler dedicated test below.
      void waiter;
      void bobPong;
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });

  test("waitForMessage answers ping and returns matcher", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, { port: 18444 }),
        completeVersionHandshake(bob, { port: 18444 }),
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
});

describe("collectAddresses", () => {
  test("decodes addrv2 into candidates", async () => {
    const [alice, bob] = await pairedProtocols();
    try {
      await Promise.all([
        completeVersionHandshake(alice, { port: 18444, sendAddrV2: true }),
        completeVersionHandshake(bob, { port: 18444, sendAddrV2: true }),
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
        },
      ]);
    } finally {
      await Promise.all([alice.close(), bob.close()]);
    }
  });
});
```

Simplify the first flaky ping test: **delete** the incomplete `"answers ping while waiting"` test and keep only `"waitForMessage answers ping and returns matcher"`.

Also add a tiny unit test for `answerPing` no-op on non-ping:

```ts
test("answerPing ignores non-ping", async () => {
  const [alice, bob] = await pairedProtocols();
  try {
    await answerPing(alice, { command: "getaddr" } as Message);
  } finally {
    await Promise.all([alice.close(), bob.close()]);
  }
});
```

- [ ] **Step 2: Run tests to verify new cases fail**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: FAIL — `completeVersionHandshake` / `waitForMessage` / `collectAddresses` not exported

- [ ] **Step 3: Implement handshake helpers**

Append to `examples/lib/p2p-helpers.ts`:

```ts
export async function answerPing(protocol: Protocol, message: Message): Promise<void> {
  if (message.command === "ping") {
    await protocol.writeMessage({ command: "pong", nonce: message.nonce });
  }
}

export async function completeVersionHandshake(
  protocol: Protocol,
  options: { port: number; startHeight?: number; sendAddrV2?: boolean },
): Promise<void> {
  const random = crypto.getRandomValues(new Uint8Array(8));
  const nonce = new DataView(random.buffer, random.byteOffset, 8).getBigUint64(0, true);
  await protocol.writeMessage({
    command: "version",
    payload: {
      version: 70_016,
      services: 0n,
      timestamp: BigInt(Math.floor(Date.now() / 1_000)),
      receiver: { services: 0n, ip: new Uint8Array(16), port: options.port },
      sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
      nonce,
      userAgent: "/bip324-ts:0.0.1/",
      startHeight: options.startHeight ?? 0,
      relay: false,
    },
  });

  let receivedVersion = false;
  let receivedVerack = false;
  while (!receivedVersion || !receivedVerack) {
    const message = await protocol.readMessage();
    if (message.command === "version") {
      receivedVersion = true;
      if (options.sendAddrV2) {
        await protocol.writeMessage({
          command: "opaque",
          type: { kind: "long", command: "sendaddrv2" },
          payload: new Uint8Array(0),
        });
      }
      await protocol.writeMessage({ command: "verack" });
    } else if (message.command === "verack") {
      receivedVerack = true;
    } else {
      await answerPing(protocol, message);
    }
  }
}

export async function waitForMessage(
  protocol: Protocol,
  match: (message: Message) => boolean,
  options: { timeoutMs?: number } = {},
): Promise<Message> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const remaining = deadline - Date.now();
    const message = await Promise.race([
      protocol.readMessage(),
      sleepReject(remaining, `timed out waiting for message after ${timeoutMs}ms`),
    ]);
    if (match(message)) return message;
    await answerPing(protocol, message);
  }
  throw new Error(`timed out waiting for message after ${timeoutMs}ms`);
}

export async function collectAddresses(
  protocol: Protocol,
  options: { timeoutMs?: number } = {},
): Promise<PeerCandidate[]> {
  await protocol.writeMessage({ command: "getaddr" });
  const message = await waitForMessage(
    protocol,
    (m) => m.command === "addr" || m.command === "addrv2",
    options,
  );
  if (message.command === "addrv2") {
    return message.payload.addresses
      .map(addrV2ToCandidate)
      .filter((peer): peer is PeerCandidate => peer !== undefined);
  }
  if (message.command === "addr") {
    return message.payload.addresses
      .map(legacyAddrToCandidate)
      .filter((peer): peer is PeerCandidate => peer !== undefined);
  }
  throw new Error("unreachable");
}

function sleepReject(ms: number, message: string): Promise<never> {
  return new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), Math.max(0, ms));
    // Allow process exit in Bun if nothing else is pending in tests that cancel early.
    timer.unref?.();
  });
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: PASS

If the dual `completeVersionHandshake` test races on `sendaddrv2` opaque messages, keep `sendAddrV2: false` on both sides for that test and cover `sendAddrV2: true` only in `collectAddresses`.

- [ ] **Step 5: Commit**

```bash
git add examples/lib/p2p-helpers.ts tests/examples/p2p-helpers.test.ts
git commit -m "$(cat <<'EOF'
feat: add P2P handshake helpers for examples

EOF
)"
```

---

### Task 3: Injectable DNS seed resolver + tests

**Files:**
- Modify: `examples/lib/p2p-helpers.ts`
- Modify: `tests/examples/p2p-helpers.test.ts`

**Interfaces:**
- Produces:
  - `MAINNET_DNS_SEEDS: readonly string[]`
  - `type DnsResolver = { resolve4(host: string): Promise<string[]>; resolve6(host: string): Promise<string[]> }`
  - `resolveSeedPeers(seeds: readonly string[], options: { port: number; resolver: DnsResolver; random?: () => number }): Promise<PeerCandidate[]>`

- [ ] **Step 1: Write failing DNS helper tests**

```ts
import { MAINNET_DNS_SEEDS, resolveSeedPeers, type DnsResolver } from "../../examples/lib/p2p-helpers.ts";

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
    expect(peers.map((p) => p.host).sort()).toEqual(["1.1.1.1", "2.2.2.2", "2001:db8::1"]);
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: FAIL — missing `resolveSeedPeers` / `MAINNET_DNS_SEEDS`

- [ ] **Step 3: Implement DNS helper**

```ts
export const MAINNET_DNS_SEEDS = Object.freeze([
  "seed.bitcoin.sipa.be",
  "dnsseed.bluematt.me",
  "seed.bitcoin.jonasschnelli.ch",
  "seed.btc.petertodd.net",
  "seed.bitcoin.sprovoost.nl",
  "dnsseed.emzy.de",
  "seed.bitcoin.wiz.biz",
]);

export type DnsResolver = {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
};

export async function resolveSeedPeers(
  seeds: readonly string[],
  options: { port: number; resolver: DnsResolver; random?: () => number },
): Promise<PeerCandidate[]> {
  const peers: PeerCandidate[] = [];
  for (const seed of seeds) {
    try {
      const [v4, v6] = await Promise.all([
        options.resolver.resolve4(seed).catch(() => [] as string[]),
        options.resolver.resolve6(seed).catch(() => [] as string[]),
      ]);
      for (const host of v4) {
        peers.push({ host, port: options.port, services: 0n, networkId: 1 });
      }
      for (const host of v6) {
        peers.push({ host, port: options.port, services: 0n, networkId: 2 });
      }
    } catch {
      // ignore whole-seed failures
    }
  }
  return shuffleInPlace(peers, options.random);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `bun test tests/examples/p2p-helpers.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add examples/lib/p2p-helpers.ts tests/examples/p2p-helpers.test.ts
git commit -m "$(cat <<'EOF'
feat: add injectable DNS seed peer resolver

EOF
)"
```

---

### Task 4: Live mainnet example + package script + README

**Files:**
- Create: `examples/mainnet-fetch-block.ts`
- Modify: `package.json` (add `example:mainnet`)
- Modify: `README.md` (short examples section / bullet)

**Interfaces:**
- Consumes: all helpers from Tasks 1–3, `connectNodeTcp` from `src/node.ts`, `Networks`/`Protocol`/`V1DetectedError` from `src/index.ts`
- Produces: runnable `bun run example:mainnet`

- [ ] **Step 1: Add package script**

In `package.json` scripts:

```json
"example:getaddr": "bun examples/signet-getaddr.ts",
"example:mainnet": "bun examples/mainnet-fetch-block.ts"
```

- [ ] **Step 2: Implement `examples/mainnet-fetch-block.ts`**

```ts
import { promises as dns } from "node:dns";
import {
  Networks,
  Protocol,
  V1DetectedError,
  type Message,
} from "../src/index.ts";
import { connectNodeTcp } from "../src/node.ts";
import {
  MAINNET_DNS_SEEDS,
  collectAddresses,
  completeVersionHandshake,
  displayHashToInternal,
  filterFullV2Peers,
  internalHashToDisplay,
  resolveSeedPeers,
  shuffleInPlace,
  waitForMessage,
  type PeerCandidate,
} from "./lib/p2p-helpers.ts";

// Hardcoded recent mainnet tip snapshot (no header sync / verification).
// Source: https://blockstream.info/api/block/<hash> on 2026-07-23.
const TARGET_HEIGHT = 959_293;
const TARGET_DISPLAY_HASH =
  "000000000000000000006f1baf68845265f3d55fd8ec79eda8ccd55c295d1bde";
const TARGET_INTERNAL_HASH = displayHashToInternal(TARGET_DISPLAY_HASH);

const network = Networks.mainnet;
const peerTimeoutMs = Number(process.env.PEER_TIMEOUT_MS ?? 15_000);
const overallTimeoutMs = Number(process.env.OVERALL_TIMEOUT_MS ?? 90_000);
const maxBootstrap = Number(process.env.MAX_BOOTSTRAP ?? 12);
const maxDiscovered = Number(process.env.MAX_DISCOVERED ?? 16);

const overallTimer = setTimeout(() => {
  console.error(`overall timeout after ${overallTimeoutMs}ms`);
  process.exit(1);
}, overallTimeoutMs);
overallTimer.unref?.();

let bootstrapTried = 0;
let discoveredTried = 0;

try {
  const bootstrapPeers = (
    await resolveSeedPeers(MAINNET_DNS_SEEDS, {
      port: network.defaultPort,
      resolver: dns,
    })
  ).slice(0, maxBootstrap);

  console.log(`resolved ${bootstrapPeers.length} bootstrap candidates from DNS seeds`);

  for (const bootstrap of bootstrapPeers) {
    bootstrapTried++;
    console.log(`bootstrap ${bootstrapTried}: ${bootstrap.host}:${bootstrap.port}`);
    const discovered = await tryBootstrap(bootstrap);
    if (!discovered) continue;

    const candidates = shuffleInPlace(
      filterFullV2Peers(discovered, {
        excludeHost: bootstrap.host,
        excludePort: bootstrap.port,
      }),
    ).slice(0, maxDiscovered);

    console.log(`discovered ${discovered.length} addresses; ${candidates.length} full+v2 candidates`);
    for (const peer of candidates.slice(0, 10)) {
      console.log(`  candidate ${peer.host}:${peer.port} services=${peer.services}`);
    }

    for (const peer of candidates) {
      discoveredTried++;
      console.log(`peer ${discoveredTried}: ${peer.host}:${peer.port}`);
      const ok = await tryFetchBlock(peer);
      if (ok) {
        clearTimeout(overallTimer);
        process.exit(0);
      }
    }
  }

  console.error(
    `failed after ${bootstrapTried} bootstrap peers and ${discoveredTried} discovered peers`,
  );
  process.exit(1);
} catch (error) {
  console.error(error);
  process.exit(1);
}

async function tryBootstrap(peer: PeerCandidate): Promise<PeerCandidate[] | undefined> {
  return withPeer(peer, async (protocol) => {
    await completeVersionHandshake(protocol, {
      port: peer.port,
      startHeight: TARGET_HEIGHT,
      sendAddrV2: true,
    });
    return collectAddresses(protocol, { timeoutMs: peerTimeoutMs });
  });
}

async function tryFetchBlock(peer: PeerCandidate): Promise<boolean> {
  return (
    (await withPeer(peer, async (protocol) => {
      await completeVersionHandshake(protocol, {
        port: peer.port,
        startHeight: TARGET_HEIGHT,
        sendAddrV2: false,
      });
      await protocol.writeMessage({
        command: "getdata",
        payload: { inventory: [{ type: 2, hash: TARGET_INTERNAL_HASH }] },
      });
      const message = await waitForMessage(
        protocol,
        (m) => m.command === "block" || m.command === "notfound",
        { timeoutMs: peerTimeoutMs },
      );
      if (message.command === "notfound") {
        console.log("  notfound");
        return false;
      }
      if (message.command === "block") {
        console.log(
          `received block height=${TARGET_HEIGHT} hash=${TARGET_DISPLAY_HASH} txs=${message.payload.transactions.length}`,
        );
        console.log(`internal hash=${internalHashToDisplay(TARGET_INTERNAL_HASH)}`);
        return true;
      }
      return false;
    })) ?? false
  );
}

async function withPeer<T>(
  peer: PeerCandidate,
  fn: (protocol: Protocol) => Promise<T>,
): Promise<T | undefined> {
  let duplex: Awaited<ReturnType<typeof connectNodeTcp>> | undefined;
  let protocol: Protocol | undefined;
  const timer = setTimeout(() => {
    void duplex?.close();
  }, peerTimeoutMs);
  try {
    duplex = await connectNodeTcp({ host: peer.host, port: peer.port });
    protocol = await Protocol.connect(duplex, { role: "initiator", network });
    return await fn(protocol);
  } catch (error) {
    if (error instanceof V1DetectedError) {
      console.log("  v1-only / not BIP-324");
    } else {
      console.log(`  failed: ${error instanceof Error ? error.message : error}`);
    }
    return undefined;
  } finally {
    clearTimeout(timer);
    try {
      await protocol?.close();
    } catch {
      // ignore
    }
    try {
      await duplex?.close();
    } catch {
      // ignore
    }
  }
}

// Silence unused Message import if TypeScript complains — remove Message import if unused.
type _Message = Message;
```

Remove the dummy `_Message` line; do not import `Message` if unused.

Fix the redundant log: print either display hash or note wire order once. Prefer:

```ts
console.log(
  `received block height=${TARGET_HEIGHT} hash=${TARGET_DISPLAY_HASH} txs=${message.payload.transactions.length}`,
);
```

- [ ] **Step 3: Mention in README**

Add under Quick usage or a short Examples section:

```markdown
## Examples

```bash
bun run example:getaddr    # signet: getaddr + headers + one block
bun run example:mainnet    # mainnet DNS seeds → peers → hardcoded recent block
```
```

- [ ] **Step 4: Typecheck**

Run: `bun run typecheck`
Expected: PASS (no errors in examples/)

- [ ] **Step 5: Run unit tests**

Run: `bun test tests/examples/p2p-helpers.test.ts && bun test`
Expected: PASS (full suite green)

- [ ] **Step 6: Commit**

```bash
git add examples/mainnet-fetch-block.ts examples/lib/p2p-helpers.ts package.json README.md
git commit -m "$(cat <<'EOF'
feat: add mainnet DNS peer discovery block-fetch example

EOF
)"
```

---

### Task 5: Manual live mainnet verification

**Files:**
- None required unless the live run exposes a bug

- [ ] **Step 1: Run the example**

Run: `bun run example:mainnet`
Expected (success path):
- Logs bootstrap DNS candidate count
- Completes at least one bootstrap handshake and prints discovered address counts
- Connects to a discovered full+v2 peer
- Prints `received block height=959293 hash=000000000000000000006f1baf68845265f3d55fd8ec79eda8ccd55c295d1bde txs=<n>`
- Exit code 0

If DNS/peers are flaky, retry once. If consistently failing, diagnose:
- Are bootstrap peers v1-only? (expected for some; continue)
- Are discovered peers missing `NODE_P2P_V2`? Loosen logging to print service bits of first 20 addrv2 entries
- Is `getdata` hash byte order wrong? Confirm with `internalHashToDisplay(TARGET_INTERNAL_HASH) === TARGET_DISPLAY_HASH` already tested; if peer returns `notfound` from many peers, double-check inventory type `2` and hash endianness against Bitcoin Core `CInv` conventions (internal byte order)

- [ ] **Step 2: If a bug fix is needed, fix + add regression test + commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
fix: make mainnet example resilient to <specific issue>

EOF
)"
```

- [ ] **Step 3: Final verification**

Run: `bun run check`
Expected: typecheck + unit tests + package smoke PASS

Do **not** put the live mainnet run into CI/`bun test`.

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| DNS seed resolve + bootstrap BIP-324 | 3, 4 |
| version/verack + sendaddrv2 + getaddr | 2, 4 |
| Filter NODE_NETWORK \| NODE_P2P_V2, IPv4/IPv6 only | 1, 4 |
| Second peer getdata hardcoded height/hash | 4 |
| Timeouts, close always, shuffle, retry summary | 4 |
| Unit tests for helpers; live is manual | 1–3, 5 |
| `example:mainnet` script + README | 4 |
| No header sync / verification / v1 fallback | 4 (explicitly omitted) |

## Self-review notes

- No TBD placeholders; concrete height/hash locked.
- Helper signatures are consistent across tasks (`PeerCandidate`, `DnsResolver`, `waitForMessage`).
- `displayHashToInternal` mutates via `bytes.reverse()` on a fresh `hexToBytes` buffer — safe; do not reverse shared constants in place after first use (example assigns once at module load).
