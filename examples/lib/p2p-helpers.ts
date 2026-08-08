// examples/lib/p2p-helpers.ts
import {
  answerPing,
  bytesToHex,
  completeVersionHandshake,
  hexToBytes,
  type Message,
  type NetworkAddress,
  type NetworkAddressV2,
  type Protocol,
  type VersionHandshakeOptions,
  type VersionHandshakeResult,
} from "../../src/index.ts";

export { answerPing, completeVersionHandshake };
export type { VersionHandshakeOptions, VersionHandshakeResult };

export const NODE_NETWORK = 1n;
export const NODE_P2P_V2 = 2048n;

export type PeerCandidate = {
  host: string;
  port: number;
  services: bigint;
  networkId: number;
  /** addr/addrv2 timestamp (unix seconds), when known. */
  time?: number;
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
      time: address.time,
    };
  }
  if (address.networkId === 2 && address.address.length === 16) {
    const host = ipv6BytesToHost(address.address);
    if (host === "::") return undefined;
    return {
      host,
      port: address.port,
      services: address.services,
      networkId: 2,
      time: address.time,
    };
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
    time: address.time,
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

/**
 * Prefer reachable-looking peers: IPv4 before IPv6, then newer addr timestamps.
 * Gossip lists are mostly dead; ranking beats blind shuffle for a short-lived example.
 */
export function rankPeerCandidates(peers: PeerCandidate[]): PeerCandidate[] {
  return peers.slice().sort((a, b) => {
    if (a.networkId !== b.networkId) return a.networkId - b.networkId;
    return (b.time ?? 0) - (a.time ?? 0);
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
  const v4Peers: PeerCandidate[] = [];
  const v6Peers: PeerCandidate[] = [];
  for (const seed of seeds) {
    try {
      const [v4, v6] = await Promise.all([
        options.resolver.resolve4(seed).catch(() => [] as string[]),
        options.resolver.resolve6(seed).catch(() => [] as string[]),
      ]);
      for (const host of v4) {
        v4Peers.push({ host, port: options.port, services: 0n, networkId: 1 });
      }
      for (const host of v6) {
        v6Peers.push({ host, port: options.port, services: 0n, networkId: 2 });
      }
    } catch {
      // ignore whole-seed failures
    }
  }
  // Prefer IPv4: many IPv6 seed hits refuse immediately or are unreachable from dual-stack hosts.
  return [
    ...shuffleInPlace(v4Peers, options.random),
    ...shuffleInPlace(v6Peers, options.random),
  ];
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
