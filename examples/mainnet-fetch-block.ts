import { promises as dns } from "node:dns";
import packageJson from "../package.json" with { type: "json" };
import { Networks, Protocol, V1DetectedError } from "../src/index.ts";
import { connectNodeTcp } from "../src/node.ts";
import {
  MAINNET_DNS_SEEDS,
  collectAddresses,
  completeVersionHandshake,
  displayHashToInternal,
  filterFullV2Peers,
  rankPeerCandidates,
  resolveSeedPeers,
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
/** TCP connect budget only. Keep short — most gossiped peers are dead. */
const connectTimeoutMs = Number(process.env.CONNECT_TIMEOUT_MS ?? 5_000);
/** Handshake + getaddr/getdata budget after TCP is up. */
const peerTimeoutMs = Number(process.env.PEER_TIMEOUT_MS ?? 20_000);
const overallTimeoutMs = Number(process.env.OVERALL_TIMEOUT_MS ?? 180_000);
const maxBootstrap = Number(process.env.MAX_BOOTSTRAP ?? 16);
const maxDiscovered = Number(process.env.MAX_DISCOVERED ?? 32);

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
    if (!discovered?.length) continue;

    const candidates = rankPeerCandidates(
      filterFullV2Peers(discovered, {
        excludeHost: bootstrap.host,
        excludePort: bootstrap.port,
      }),
    ).slice(0, maxDiscovered);

    console.log(`discovered ${discovered.length} addresses; ${candidates.length} full+v2 candidates`);
    for (const peer of candidates.slice(0, 10)) {
      console.log(
        `  candidate ${peer.host}:${peer.port} services=${peer.services}` +
          (peer.time !== undefined ? ` time=${peer.time}` : ""),
      );
    }

    for (const peer of candidates) {
      discoveredTried++;
      console.log(`peer ${discoveredTried}: ${peer.host}:${peer.port}`);
      if (await tryFetchBlock(peer)) {
        clearTimeout(overallTimer);
        process.exit(0);
      }
    }

    // Gossip peers are often unreachable. A seed peer that just gave us addresses
    // already proved BIP-324 works — fetch the block from it as a fallback.
    console.log(`fallback: fetch block from bootstrap ${bootstrap.host}:${bootstrap.port}`);
    if (await tryFetchBlock(bootstrap)) {
      clearTimeout(overallTimer);
      process.exit(0);
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
      name: packageJson.name,
      version: packageJson.version,
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
        name: packageJson.name,
        version: packageJson.version,
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
  const connectController = new AbortController();
  const connectTimer = setTimeout(() => {
    connectController.abort(new Error(`connect timed out after ${connectTimeoutMs}ms`));
  }, connectTimeoutMs);
  let sessionTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    duplex = await connectNodeTcp(
      { host: peer.host, port: peer.port },
      undefined,
      connectController.signal,
    );
    clearTimeout(connectTimer);
    sessionTimer = setTimeout(() => {
      void duplex?.close();
    }, peerTimeoutMs);
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
    clearTimeout(connectTimer);
    if (sessionTimer) clearTimeout(sessionTimer);
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
