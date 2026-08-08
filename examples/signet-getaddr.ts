import {
  bytesToHex,
  hexToBytes,
  Networks,
  Protocol,
  type Message,
  type NetworkAddressV2,
  encodeBlockHeader,
} from "../src/index.ts";
import { connectNodeTcp } from "../src/node.ts";
import { sha256 } from "@noble/hashes/sha2.js";

const network = Networks.signet;
const host = process.env.BITCOIN_HOST ?? "seed.signet.bitcoin.sprovoost.nl";
const port = Number(process.env.BITCOIN_PORT ?? network.defaultPort);
const duplex = await connectNodeTcp({ host, port });
const timeout = setTimeout(() => void duplex.close(), 20_000);

try {
  const protocol = await Protocol.connect(duplex, { role: "initiator", network });
  const random = crypto.getRandomValues(new Uint8Array(8));
  const nonce = new DataView(random.buffer).getBigUint64(0, true);
  await protocol.writeMessage({
    command: "version",
    payload: {
      version: 70_016,
      services: 0n,
      timestamp: BigInt(Math.floor(Date.now() / 1_000)),
      receiver: { services: 0n, ip: new Uint8Array(16), port },
      sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
      nonce,
      userAgent: "/bip324-ts:0.0.1/",
      startHeight: 0,
      relay: false,
    },
  });

  let receivedVersion = false;
  let receivedVerack = false;
  while (!receivedVersion || !receivedVerack) {
    const message = await protocol.readMessage();
    if (message.command === "version") {
      receivedVersion = true;
      await protocol.writeMessage({
        command: "opaque",
        type: { kind: "long", command: "sendaddrv2" },
        payload: new Uint8Array(0),
      });
      await protocol.writeMessage({ command: "verack" });
    } else if (message.command === "verack") {
      receivedVerack = true;
    } else {
      await answerPing(protocol, message);
    }
  }

  await protocol.writeMessage({ command: "getaddr" });
  for (;;) {
    const message = await protocol.readMessage();
    if (message.command === "addr") {
      console.log(`received ${message.payload.addresses.length} v1 addresses`);
      for (const address of message.payload.addresses.slice(0, 20)) {
        console.log(`${bytesToHex(address.ip)}:${address.port} services=${address.services}`);
      }
      break;
    }
    if (message.command === "addrv2") {
      console.log(`received ${message.payload.addresses.length} addrv2 addresses`);
      for (const address of message.payload.addresses.slice(0, 20)) printAddrV2(address);
      break;
    }
    await answerPing(protocol, message);
  }

  // Hashes in Bitcoin P2P payloads use internal (little-endian display) byte order.
  const signetGenesis = hexToBytes(
    "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000",
  );
  await protocol.writeMessage({
    command: "getheaders",
    payload: {
      version: 70_016,
      locatorHashes: [signetGenesis],
      stopHash: new Uint8Array(32),
    },
  });
  let newestHeader;
  for (;;) {
    const message = await protocol.readMessage();
    if (message.command === "headers") {
      console.log(`received ${message.payload.headers.length} block headers`);
      newestHeader = message.payload.headers.at(-1);
      break;
    }
    await answerPing(protocol, message);
  }
  if (newestHeader) {
    const firstHash = sha256(encodeBlockHeader(newestHeader));
    const blockHash = sha256(firstHash);
    firstHash.fill(0);
    await protocol.writeMessage({
      command: "getdata",
      payload: { inventory: [{ type: 2, hash: blockHash }] },
    });
    for (;;) {
      const message = await protocol.readMessage();
      if (message.command === "block") {
        console.log(`received block with ${message.payload.transactions.length} transactions`);
        break;
      }
      if (message.command === "notfound") {
        console.log("peer did not have the requested block");
        break;
      }
      await answerPing(protocol, message);
    }
  }
  await protocol.close();
} finally {
  clearTimeout(timeout);
  await duplex.close();
}

async function answerPing(protocol: Protocol, message: Message): Promise<void> {
  if (message.command === "ping") {
    await protocol.writeMessage({ command: "pong", nonce: message.nonce });
  }
}

function printAddrV2(address: NetworkAddressV2): void {
  console.log(
    `network=${address.networkId} address=${bytesToHex(address.address)}:${address.port}` +
    ` services=${address.services}`,
  );
}
