import type { Message } from "../messages/codec.ts";
import type { Protocol } from "./protocol.ts";

export type VersionHandshakeOptions = {
  port: number;
  /** Application name from the main app (e.g. package.json `name`). */
  name: string;
  /** Application version from the main app (e.g. package.json `version`). */
  version: string;
  /** Height we advertise in our version message (default 0). */
  startHeight?: number;
  /** Service flags we advertise (default 0n). */
  services?: bigint;
  /**
   * After the peer's version, send `sendaddrv2` before verack.
   * Default true (matches Bitcoin Core peers).
   */
  sendAddrV2?: boolean;
};

export type VersionHandshakeResult = {
  /** Peer's advertised service flags. */
  services: bigint;
  /** Peer's advertised start height. */
  startHeight: number;
};

const MAX_VERSION_HANDSHAKE_MESSAGES = 32;

/** Reply to ping; no-op for other commands. */
export async function answerPing(
  protocol: Protocol,
  message: Message,
): Promise<void> {
  if (message.command === "ping") {
    await protocol.writeMessage({ command: "pong", nonce: message.nonce });
  }
}

/**
 * Bitcoin P2P application handshake (version / verack) on an already-connected
 * BIP-324 `Protocol` session.
 */
export async function completeVersionHandshake(
  protocol: Protocol,
  options: VersionHandshakeOptions,
): Promise<VersionHandshakeResult> {
  const sendAddrV2 = options.sendAddrV2 !== false;
  const random = crypto.getRandomValues(new Uint8Array(8));
  const nonce = new DataView(
    random.buffer,
    random.byteOffset,
    8,
  ).getBigUint64(0, true);

  await protocol.writeMessage({
    command: "version",
    payload: {
      version: 70_016,
      services: options.services ?? 0n,
      timestamp: BigInt(Math.floor(Date.now() / 1_000)),
      receiver: { services: 0n, ip: new Uint8Array(16), port: options.port },
      sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
      nonce,
      userAgent: `/${options.name}:${options.version}/`,
      startHeight: options.startHeight ?? 0,
      relay: false,
    },
  });

  let receivedVersion = false;
  let receivedVerack = false;
  let peerServices = 0n;
  let peerStartHeight = 0;
  let seen = 0;

  while (!receivedVersion || !receivedVerack) {
    if (seen >= MAX_VERSION_HANDSHAKE_MESSAGES) {
      throw new Error("version handshake exceeded message limit");
    }
    seen += 1;
    const message = await protocol.readMessage();
    if (message.command === "version") {
      if (receivedVersion) continue;
      receivedVersion = true;
      peerServices = message.payload.services;
      peerStartHeight = message.payload.startHeight;
      if (sendAddrV2) {
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

  return { services: peerServices, startHeight: peerStartHeight };
}
