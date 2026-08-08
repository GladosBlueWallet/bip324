import { destroySession, type CipherSession } from "../crypto/session-keys.ts";
import {
  AuthenticationError,
  ProtocolClosedError,
  V1DetectedError,
} from "../errors.ts";
import {
  performHandshake,
  type HandshakeOptions,
  type Role,
} from "../handshake/handshake.ts";
import type { ByteDuplex } from "../io/byte-duplex.ts";
import { decodeMessage, encodeMessage, type Message } from "../messages/codec.ts";
import type { Network } from "../networks/networks.ts";
import { decodePacket } from "../packet/decode.ts";
import { encodePacket } from "../packet/encode.ts";

export type ProtocolOptions = {
  role: Role;
  network: Network;
  garbage?: Uint8Array;
  createKeyPair?: HandshakeOptions["createKeyPair"];
};

export { AuthenticationError, ProtocolClosedError, V1DetectedError };

/**
 * Thin session helper: BIP-324 handshake + encrypted message I/O over an injected duplex.
 */
export class Protocol {
  #closed = false;
  #sendQueue: Promise<void> = Promise.resolve();
  #recvQueue: Promise<void> = Promise.resolve();
  #closePromise: Promise<void> | undefined;
  readonly #duplex: ByteDuplex;
  readonly #session: CipherSession;

  private constructor(
    duplex: ByteDuplex,
    session: CipherSession,
    readonly role: Role,
  ) {
    this.#duplex = duplex;
    this.#session = session;
  }

  get sessionId(): Uint8Array {
    return this.#session.sessionId.slice();
  }

  get isClosed(): boolean {
    return this.#closed;
  }

  static async connect(duplex: ByteDuplex, opts: ProtocolOptions): Promise<Protocol> {
    try {
      const result = await performHandshake(duplex, opts);
      if (result.transport === "v1") throw new V1DetectedError(result.buffered);
      return new Protocol(duplex, result.session, result.role);
    } catch (error) {
      if (error instanceof V1DetectedError) throw error;
      try {
        await duplex.close();
      } catch {
        // Preserve the protocol/transport error that caused teardown.
      }
      throw error;
    }
  }

  async writeMessage(msg: Message): Promise<void> {
    const contents = encodeMessage(msg);
    return this.#enqueue("send", async () => {
      this.#assertOpen();
      try {
        await this.#duplex.write(encodePacket(this.#session, contents));
      } catch (error) {
        await this.#invalidate();
        throw error;
      }
    });
  }

  async readMessage(): Promise<Message> {
    let result: Message | undefined;
    await this.#enqueue("recv", async () => {
      this.#assertOpen();
      try {
        const contents = await decodePacket(this.#session, this.#duplex);
        result = decodeMessage(contents);
      } catch (error) {
        await this.#invalidate();
        throw error;
      }
    });
    return result!;
  }

  async close(): Promise<void> {
    if (!this.#closePromise) {
      this.#closed = true;
      destroySession(this.#session);
      this.#closePromise = Promise.resolve().then(() => this.#duplex.close());
    }
    await this.#closePromise;
  }

  #assertOpen(): void {
    if (this.#closed) throw new ProtocolClosedError();
  }

  async #invalidate(): Promise<void> {
    if (!this.#closePromise) {
      this.#closed = true;
      destroySession(this.#session);
      this.#closePromise = Promise.resolve().then(() => this.#duplex.close());
    }
    try {
      await this.#closePromise;
    } catch {
      // The triggering error is more useful than a secondary close failure.
    }
  }

  #enqueue(direction: "send" | "recv", operation: () => Promise<void>): Promise<void> {
    const previous = direction === "send" ? this.#sendQueue : this.#recvQueue;
    const next = previous.catch(() => {}).then(operation);
    if (direction === "send") this.#sendQueue = next;
    else this.#recvQueue = next;
    return next;
  }
}
