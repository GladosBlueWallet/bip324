import type { ByteDuplex } from "./byte-duplex.ts";

/**
 * Minimal EventEmitter-style TCP socket shape (Node `net.Socket`,
 * `react-native-tcp-socket`, and similar).
 *
 * Intentionally duck-typed — no `node:net` import — so React Native hosts can
 * pass sockets from `react-native-tcp-socket` without using `bip324/node`.
 */
export type EventSocket = {
  on(event: "data", cb: (chunk: Uint8Array | string) => void): unknown;
  on(event: "error", cb: (err: Error) => void): unknown;
  on(event: "close", cb: (...args: unknown[]) => void): unknown;
  on(event: "end", cb: (...args: unknown[]) => void): unknown;
  once?(event: "close", cb: (...args: unknown[]) => void): unknown;
  write(
    data: Uint8Array,
    cb?: (err?: Error | null) => void,
  ): boolean | void;
  destroy(err?: Error): void;
  pause?(): void;
  resume?(): void;
  destroyed?: boolean;
};

export type EventSocketDuplexOptions = {
  /** Pause the socket after this many unread bytes. Defaults to 1 MiB. */
  highWaterMark?: number;
  /** Destroy the socket if buffered unread bytes exceed this. Defaults to 20 MiB. */
  maxBufferedBytes?: number;
};

/** ByteDuplex adapter for EventEmitter-style TCP sockets. */
export class EventSocketDuplex implements ByteDuplex {
  readonly #socket: EventSocket;
  #chunks: Uint8Array[] = [];
  #bufferedBytes = 0;
  readonly #highWaterMark: number;
  readonly #maxBufferedBytes: number;
  #paused = false;
  #pending:
    | {
      n: number;
      resolve: (bytes: Uint8Array) => void;
      reject: (error: unknown) => void;
    }
    | undefined;
  #ended = false;
  #error: unknown;
  #closePromise: Promise<void> | undefined;

  constructor(socket: EventSocket, options: EventSocketDuplexOptions = {}) {
    this.#socket = socket;
    this.#highWaterMark = options.highWaterMark ?? 1024 * 1024;
    this.#maxBufferedBytes = options.maxBufferedBytes ?? 20 * 1024 * 1024;
    if (
      !Number.isSafeInteger(this.#highWaterMark) ||
      !Number.isSafeInteger(this.#maxBufferedBytes) ||
      this.#highWaterMark <= 0 ||
      this.#maxBufferedBytes < this.#highWaterMark
    ) {
      throw new RangeError("invalid EventSocket buffer limits");
    }
    socket.on("data", (chunk) => {
      if (this.#error) return;
      const bytes =
        typeof chunk === "string"
          ? new TextEncoder().encode(chunk)
          : new Uint8Array(chunk);
      if (this.#bufferedBytes + bytes.length > this.#maxBufferedBytes) {
        const error = new Error("socket buffer limit exceeded");
        this.#error = error;
        this.#chunks = [];
        this.#bufferedBytes = 0;
        this.#flush();
        socket.destroy(error);
        return;
      }
      this.#chunks.push(bytes);
      this.#bufferedBytes += bytes.length;
      if (
        this.#bufferedBytes >= this.#highWaterMark &&
        typeof socket.pause === "function" &&
        !this.#paused
      ) {
        socket.pause();
        this.#paused = true;
      }
      this.#flush();
    });
    socket.on("end", () => {
      this.#ended = true;
      this.#flush();
    });
    socket.on("close", () => {
      this.#ended = true;
      this.#flush();
    });
    socket.on("error", (error) => {
      this.#error = error;
      this.#flush();
    });
  }

  read(n: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(n) || n <= 0) {
      return Promise.reject(new RangeError(`invalid read length: ${n}`));
    }
    if (this.#pending) {
      return Promise.reject(new Error("concurrent socket reads are not supported"));
    }
    if (this.#error) return Promise.reject(this.#error);
    const available = this.#take(n);
    if (available) return Promise.resolve(available);
    if (this.#ended) return Promise.resolve(new Uint8Array(0));
    return new Promise<Uint8Array>((resolve, reject) => {
      this.#pending = { n, resolve, reject };
    });
  }

  write(bytes: Uint8Array): Promise<void> {
    if (this.#ended || this.#socket.destroyed) {
      return Promise.reject(new Error("cannot write to closed socket"));
    }
    return new Promise<void>((resolve, reject) => {
      this.#socket.write(bytes, (error?: Error | null) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }

  async close(): Promise<void> {
    if (!this.#closePromise) {
      if (this.#socket.destroyed) return;
      this.#closePromise = new Promise<void>((resolve) => {
        const finish = () => resolve();
        if (typeof this.#socket.once === "function") {
          this.#socket.once("close", finish);
        } else {
          this.#socket.on("close", finish);
        }
        this.#socket.destroy();
      });
    }
    await this.#closePromise;
  }

  #flush(): void {
    const pending = this.#pending;
    if (!pending) return;
    if (this.#error) {
      this.#pending = undefined;
      pending.reject(this.#error);
      return;
    }
    const available = this.#take(pending.n);
    if (available) {
      this.#pending = undefined;
      pending.resolve(available);
    } else if (this.#ended) {
      this.#pending = undefined;
      pending.resolve(new Uint8Array(0));
    }
  }

  #take(n: number): Uint8Array | undefined {
    const chunk = this.#chunks[0];
    if (!chunk) return undefined;
    if (chunk.length <= n) {
      this.#chunks.shift();
      this.#bufferedBytes -= chunk.length;
      this.#maybeResume();
      return chunk;
    }
    const result = chunk.slice(0, n);
    this.#chunks[0] = chunk.slice(n);
    this.#bufferedBytes -= result.length;
    this.#maybeResume();
    return result;
  }

  #maybeResume(): void {
    if (
      !this.#ended &&
      !this.#error &&
      this.#paused &&
      this.#bufferedBytes < this.#highWaterMark / 2 &&
      typeof this.#socket.resume === "function"
    ) {
      this.#socket.resume();
      this.#paused = false;
    }
  }
}
