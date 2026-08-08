import { expect, test } from "bun:test";
import {
  EventSocketDuplex,
  type EventSocket,
} from "../../src/io/event-socket-duplex.ts";
import { readExactly } from "../../src/io/read-exactly.ts";

type Handler = (...args: unknown[]) => void;

/** Minimal EventEmitter-style socket for adapter unit tests (no real TCP). */
class FakeEventSocket {
  destroyed = false;
  paused = false;
  readonly #handlers = new Map<string, Set<Handler>>();

  on(event: string, cb: Handler): this {
    let set = this.#handlers.get(event);
    if (!set) {
      set = new Set();
      this.#handlers.set(event, set);
    }
    set.add(cb);
    return this;
  }

  once(event: string, cb: Handler): this {
    const wrap: Handler = (...args) => {
      this.#handlers.get(event)?.delete(wrap);
      cb(...args);
    };
    return this.on(event, wrap);
  }

  emit(event: string, ...args: unknown[]): void {
    for (const cb of [...(this.#handlers.get(event) ?? [])]) cb(...args);
  }

  write(_data: Uint8Array, cb?: (err?: Error | null) => void): boolean {
    queueMicrotask(() => cb?.(null));
    return true;
  }

  destroy(err?: Error): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (err) this.emit("error", err);
    this.emit("close");
  }

  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
  }

  pushData(chunk: Uint8Array | string): void {
    this.emit("data", chunk);
  }

  asEventSocket(): EventSocket {
    return this as unknown as EventSocket;
  }
}

test("EventSocketDuplex preserves fragmented reads from a duck-typed socket", async () => {
  const socket = new FakeEventSocket();
  const duplex = new EventSocketDuplex(socket.asEventSocket());

  const readPromise = readExactly(duplex, 4);
  socket.pushData(new Uint8Array([1, 2]));
  queueMicrotask(() => socket.pushData(new Uint8Array([3, 4])));
  expect(await readPromise).toEqual(new Uint8Array([1, 2, 3, 4]));

  await duplex.close();
  expect(socket.destroyed).toBe(true);
});

test("EventSocketDuplex accepts string data chunks", async () => {
  const socket = new FakeEventSocket();
  const duplex = new EventSocketDuplex(socket.asEventSocket());
  socket.pushData("ab");
  expect(await duplex.read(2)).toEqual(new TextEncoder().encode("ab"));
  await duplex.close();
});

test("EventSocketDuplex pauses locally without isPaused()", async () => {
  const socket = new FakeEventSocket();
  const duplex = new EventSocketDuplex(socket.asEventSocket(), {
    highWaterMark: 4,
    maxBufferedBytes: 64,
  });

  socket.pushData(new Uint8Array([1, 2, 3, 4]));
  expect(socket.paused).toBe(true);

  expect(await duplex.read(4)).toEqual(new Uint8Array([1, 2, 3, 4]));
  expect(socket.paused).toBe(false);

  await duplex.close();
});

test("EventSocketDuplex destroys peers that exceed the hard buffer limit", async () => {
  const socket = new FakeEventSocket();
  const duplex = new EventSocketDuplex(socket.asEventSocket(), {
    highWaterMark: 4,
    maxBufferedBytes: 8,
  });

  socket.pushData(new Uint8Array(32));
  await expect(duplex.read(1)).rejects.toThrow("buffer limit");
  expect(socket.destroyed).toBe(true);
});

test("EventSocketDuplex rejects invalid buffer options", () => {
  const socket = new FakeEventSocket();
  expect(
    () =>
      new EventSocketDuplex(socket.asEventSocket(), {
        highWaterMark: 0,
        maxBufferedBytes: 8,
      }),
  ).toThrow("buffer limits");
});

test("EventSocketDuplex write rejects after close", async () => {
  const socket = new FakeEventSocket();
  const duplex = new EventSocketDuplex(socket.asEventSocket());
  await duplex.close();
  await expect(duplex.write(new Uint8Array([1]))).rejects.toThrow(
    "cannot write to closed socket",
  );
});
