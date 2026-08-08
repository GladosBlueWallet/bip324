import { expect, test } from "bun:test";
import { createServer } from "node:net";
import { readExactly } from "../../src/io/read-exactly.ts";
import { connectNodeTcp } from "../../src/node.ts";

test("Node TCP adapter preserves fragmented byte streams", async () => {
  const server = createServer((socket) => {
    socket.on("data", (bytes) => {
      if (typeof bytes === "string") throw new Error("unexpected decoded socket data");
      socket.write(bytes.subarray(0, 1));
      queueMicrotask(() => socket.write(bytes.subarray(1)));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("expected TCP address");
  const duplex = await connectNodeTcp({ host: "127.0.0.1", port: address.port });

  try {
    const sent = new Uint8Array([1, 2, 3, 4]);
    await duplex.write(sent);
    expect(await readExactly(duplex, sent.length)).toEqual(sent);
  } finally {
    await duplex.close();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("Node TCP adapter terminates peers that exceed the hard buffer limit", async () => {
  const server = createServer((socket) => {
    socket.write(new Uint8Array(32));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("expected TCP address");
  const duplex = await connectNodeTcp(
    { host: "127.0.0.1", port: address.port },
    { highWaterMark: 4, maxBufferedBytes: 8 },
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 10));
    await expect(duplex.read(1)).rejects.toThrow("buffer limit");
  } finally {
    await duplex.close();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("connectNodeTcp aborts a stuck connect attempt via signal", async () => {
  // 192.0.2.0/24 is reserved (TEST-NET-1) and never routable, so the SYN is
  // silently dropped and the OS connect() would otherwise hang far longer
  // than any reasonable peer timeout.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("connect timed out")), 50);
  try {
    await expect(
      connectNodeTcp({ host: "192.0.2.1", port: 8333 }, undefined, controller.signal),
    ).rejects.toBeInstanceOf(Error);
  } finally {
    clearTimeout(timer);
  }
});

test("connectNodeTcp rejects immediately when signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort(new Error("already aborted"));
  await expect(
    connectNodeTcp({ host: "192.0.2.1", port: 8333 }, undefined, controller.signal),
  ).rejects.toThrow("already aborted");
});

test("connectNodeTcp rejects invalid adapter options without leaking the socket", async () => {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("expected TCP address");

  await expect(connectNodeTcp(
    { host: "127.0.0.1", port: address.port },
    { highWaterMark: 0, maxBufferedBytes: 8 },
  )).rejects.toThrow("buffer limits");

  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
});
