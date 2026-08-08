import assert from "node:assert/strict";

globalThis.TextEncoder = undefined;
globalThis.TextDecoder = undefined;
const { Networks, decodeMessage, encodeMessage, EventSocketDuplex } = await import(
  "../../dist/react-native.js"
);
const { NodeSocketDuplex } = await import("../../dist/node.js");
const main = await import("../../dist/index.js");

assert.equal(Networks.mainnet.defaultPort, 8333);
assert.deepEqual(
  decodeMessage(encodeMessage({ command: "ping", nonce: new Uint8Array(8).fill(7) })),
  { command: "ping", nonce: new Uint8Array(8).fill(7) },
);
const version = {
  command: "version",
  payload: {
    version: 70_016,
    services: 0n,
    timestamp: 0n,
    receiver: { services: 0n, ip: new Uint8Array(16), port: 8333 },
    sender: { services: 0n, ip: new Uint8Array(16), port: 0 },
    nonce: 0n,
    userAgent: "/π/",
    startHeight: 0,
  },
};
assert.deepEqual(decodeMessage(encodeMessage(version)), version);
assert.equal(typeof NodeSocketDuplex, "function");
assert.equal(typeof EventSocketDuplex, "function");
assert.equal(typeof main.EventSocketDuplex, "function");
