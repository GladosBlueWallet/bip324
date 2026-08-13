import assert from "node:assert/strict";

const { Networks, decodeMessage, encodeMessage, EventSocketDuplex } = await import(
  "../../src/index.ts"
);
const { NodeSocketDuplex } = await import("../../src/node.ts");
const rn = await import("../../src/react-native.ts");
const pkg = await import("bip324");
const pkgNode = await import("bip324/node");

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
    relay: true,
  },
};
assert.deepEqual(decodeMessage(encodeMessage(version)), version);
assert.equal(typeof NodeSocketDuplex, "function");
assert.equal(typeof EventSocketDuplex, "function");
assert.equal(typeof rn.EventSocketDuplex, "function");
assert.equal(typeof pkg.EventSocketDuplex, "function");
assert.equal(typeof pkgNode.NodeSocketDuplex, "function");
assert.equal(pkg.Networks.mainnet.defaultPort, 8333);
