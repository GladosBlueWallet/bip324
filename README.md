# bip324

Isomorphic TypeScript **BIP-324** Bitcoin P2P transport + v2 message codec.

- **Runtime-neutral core** — packet crypto and codecs have no Node/Bun built-ins
- **Injected sockets** — implement `ByteDuplex` for Bun / Node / React Native
- **Pure JS crypto** — `@noble/hashes`, `@noble/ciphers`, ElligatorSwift via `@scure/btc-signer`
- **Typed payloads** — version, addresses, headers, inventory, transactions, and blocks
- **Official vectors** — every case in `testdata/bip324/` executes in the test suite

## Install

```bash
bun install
bun run check
```

## Quick usage

```ts
import { Networks, Protocol, pairedByteDuplexes } from "bip324";

const [a, b] = pairedByteDuplexes();
const [alice, bob] = await Promise.all([
  Protocol.connect(a, { role: "initiator", network: Networks.regtest }),
  Protocol.connect(b, { role: "responder", network: Networks.regtest }),
]);

await alice.writeMessage({ command: "ping", nonce: new Uint8Array(8) });
const msg = await bob.readMessage();
```

Provide your own `ByteDuplex` for real TCP:

```ts
type ByteDuplex = {
  // Return 1..n bytes, or an empty array at EOF.
  read(n: number): Promise<Uint8Array>;
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
};
```

Node and Bun can use the optional TCP adapter:

```ts
import { Networks, Protocol } from "bip324";
import { connectNodeTcp } from "bip324/node";

const duplex = await connectNodeTcp({
  host: "seed.signet.bitcoin.sprovoost.nl",
  port: Networks.signet.defaultPort,
});
const peer = await Protocol.connect(duplex, {
  role: "initiator",
  network: Networks.signet,
});
```

### React Native (`react-native-tcp-socket`)

Do **not** import `bip324/node` in React Native. Wrap a Node-like TCP socket with
`EventSocketDuplex` from the core package (works with
[`react-native-tcp-socket`](https://github.com/Rapsssito/react-native-tcp-socket)):

```ts
import TcpSocket from "react-native-tcp-socket";
import { EventSocketDuplex, Networks, Protocol } from "bip324";
// Install a CSPRNG polyfill at app entry, e.g. react-native-get-random-values

const socket = TcpSocket.createConnection({ host, port }, () => {});
await new Promise<void>((resolve, reject) => {
  socket.once("connect", () => resolve());
  socket.once("error", reject);
});

const duplex = new EventSocketDuplex(socket);
const peer = await Protocol.connect(duplex, {
  role: "initiator",
  network: Networks.mainnet,
});
```

`Protocol.connect` throws `V1DetectedError` without closing the duplex when a
responder detects v1. Lower-level callers can use `performHandshake` to receive
the consumed prefix as a structured `V1HandshakeResult`.

## Examples

```bash
bun run example:getaddr    # signet: getaddr + headers + one block
bun run example:mainnet    # mainnet DNS seeds → peers → hardcoded recent block
```

ElligatorSwift key generation needs a cryptographically secure
`globalThis.crypto.getRandomValues`. Node and modern browsers provide it. React
Native/Hermes applications should install a secure random-values polyfill before
connecting (for example `react-native-get-random-values`), or pass a secure
`createKeyPair` implementation in `Protocol.connect` options. The package's
`react-native` export condition is a self-contained bundle and supplies the
`TextEncoder` needed by the upstream cryptography stack; core decoding does not
require `TextDecoder`.

## Layout

```
src/crypto/      ElligatorSwift, HKDF, FSChaCha20*
src/handshake/   BIP-324 handshake state machine
src/packet/      Packet encode/decode
src/messages/    Strict framing + typed Bitcoin P2P payload codecs
src/session/     Protocol helper
src/io/          ByteDuplex + EventSocketDuplex (runtime-neutral TCP wrap)
src/node.ts      Optional Node/Bun TCP connect helper (`bip324/node`)
testdata/bip324/ Official CSV vectors
```

## Spec / plan

- `docs/superpowers/specs/2026-07-23-bip324-typescript-design.md`
- `docs/superpowers/plans/2026-07-23-bip324-typescript.md`
