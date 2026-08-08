# BIP-324 TypeScript Library Design

**Date:** 2026-07-23  
**Status:** Draft (awaiting user review of this document)  
**Package:** `bip324`

## Summary

Build a pure TypeScript, isomorphic BIP-324 implementation: encrypted Bitcoin P2P **transport** plus **v2 application message codec**. Core is sans-I/O. Sockets are injected via a minimal byte duplex. Crypto uses Noble/scure (no WASM). Development is vector-driven and modular.

## Decisions

| Topic | Choice |
|-------|--------|
| Scope | Transport + v2 message codec (not peer pool / Neutrino) |
| Crypto | Pure JS: `@noble/hashes`, `@noble/ciphers`, ElligatorSwift via `@scure/btc-signer` (or vendored if needed) |
| I/O | Sans-I/O core + optional `Protocol` over `ByteDuplex` |
| Layout | Single package, layered folders |
| Test order | BIP CSV vectors first, then implement (TDD) |

## Goals

- Correct BIP-324 handshake, packet encryption, and v2 message framing
- Usable in Bun, Node, browsers, and React Native without Node/Bun builtins in core
- Modular modules for ease of debug and development
- Import and pass official BIP-324 test vectors (plus useful extras from rust-bitcoin / Core)

## Non-goals (v1)

- Peer pool, DNS seeds, connection managers
- BIP-157/158 compact block filters
- Built-in socket implementations (optional `examples/` adapters only)
- WASM / native crypto backends
- Inbound listen server
- Full SPV / Neutrino wallet logic

## Architecture

```
src/
  crypto/       ElligatorSwift ECDH, HKDF, FSChaCha20, FSChaCha20Poly1305
  handshake/    Initiator/responder state machine (pure)
  packet/       Packet encrypt/decrypt (pure)
  messages/     Short message IDs + encode/decode for known commands
  networks/     Network magic / params (mainnet, testnet3, signet, regtest)
  io/           ByteDuplex interface only
  session/      Thin Protocol helper: duplex + handshake + packets
  index.ts      Public exports
testdata/       BIP CSV vectors and any additional fixtures
tests/          Unit tests mirroring src/
examples/       Optional Bun (and later RN) duplex adapters — not core
```

### Layer responsibilities

1. **crypto** — Primitives and BIP-324 key schedule wrappers only. No TCP, no messages.
2. **handshake** — Pure state machine: local keygen → exchange ellswift keys → garbage → terminators → derive session material → version packets once ciphers exist.
3. **packet** — `encodePacket` / `decodePacket` using `FSChaCha20` (length) + `FSChaCha20Poly1305` (payload); decoy/ignore bit; AAD for first packet garbage auth.
4. **messages** — Map short 1-byte IDs ↔ command names; serialize/deserialize typed payloads for v1 message set below; unknown IDs → opaque `{ type, payload }`.
5. **networks** — Magic bytes used in v1 detection prefix and HKDF salt (`bitcoin_v2_shared_secret` ‖ magic).
6. **io** — `ByteDuplex`: `{ read(n): Promise<Uint8Array>, write(bytes): Promise<void>, close(): Promise<void> }`.
7. **session** — Optional `Protocol`: drive handshake over duplex, then encrypt/decrypt application messages. Not required for unit tests.

### Data flow

```
App --> Protocol (optional) --> Handshake / CipherSession (pure)
                 |
                 v
            ByteDuplex <-- adapters (Bun / RN / mock duplex in tests)
```

Unit tests call Handshake + CipherSession + message codec with `Uint8Array` only.

## Public API (sketch)

```ts
// Networks
export type NetworkName = "mainnet" | "testnet3" | "signet" | "regtest";
export const Networks: Record<NetworkName, { magic: Uint8Array; name: NetworkName }>;

// Crypto / session material (as needed for advanced users)
export { ellswiftCreate, v2Ecdh, /* ... */ };

// Handshake
export class Handshake { /* role, feed(bytes), takeSendBuffer(), finish → CipherSession */ }
export type Role = "initiator" | "responder";

// Packets
export function encodePacket(session: CipherSession, contents: Uint8Array, opts?: { aad?: Uint8Array; ignore?: boolean }): Uint8Array;
/** Decrypt one packet from a byte source. Skips decoy packets until a genuine contents buffer is returned. */
export function decodePacket(session: CipherSession, reader: { read(n: number): Promise<Uint8Array> }, opts?: { aad?: Uint8Array }): Promise<Uint8Array>;

// Messages
export type Message =
  | { command: "version"; payload: VersionPayload }
  | { command: "verack" }
  | { command: "ping"; nonce: Uint8Array }
  // ...
  | { command: string; payload: Uint8Array }; // opaque / unknown

export function encodeMessage(msg: Message): Uint8Array; // application contents (pre-packet)
export function decodeMessage(contents: Uint8Array): Message;

// I/O
export interface ByteDuplex {
  read(n: number): Promise<Uint8Array>;
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

// Optional session
export class Protocol {
  static connect(duplex: ByteDuplex, opts: { role: Role; network: NetworkName; garbage?: Uint8Array }): Promise<Protocol>;
  writeMessage(msg: Message): Promise<void>;
  readMessage(): Promise<Message>;
  readonly sessionId: Uint8Array;
  close(): Promise<void>;
}
```

Exact method names may be adjusted during implementation for ergonomics; behavior must match BIP-324.

## Crypto pipeline

Built on BIP-324:

1. **ElligatorSwift** 64-byte public keys (pseudorandom bytestream)
2. **X-only ECDH** + BIP340 tagged hash `bip324_ellswift_xonly_ecdh`
3. **HKDF-SHA256** → `session_id`, `initiator_L/P`, `responder_L/P`, garbage terminators
4. **FSChaCha20** — length field encryption, rekey every 224 packets
5. **FSChaCha20Poly1305** — content AEAD, rekey every 224 packets
6. Handshake garbage (0–4095 bytes) + 16-byte terminators; first encrypted packet AAD = sent garbage
7. Empty transport version packets after handshake

Libraries: `@noble/hashes`, `@noble/ciphers`, ElligatorSwift from `@scure/btc-signer/p2p` (vendoring allowed if the experimental API is unsuitable).

## Message codec (v1 typed set)

Typed encode/decode for:

- `version`, `verack`
- `ping`, `pong`
- `getaddr`, `addr`, `addrv2`
- `getheaders`, `headers`
- `getdata`, `inv`, `notfound`
- `block`, `tx`
- `reject` (optional; decode if encountered)

Other BIP-324 short message type IDs (e.g. compact filters, cmpctblock) decode as opaque payloads until typed parsers are added. Encoding must accept either short ID or long 13-byte form per BIP equivalence rules when receiving.

## Testing

### Vector sources

Import into `testdata/` (retain provenance in a README):

- [BIP-324](https://github.com/bitcoin/bips/tree/master/bip-0324):
  - `ellswift_decode_test_vectors.csv`
  - `xswiftec_inv_test_vectors.csv`
  - `packet_encoding_test_vectors.csv`
  - Align behavior with `reference.py`
- Additional vectors from [rust-bitcoin/bip324](https://github.com/rust-bitcoin/bip324) and Bitcoin Core functional tests if they cover gaps (document source per file)

### Test runner

- `bun test` for local/CI in this repo
- Tests must not import Bun TCP APIs; only `Uint8Array` and mock duplexes
- Mirror layout: `tests/crypto/`, `tests/handshake/`, etc.

### Implementation order (TDD)

1. Scaffold package + testdata + failing vector tests
2. ElligatorSwift / ECDH / HKDF green against vectors
3. FSChaCha20 + FSChaCha20Poly1305 + packet vectors
4. Handshake state machine (initiator + responder, including v1 prefix detection)
5. Message short IDs + typed codecs for listed commands
6. `Protocol` + mock `ByteDuplex` integration tests
7. Optional `examples/bun-tcp.ts` adapter (manual / smoke, not required for unit green)

## Error handling

Typed errors, e.g.:

- `HandshakeError` — terminator not found, v1/wrong-network detection, state violation
- `DecryptError` — AEAD failure
- `ProtocolError` — unexpected EOF, oversized packet
- `MessageDecodeError` — malformed payload

Decrypt/auth failures abort the session (match Core: disconnect).

## Dependencies

**Runtime (core):**

- `@noble/hashes`
- `@noble/ciphers`
- `@scure/btc-signer` (ElligatorSwift / p2p helpers) — or vendored ellswift module

**Dev:**

- `typescript`
- `@types/bun` (or vitest if we switch later)
- No Node-only test deps required for core

**Peer / optional:** none for sockets.

## Examples (non-core)

`examples/bun-tcp.ts` — implement `ByteDuplex` with Bun TCP, run initiator handshake to a signet/testnet peer. Document that RN would use `react-native-tcp-socket` (or similar) the same way.

## Success criteria

- All imported BIP packet/ellswift vectors pass
- Handshake round-trip between two in-process `Protocol` instances over a paired mock duplex
- Tree-shakeable ESM; no `node:` or `bun:` imports under `src/`
- Clear module boundaries: changing packet crypto does not require editing message codecs

## Open items (resolved at plan time, not blockers)

- Whether to vendor ElligatorSwift vs depend on `@scure/btc-signer` experimental API — decide when first ellswift tests are wired (prefer scure if vectors pass)
