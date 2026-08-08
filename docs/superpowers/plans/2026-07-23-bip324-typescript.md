# BIP-324 TypeScript Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an isomorphic, sans-I/O TypeScript BIP-324 transport + v2 message codec, validated against official BIP CSV vectors.

**Architecture:** Layered single package (`src/crypto`, `handshake`, `packet`, `messages`, `networks`, `io`, `session`). Pure `Uint8Array` APIs; optional `Protocol` over injected `ByteDuplex`. Crypto via `@noble/*` + `@scure/btc-signer` ElligatorSwift.

**Tech Stack:** TypeScript (ESM), Bun test runner, `@noble/hashes`, `@noble/ciphers`, `@scure/btc-signer`.

## Global Constraints

- No `node:` / `bun:` imports under `src/`
- Core is sans-I/O; sockets only in `examples/`
- TDD: failing vector tests before implementation
- Spec: `docs/superpowers/specs/2026-07-23-bip324-typescript-design.md`
- Testdata: `testdata/bip324/*.csv` from bitcoin/bips BIP-324

## File map

| Path | Responsibility |
|------|----------------|
| `src/crypto/bytes.ts` | hex helpers |
| `src/crypto/hash.ts` | taggedHash, hkdfSha256 |
| `src/crypto/ellswift.ts` | decode / ecdh / create wrappers |
| `src/crypto/v2-ecdh.ts` | BIP-324 shared secret |
| `src/crypto/fs-chacha20.ts` | FSChaCha20 |
| `src/crypto/fs-chacha20-poly1305.ts` | FSChaCha20Poly1305 |
| `src/crypto/session-keys.ts` | HKDF key schedule → CipherSession |
| `src/packet/encode.ts` / `decode.ts` | packet framing |
| `src/handshake/handshake.ts` | state machine |
| `src/messages/*` | short IDs + codecs |
| `src/networks/networks.ts` | magics |
| `src/io/byte-duplex.ts` | interface |
| `src/session/protocol.ts` | duplex session |
| `src/index.ts` | exports |
| `tests/**` | unit tests |
| `testdata/bip324/**` | CSV vectors |
| `examples/bun-tcp.ts` | optional Bun adapter |

---

### Task 1: Package scaffold + vector fixtures + CSV loader

**Files:**
- Create: `package.json` scripts, `tsconfig.json` update, `testdata/bip324/README.md`
- Create: `tests/helpers/csv.ts`
- Create: `tests/crypto/ellswift-decode.test.ts` (failing)
- Keep: existing CSV files in `testdata/bip324/`

**Interfaces:**
- Produces: `parseCsv(path): Record<string, string>[]`, `hexToBytes(hex): Uint8Array`

- [ ] **Step 1: Add test script and testdata README**

`package.json` scripts:
```json
{
  "scripts": {
    "test": "bun test",
    "typecheck": "tsc --noEmit"
  }
}
```

`testdata/bip324/README.md`:
```markdown
# BIP-324 test vectors

Source: https://github.com/bitcoin/bips/tree/master/bip-0324

- ellswift_decode_test_vectors.csv
- xswiftec_inv_test_vectors.csv
- packet_encoding_test_vectors.csv
```

- [ ] **Step 2: Write CSV helper + failing ellswift decode test**

```ts
// tests/helpers/csv.ts
import { readFileSync } from "fs";

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("odd hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function parseCsv(path: string): Record<string, string>[] {
  const text = readFileSync(path, "utf8").trim();
  const lines = text.split(/\r?\n/);
  const headers = lines[0]!.split(",");
  return lines.slice(1).map((line) => {
    const cols = line.split(",");
    const row: Record<string, string> = {};
    headers.forEach((h, i) => (row[h] = cols[i] ?? ""));
    return row;
  });
}
```

```ts
// tests/crypto/ellswift-decode.test.ts
import { describe, expect, test } from "bun:test";
import { join } from "path";
import { hexToBytes, parseCsv } from "../helpers/csv.ts";
import { ellswiftDecode } from "../../src/crypto/ellswift.ts";

describe("ellswiftDecode BIP vectors", () => {
  const rows = parseCsv(join(import.meta.dir, "../../testdata/bip324/ellswift_decode_test_vectors.csv"));
  for (const row of rows) {
    test(`ellswift=${row.ellswift?.slice(0, 16)}…`, () => {
      const got = ellswiftDecode(hexToBytes(row.ellswift!));
      expect(Buffer.from(got).toString("hex")).toBe(row.x!);
    });
  }
});
```

- [ ] **Step 3: Run tests — expect FAIL (module missing)**

Run: `bun test tests/crypto/ellswift-decode.test.ts`  
Expected: fail resolving `../../src/crypto/ellswift.ts`

- [ ] **Step 4: Stub `ellswiftDecode` that throws**

```ts
// src/crypto/ellswift.ts
export function ellswiftDecode(_ellswift: Uint8Array): Uint8Array {
  throw new Error("not implemented");
}
```

- [ ] **Step 5: Run tests — expect FAIL (not implemented / wrong values)**

Run: `bun test tests/crypto/ellswift-decode.test.ts`  
Expected: FAIL with "not implemented"

---

### Task 2: ElligatorSwift decode (+ optional xswiftec_inv)

**Files:**
- Modify: `src/crypto/ellswift.ts`
- Create: `tests/crypto/xswiftec-inv.test.ts` (if exporting inv for vectors)

**Interfaces:**
- Produces: `ellswiftDecode(ellswift: Uint8Array): Uint8Array` → 32-byte x-only

- [ ] **Step 1: Implement decode via `@scure/btc-signer` (or port reference.py if scure mismatches)**

```ts
import { elligatorSwift } from "@scure/btc-signer/p2p.js";

export function ellswiftDecode(ellswift: Uint8Array): Uint8Array {
  if (ellswift.length !== 64) throw new Error("ellswift must be 64 bytes");
  return elligatorSwift.decode(ellswift);
}
```

- [ ] **Step 2: Run ellswift decode tests — expect PASS**

Run: `bun test tests/crypto/ellswift-decode.test.ts`  
Expected: all PASS

- [ ] **Step 3: If scure fails vectors, vendor `xswiftec` from BIP `reference.py` into `src/crypto/ellswift.ts` and re-run until green**

---

### Task 3: Tagged hash, HKDF, v2_ecdh, session key schedule

**Files:**
- Create: `src/crypto/hash.ts`, `src/crypto/v2-ecdh.ts`, `src/crypto/session-keys.ts`
- Create: `tests/crypto/packet-encoding-keys.test.ts` (asserts mid_* columns from packet CSV)

**Interfaces:**
- Produces:
  - `taggedHash(tag: string, data: Uint8Array): Uint8Array`
  - `hkdfSha256(ikm, salt, info, length): Uint8Array`
  - `v2Ecdh(priv, ellswiftTheirs, ellswiftOurs, initiating): Uint8Array`
  - `deriveSessionKeys(ecdhSecret, magic, initiating): SessionKeyMaterial`

- [ ] **Step 1: Failing test using packet vector row for mid_shared_secret / keys**

Parse `packet_encoding_test_vectors.csv`; for each row compute `v2Ecdh` and compare to `mid_shared_secret`; derive keys and compare initiator/responder L/P and session_id.

- [ ] **Step 2: Implement with `@noble/hashes` (`hkdf`, `sha256`) matching BIP reference.py**

- [ ] **Step 3: Tests PASS**

---

### Task 4: FSChaCha20 + FSChaCha20Poly1305 + packet encode

**Files:**
- Create: `src/crypto/fs-chacha20.ts`, `src/crypto/fs-chacha20-poly1305.ts`
- Create: `src/packet/encode.ts`
- Create: `tests/crypto/packet-encoding.test.ts`

**Interfaces:**
- Produces:
  - `class FSChaCha20 { encrypt(chunk: Uint8Array): Uint8Array }`
  - `class FSChaCha20Poly1305 { encrypt(aad, pt): Uint8Array; decrypt(aad, ct): Uint8Array | null }`
  - `encodePacket(sendL, sendP, contents, aad?, ignore?): Uint8Array`
  - `class CipherSession` holding send/recv L/P + terminators + sessionId

- [ ] **Step 1: Failing test — for each packet CSV row, build session from keys, encrypt `in_contents` × `in_multiply`, assert ciphertext equals `out_ciphertext` or ends with `out_ciphertext_endswith`**

- [ ] **Step 2: Port FS wrappers from BIP reference.py using `@noble/ciphers/chacha.js` ChaCha20 and ChaCha20-Poly1305**

- [ ] **Step 3: Tests PASS**

---

### Task 5: Packet decode + CipherSession helper

**Files:**
- Create: `src/packet/decode.ts`, `src/crypto/cipher-session.ts`
- Create: `tests/packet/roundtrip.test.ts`

**Interfaces:**
- Produces: `decodePacket(session, read): Promise<Uint8Array>` (skips decoys)

- [ ] **Step 1: Round-trip test encode→decode with mock reader**
- [ ] **Step 2: Implement decode (3-byte length decrypt, AEAD decrypt, ignore bit)**
- [ ] **Step 3: PASS**

---

### Task 6: Handshake state machine (initiator + responder)

**Files:**
- Create: `src/handshake/handshake.ts`, `src/networks/networks.ts`
- Create: `tests/handshake/handshake.test.ts`

**Interfaces:**
- Produces: `Handshake` with `createInitiator`, `createResponder`, `write()`, `read()`, → `CipherSession`
- Networks: mainnet/testnet3/signet/regtest magics

- [ ] **Step 1: In-process initiator↔responder over paired buffers; empty garbage; complete version exchange**
- [ ] **Step 2: Implement per BIP handshake pseudocode (v1 prefix detection on responder)**
- [ ] **Step 3: PASS; session IDs match**

---

### Task 7: Message short IDs + core codecs

**Files:**
- Create: `src/messages/ids.ts`, `src/messages/codec.ts`, `src/messages/version.ts`, …
- Create: `tests/messages/*.test.ts`

**Interfaces:**
- Produces: `encodeMessage(msg): Uint8Array`, `decodeMessage(bytes): Message`

- [ ] **Step 1: Tests for short ID table + version/ping/pong/getheaders round-trips**
- [ ] **Step 2: Implement codecs for typed set from spec**
- [ ] **Step 3: PASS**

---

### Task 8: ByteDuplex + Protocol session

**Files:**
- Create: `src/io/byte-duplex.ts`, `src/session/protocol.ts`, `src/index.ts`
- Create: `tests/session/protocol.test.ts`
- Create: `examples/bun-tcp.ts` (optional smoke)

**Interfaces:**
- Produces: `Protocol.connect(duplex, opts)`, `writeMessage`, `readMessage`

- [ ] **Step 1: Mock duplex pair; two Protocols exchange version + ping/pong**
- [ ] **Step 2: Implement Protocol**
- [ ] **Step 3: Export public API from `src/index.ts`; PASS**

---

### Task 9: Polish

- [ ] Typecheck clean (`bun run typecheck`)
- [ ] README: install, isomorphic note, example usage, vector provenance
- [ ] Ensure no `node:`/`bun:` under `src/` (grep)

## Spec coverage check

| Spec requirement | Task |
|------------------|------|
| Transport + v2 codec | 4–8 |
| Sans-I/O + ByteDuplex | 6, 8 |
| Noble/scure crypto | 2–4 |
| BIP CSV vectors | 1–4 |
| Networks / magic in HKDF | 3, 6 |
| Typed message set | 7 |
| Examples optional | 8 |

## Execution

After plan save: execute inline in this session starting at Task 1 (user approved “go ahead”).
