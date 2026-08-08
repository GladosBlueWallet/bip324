# Mainnet Peer Discovery + Block Fetch Example

Status: Draft  
Date: 2026-07-23

## Goal

Add a runnable example that:

1. Resolves Bitcoin mainnet DNS seeds.
2. Opens a BIP-324 connection to a bootstrap peer.
3. Completes Bitcoin P2P handshake (`version` / `verack`) and requests peer addresses.
4. Selects a different discovered peer that advertises full-block service and BIP-324 support.
5. Fetches one hardcoded recent mainnet block by hash from that peer.
6. Prints peer details, target height, and transaction count.

No consensus validation, header synchronization, peer persistence, or v1 transport fallback.

## Approach

**DNS seed → bootstrap peer → discovered full v2 peer → `getdata` for hardcoded height/hash.**

This exercises both discovery and second-hop interoperability. Fetching the block from the bootstrap peer alone would not prove address gossip works end-to-end.

## Architecture

### Files

| Path | Role |
|------|------|
| `examples/mainnet-fetch-block.ts` | Live example entrypoint |
| `examples/lib/p2p-helpers.ts` | Shared handshake, ping handling, address formatting, service filtering |
| `tests/examples/p2p-helpers.test.ts` | Unit tests for pure helpers |
| `package.json` | Add `example:mainnet` script |

The existing `examples/signet-getaddr.ts` may optionally reuse helpers, but that refactor is not required for this work.

### Constants

- Network: `Networks.mainnet`
- DNS seeds: Bitcoin Core mainnet seeds (for example `seed.bitcoin.sipa.be`, `dnsseed.bluematt.me`, `seed.bitcoin.jonasschnelli.ch`, `seed.btc.petertodd.net`, `seed.bitcoin.sprovoost.nl`, `dnsseed.emzy.de`, `seed.bitcoin.wiz.biz`)
- Protocol version: `70016`
- User agent: `/bip324-ts:0.0.1/`
- Target block: hardcoded recent mainnet **height and hash** chosen at implementation time from a known public source; documented in the example comments
- Service bits required for second hop: `NODE_NETWORK` (`1`) and `NODE_P2P_V2` (`2048`)

### Flow

```text
resolve DNS seeds
  -> shuffle candidate addresses
  -> for each bootstrap candidate:
       TCP connect + BIP-324 handshake
       version/verack + sendaddrv2
       getaddr -> collect addr/addrv2
       filter routable IPv4/IPv6 with NODE_NETWORK|NODE_P2P_V2
       exclude bootstrap peer itself
       shuffle discovered peers
       -> for each discovered peer:
            TCP connect + BIP-324 handshake
            version/verack
            getdata(MSG_BLOCK, hardcoded hash)
            wait for block or notfound
            on block: print summary and exit success
            on notfound/timeout/error: close and try next peer
       if no discovered peer succeeds, try next bootstrap
  -> if exhausted: exit with concise failure summary
```

### Address handling

- Prefer `addrv2` when available; accept legacy `addr` otherwise.
- Support IPv4 and IPv6 only for connection attempts.
- Skip Tor / I2P / CJDNS / unknown network IDs.
- Format addresses for logging (dotted IPv4, compressed IPv6).
- Convert BIP-324 / Bitcoin wire address bytes into host strings usable by `connectNodeTcp`.

### Reliability

- Per-peer connection/handshake timeout (default ~15s).
- Overall example timeout (default ~90s).
- Always close failed and successful connections.
- Randomize DNS and discovered candidates.
- Continue across seeds and peers on:
  - TCP failure
  - BIP-324 / v1 detection failure
  - handshake timeout
  - `notfound`
  - decode / protocol errors
- Final failure message summarizes how many bootstrap and discovered peers were tried.

### Out of scope

- Header sync / locator walking to derive the target hash
- Merkle / PoW / consensus verification of the received block
- Storing peers or addresses
- Listening as a server
- Automatic v1 fallback after `V1DetectedError`
- Fetching multiple blocks or inventory-driven catch-up

## Testing

### Automated

Unit-test pure helpers with in-memory fixtures:

- IPv4 / IPv6 address byte ↔ host string conversion
- Service-bit filtering (`NODE_NETWORK`, `NODE_P2P_V2`)
- Exclusion of non-routable / non-IP network IDs
- Candidate shuffle / selection does not return the bootstrap peer
- Displayed block-hash byte-order helper if used

Do not put live mainnet traffic in `bun test`.

### Manual

Run:

```bash
bun run example:mainnet
```

Success criteria:

- At least one bootstrap peer completes BIP-324 + version handshake.
- At least one address list is printed.
- A second peer returns the hardcoded block.
- Example prints height, hash, and transaction count, then exits cleanly.

## Package surface

Add:

```json
"example:mainnet": "bun examples/mainnet-fetch-block.ts"
```

Optionally mention the example briefly in `README.md` under examples / usage. No library API changes are required unless helper extraction reveals a missing export already present in `src/`.
