import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { bytesToHex } from "../../src/crypto/bytes.ts";
import { ellswiftDecode, ellswiftEcdhXonly } from "../../src/crypto/ellswift.ts";
import { deriveKeyMaterial, deriveSessionKeys } from "../../src/crypto/session-keys.ts";
import { v2Ecdh } from "../../src/crypto/v2-ecdh.ts";
import { Networks } from "../../src/networks/networks.ts";
import { decodePacket } from "../../src/packet/decode.ts";
import { encodePacket } from "../../src/packet/encode.ts";
import { hexToBytes, parseCsv } from "../helpers/csv.ts";

const MAGIC = Networks.mainnet.magic;

describe("BIP-324 packet_encoding vectors", () => {
  const rows = parseCsv(
    join(import.meta.dir, "../../testdata/bip324/packet_encoding_test_vectors.csv"),
  );

  for (const row of rows) {
    test(`idx=${row.in_idx} keys + ciphertext`, () => {
      const priv = hexToBytes(row.in_priv_ours!);
      const ours = hexToBytes(row.in_ellswift_ours!);
      const theirs = hexToBytes(row.in_ellswift_theirs!);
      const initiating = row.in_initiating === "1";

      expect(bytesToHex(ellswiftDecode(ours))).toBe(row.mid_x_ours!);
      expect(bytesToHex(ellswiftDecode(theirs))).toBe(row.mid_x_theirs!);
      expect(bytesToHex(ellswiftEcdhXonly(theirs, priv))).toBe(row.mid_x_shared!);

      const secret = v2Ecdh(priv, theirs, ours, initiating);
      expect(bytesToHex(secret)).toBe(row.mid_shared_secret!);

      const keys = deriveKeyMaterial(secret, MAGIC);
      expect(bytesToHex(keys.initiatorL)).toBe(row.mid_initiator_l!);
      expect(bytesToHex(keys.initiatorP)).toBe(row.mid_initiator_p!);
      expect(bytesToHex(keys.responderL)).toBe(row.mid_responder_l!);
      expect(bytesToHex(keys.responderP)).toBe(row.mid_responder_p!);
      expect(bytesToHex(keys.sessionId)).toBe(row.out_session_id!);

      const session = deriveSessionKeys(secret, MAGIC, initiating);
      expect(bytesToHex(session.sessionId)).toBe(row.out_session_id!);
      expect(bytesToHex(session.sendGarbageTerminator)).toBe(row.mid_send_garbage_terminator!);
      expect(bytesToHex(session.recvGarbageTerminator)).toBe(row.mid_recv_garbage_terminator!);

      // Advance ciphers with in_idx empty packets (matches BIP run_test_vectors.py)
      const prior = Number(row.in_idx);
      for (let i = 0; i < prior; i++) {
        encodePacket(session, new Uint8Array(0));
      }

      const unit = hexToBytes(row.in_contents!);
      const multiply = Number(row.in_multiply);
      const contents = new Uint8Array(unit.length * multiply);
      for (let i = 0; i < multiply; i++) contents.set(unit, i * unit.length);

      const aad = row.in_aad ? hexToBytes(row.in_aad) : new Uint8Array(0);
      const ignore = row.in_ignore === "1";
      const ciphertext = encodePacket(session, contents, { aad, ignore });

      if (row.out_ciphertext) {
        expect(bytesToHex(ciphertext)).toBe(row.out_ciphertext);
      }
      if (row.out_ciphertext_endswith) {
        expect(bytesToHex(ciphertext).endsWith(row.out_ciphertext_endswith)).toBe(true);
      }
    });

    if (row.out_ciphertext && row.in_ignore !== "1") {
      test(`idx=${row.in_idx} independently decrypts official ciphertext`, async () => {
        const priv = hexToBytes(row.in_priv_ours!);
        const ours = hexToBytes(row.in_ellswift_ours!);
        const theirs = hexToBytes(row.in_ellswift_theirs!);
        const initiating = row.in_initiating === "1";
        const secret = v2Ecdh(priv, theirs, ours, initiating);
        const sender = deriveSessionKeys(secret, MAGIC, initiating);
        const receiver = deriveSessionKeys(secret, MAGIC, !initiating);
        for (let i = 0; i < Number(row.in_idx); i++) {
          const prior = encodePacket(sender, new Uint8Array(0));
          let priorOffset = 0;
          await decodePacket(receiver, {
            async read(n) {
              const chunk = prior.slice(priorOffset, priorOffset + n);
              priorOffset += chunk.length;
              return chunk;
            },
          });
        }
        const packet = hexToBytes(row.out_ciphertext!);
        let offset = 0;
        const contents = await decodePacket(
          receiver,
          {
            async read(n) {
              const chunk = packet.slice(offset, offset + Math.min(n, 7));
              offset += chunk.length;
              return chunk;
            },
          },
          { aad: row.in_aad ? hexToBytes(row.in_aad) : new Uint8Array(0) },
        );
        const unit = hexToBytes(row.in_contents!);
        const expected = new Uint8Array(unit.length * Number(row.in_multiply));
        for (let i = 0; i < Number(row.in_multiply); i++) expected.set(unit, i * unit.length);
        expect(contents).toEqual(expected);
      });
    }
  }
});
