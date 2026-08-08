import { concatBytes } from "./bytes.ts";
import { ellswiftEcdhXonly } from "./ellswift.ts";
import { taggedHash } from "./hash.ts";

/**
 * BIP-324 shared secret from ephemeral keys.
 * Matches reference.py `v2_ecdh`.
 */
export function v2Ecdh(
  priv: Uint8Array,
  ellswiftTheirs: Uint8Array,
  ellswiftOurs: Uint8Array,
  initiating: boolean,
): Uint8Array {
  const ecdhPointX = ellswiftEcdhXonly(ellswiftTheirs, priv);
  const ordered = initiating
    ? concatBytes(ellswiftOurs, ellswiftTheirs, ecdhPointX)
    : concatBytes(ellswiftTheirs, ellswiftOurs, ecdhPointX);
  return taggedHash("bip324_ellswift_xonly_ecdh", ordered);
}
