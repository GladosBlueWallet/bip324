export type NetworkName = "mainnet" | "testnet3" | "signet" | "regtest";

export type Network = {
  readonly name: NetworkName;
  /** 4-byte network magic used in BIP-324 HKDF salt and v1 detection. */
  readonly magic: Uint8Array;
  readonly defaultPort: number;
};

function network(name: NetworkName, bytes: number[], defaultPort: number): Network {
  const networkMagic = new Uint8Array(bytes);
  return Object.freeze({
    name,
    get magic() {
      return networkMagic.slice();
    },
    defaultPort,
  });
}

export const Networks: Readonly<Record<NetworkName, Network>> = Object.freeze({
  mainnet: network("mainnet", [0xf9, 0xbe, 0xb4, 0xd9], 8333),
  testnet3: network("testnet3", [0x0b, 0x11, 0x09, 0x07], 18_333),
  signet: network("signet", [0x0a, 0x03, 0xcf, 0x40], 38_333),
  regtest: network("regtest", [0xfa, 0xbf, 0xb5, 0xda], 18_444),
});
