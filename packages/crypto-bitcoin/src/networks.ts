export type BitcoinNetworkName = 'mainnet' | 'testnet' | 'signet' | 'regtest'

/** What tells one network's addresses from another's. */
export type BitcoinNetwork = {
  readonly name: BitcoinNetworkName
  /** The Bech32 human-readable part of its SegWit addresses. */
  readonly bech32: string
  /** The BIP-44 coin type in its derivation paths: 0 for mainnet, 1 for every test network. */
  readonly coinType: 0 | 1
  /** Base58Check version bytes of its legacy P2PKH and P2SH addresses. */
  readonly pubKeyHash: number
  readonly scriptHash: number
}

export const NETWORKS: Readonly<Record<BitcoinNetworkName, BitcoinNetwork>> = Object.freeze({
  mainnet: {bech32: 'bc', coinType: 0, name: 'mainnet', pubKeyHash: 0x00, scriptHash: 0x05},
  regtest: {bech32: 'bcrt', coinType: 1, name: 'regtest', pubKeyHash: 0x6f, scriptHash: 0xc4},
  signet: {bech32: 'tb', coinType: 1, name: 'signet', pubKeyHash: 0x6f, scriptHash: 0xc4},
  testnet: {bech32: 'tb', coinType: 1, name: 'testnet', pubKeyHash: 0x6f, scriptHash: 0xc4},
})
