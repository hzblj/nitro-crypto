import type {ChainId} from '../core'

/** Something the wallet holds: a network's own coin, or a token on it. */
export type Asset = {
  /** `ethereum`, or `ethereum:usdc` for a token. */
  readonly id: string
  readonly chain: ChainId
  readonly symbol: string
  readonly name: string
  readonly decimals: number
  /** The ERC-20 contract or the SPL mint; none for the network's own coin. */
  readonly contract?: string
  /** Its CoinGecko id: testnet coins are priced as their mainnet twins. */
  readonly priceId: string
}

export type Faucet = {readonly label: string; readonly url: string}

export type Network = {
  readonly chain: ChainId
  /** "Ethereum". */
  readonly name: string
  /** The test network: "Sepolia". */
  readonly testnet: string
  readonly curve: string
  /** The service the wallet reads and broadcasts through. */
  readonly endpoint: string
  /** Where its history comes from, when that is not `endpoint`. */
  readonly indexer?: string
  readonly native: Asset
  readonly tokens: readonly Asset[]
  readonly explorer: {readonly address: (address: string) => string; readonly tx: (hash: string) => string}
  readonly faucets: readonly Faucet[]
}

const ethereum: Network = {
  chain: 'ethereum',
  curve: 'secp256k1',
  endpoint: 'https://ethereum-sepolia-rpc.publicnode.com',
  explorer: {
    address: address => `https://sepolia.etherscan.io/address/${address}`,
    tx: hash => `https://sepolia.etherscan.io/tx/${hash}`,
  },
  faucets: [
    {label: 'Google Cloud Sepolia faucet', url: 'https://cloud.google.com/application/web3/faucet/ethereum/sepolia'},
    {label: 'Circle USDC faucet', url: 'https://faucet.circle.com'},
  ],
  indexer: 'https://eth-sepolia.blockscout.com/api/v2',
  name: 'Ethereum',
  native: {chain: 'ethereum', decimals: 18, id: 'ethereum', name: 'Ether', priceId: 'ethereum', symbol: 'ETH'},
  testnet: 'Sepolia',
  tokens: [
    {
      chain: 'ethereum',
      contract: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
      decimals: 6,
      id: 'ethereum:usdc',
      name: 'USD Coin',
      priceId: 'usd-coin',
      symbol: 'USDC',
    },
  ],
}

const bitcoin: Network = {
  chain: 'bitcoin',
  curve: 'secp256k1',
  endpoint: 'https://mempool.space/testnet4/api',
  explorer: {
    address: address => `https://mempool.space/testnet4/address/${address}`,
    tx: txid => `https://mempool.space/testnet4/tx/${txid}`,
  },
  faucets: [
    {label: 'mempool.space testnet4 faucet', url: 'https://mempool.space/testnet4/faucet'},
    {label: 'coinfaucet.eu', url: 'https://coinfaucet.eu/en/btc-testnet4/'},
  ],
  name: 'Bitcoin',
  native: {chain: 'bitcoin', decimals: 8, id: 'bitcoin', name: 'Bitcoin', priceId: 'bitcoin', symbol: 'BTC'},
  testnet: 'testnet4',
  tokens: [],
}

const solana: Network = {
  chain: 'solana',
  curve: 'Ed25519',
  endpoint: 'https://api.devnet.solana.com',
  explorer: {
    address: address => `https://explorer.solana.com/address/${address}?cluster=devnet`,
    tx: signature => `https://explorer.solana.com/tx/${signature}?cluster=devnet`,
  },
  faucets: [
    {label: 'Solana faucet', url: 'https://faucet.solana.com'},
    {label: 'Circle USDC faucet', url: 'https://faucet.circle.com'},
  ],
  name: 'Solana',
  native: {chain: 'solana', decimals: 9, id: 'solana', name: 'Solana', priceId: 'solana', symbol: 'SOL'},
  testnet: 'devnet',
  tokens: [
    {
      chain: 'solana',
      contract: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
      decimals: 6,
      id: 'solana:usdc',
      name: 'USD Coin',
      priceId: 'usd-coin',
      symbol: 'USDC',
    },
  ],
}

export const NETWORKS: {readonly [Id in ChainId]: Network} = {bitcoin, ethereum, solana}

export const assetsOf = (chain: ChainId): readonly Asset[] => [NETWORKS[chain].native, ...NETWORKS[chain].tokens]

export const findAsset = (id: string): Asset | undefined =>
  Object.values(NETWORKS)
    .flatMap(network => [network.native, ...network.tokens])
    .find(asset => asset.id === id)

export const isChainId = (value: unknown): value is ChainId =>
  value === 'ethereum' || value === 'bitcoin' || value === 'solana'
