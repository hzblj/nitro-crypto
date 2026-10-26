import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {solanaAdapter} from '@hzblj/crypto-solana'
import type {AccountOf, ChainsOf, CryptoEngine, EphemeralWallet} from '@hzblj/nitro-crypto'

/** Sepolia's EIP-155 chain id: what every Ethereum transaction this wallet signs is bound to. */
export const SEPOLIA_CHAIN_ID = 11_155_111

/**
 * The wallet's chains: the three published adapters, each configured for its test network. The ids are the plain
 * chain names, because this engine registers nothing else; the debug tab's engine keeps its mainnet adapters apart.
 * Apart from `engine.ts`, so the tests take the same list and accounts without the native module.
 */
export const createWalletAdapters = () =>
  [
    ethereumAdapter({chainId: SEPOLIA_CHAIN_ID, name: 'Ethereum Sepolia'}),
    bitcoinAdapter({name: 'Bitcoin testnet4', network: 'testnet'}),
    solanaAdapter({cluster: 'devnet'}),
  ] as const

type Chains = ChainsOf<ReturnType<typeof createWalletAdapters>>

export type WalletCrypto = CryptoEngine<Chains>
export type ChainId = keyof Chains & string
export type WalletKeys = EphemeralWallet<Chains>
export type ChainAccount<Id extends ChainId> = AccountOf<Chains[Id]>

/** The account the wallet shows on each chain. */
export type WalletAccounts = {readonly [Id in ChainId]: ChainAccount<Id>}

export const CHAIN_IDS = ['ethereum', 'bitcoin', 'solana'] as const satisfies readonly ChainId[]

/**
 * The first account of each chain, at the path its own wallets use, so the same recovery phrase shows the same
 * addresses in MetaMask (`m/44'/60'/0'/0/0`), a BIP-84 Bitcoin wallet (`m/84'/1'/0'/0/0` on a test network) and
 * Phantom (`m/44'/501'/0'/0'`).
 */
export const deriveAccounts = async (keys: WalletKeys): Promise<WalletAccounts> => {
  const [ethereum, bitcoin, solana] = await Promise.all([
    keys.deriveAccount({chain: 'ethereum', index: 0}),
    keys.deriveAccount({chain: 'bitcoin', index: 0}),
    keys.deriveAccount({account: 0, chain: 'solana'}),
  ])

  return {bitcoin, ethereum, solana}
}
