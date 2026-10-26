import type {UR} from '@hzblj/crypto-airgap'
import type {EthereumAirgapAccount} from '@hzblj/crypto-airgap-ethereum'
import type {SolanaAirgapAccount} from '@hzblj/crypto-airgap-solana'
import type {BitcoinWatchAccount} from '@hzblj/crypto-bitcoin'

import type {Asset} from '../config'
import type {ChainAccount, ChainId} from '../core'

/** An asset and how much of it an address holds, in its smallest unit. */
export type Holding = {readonly asset: Asset; readonly balance: bigint}

export type TransactionStatus = 'pending' | 'confirmed' | 'failed'

/** One movement of one asset, as the wallet's history lists it. */
export type ActivityItem = {
  /** Unique across chains: the chain, the transaction and the asset. */
  readonly id: string
  readonly chain: ChainId
  /** The transaction hash, txid or signature, as its explorer takes it. */
  readonly hash: string
  /** What moved. A token the wallet does not list still has a symbol and decimals. */
  readonly asset: Pick<Asset, 'decimals' | 'symbol'> & {readonly id?: string}
  readonly direction: 'in' | 'out' | 'self'
  /** What the other side got or gave, fee excluded. */
  readonly amount: bigint
  readonly counterparty?: string
  /** Milliseconds; none while it waits in a mempool. */
  readonly timestamp?: number
  readonly status: TransactionStatus
}

export type SendRequest = {
  readonly asset: Asset
  readonly to: string
  /** In the asset's smallest unit; `max` sends everything that leaves enough for the fee. */
  readonly amount: bigint | 'max'
}

/** A transaction built from the network's current state, ready to sign: what the review screen shows. */
export type Quote = {
  /** What the recipient gets. */
  readonly amount: bigint
  /** The network fee, in the network's own coin: the most it can cost. */
  readonly fee: bigint
  /** Facts the review screen lists: nonce, fee rate, inputs. */
  readonly details: readonly {readonly label: string; readonly value: string}[]
  /** Signs it inside the engine and broadcasts it; resolves to the transaction's hash. */
  readonly send: () => Promise<string>
}

/** An account whose key is on an air-gapped signer: what a watch-only wallet builds transactions for. */
export type WatchAccount<Id extends ChainId> = {
  readonly bitcoin: BitcoinWatchAccount
  readonly ethereum: EthereumAirgapAccount
  readonly solana: SolanaAirgapAccount
}[Id]

/** The same transaction as a `Quote`, for a key held elsewhere: a request to show, and its answer to broadcast. */
export type AirgapQuote = Omit<Quote, 'send'> & {
  /** What the signer scans: a PSBT, an ERC-4527 request, or a Solana sign request. */
  readonly request: UR
  /** Checks the signer's answer against the request (its signer verified by the engine) and broadcasts it. */
  readonly complete: (answer: UR) => Promise<string>
}

/** Everything the wallet asks one chain's network, on top of what its adapter does offline. */
export type ChainService<Id extends ChainId> = {
  readonly holdings: (address: string) => Promise<Holding[]>
  readonly activity: (address: string) => Promise<ActivityItem[]>
  readonly quote: (account: ChainAccount<Id>, request: SendRequest) => Promise<Quote>
  readonly airgapQuote: (account: WatchAccount<Id>, request: SendRequest) => Promise<AirgapQuote>
  readonly status: (hash: string) => Promise<TransactionStatus>
}
