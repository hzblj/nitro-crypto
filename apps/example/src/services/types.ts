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

/** Everything the wallet asks one chain's network, on top of what its adapter does offline. */
export type ChainService<Id extends ChainId> = {
  readonly holdings: (address: string) => Promise<Holding[]>
  readonly activity: (address: string) => Promise<ActivityItem[]>
  readonly quote: (account: ChainAccount<Id>, request: SendRequest) => Promise<Quote>
  readonly status: (hash: string) => Promise<TransactionStatus>
}
