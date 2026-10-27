import type {BitcoinNetworkName} from '../networks'
import type {RequestOptions} from './http'

/** A block of the best chain: its height and its hash (display order). */
export type BlockRef = {readonly height: number; readonly hash: string}

/** What a backend knows about one address: its confirmed totals and its mempool's, as Esplora's `/address` says. */
export type AddressSummary = {
  /** Confirmed transactions that pay or spend from the address. */
  readonly txCount: number
  /** Satoshis its confirmed transactions paid to it. */
  readonly funded: bigint
  /** Satoshis of its coins that confirmed transactions spent. */
  readonly spent: bigint
  /** Mempool transactions that pay or spend from it. */
  readonly mempoolTxCount: number
  readonly mempoolFunded: bigint
  /** Satoshis of its coins (confirmed or not) that mempool transactions spend. */
  readonly mempoolSpent: bigint
}

/** Where a transaction is: in a block of the best chain, or waiting in the mempool. */
export type BackendStatus =
  | {
      readonly confirmed: true
      readonly height: number
      readonly blockHash: string
      /** The block's timestamp, in seconds. */
      readonly blockTime: number
    }
  | {readonly confirmed: false}

export type BackendInput = {
  /** The transaction of the coin it spends, in display order. */
  readonly txid: string
  readonly vout: number
  readonly sequence: number
  /** The address of the coin it spends; `undefined` for a script without one, or a coinbase. */
  readonly address: string | undefined
  /** Satoshis of the coin it spends; `undefined` for a coinbase. */
  readonly value: bigint | undefined
}

export type BackendOutput = {
  /** `undefined` for a script without an address (an `OP_RETURN`, a bare script). */
  readonly address: string | undefined
  readonly value: bigint
}

/** A transaction as a wallet reads it: the coins it spends (with their addresses and values), what it pays, where it is. */
export type BackendTransaction = {
  readonly txid: string
  readonly inputs: readonly BackendInput[]
  readonly outputs: readonly BackendOutput[]
  /** Satoshis; `undefined` when the backend does not know every input's value. 0 for a coinbase. */
  readonly fee: bigint | undefined
  /** Virtual bytes: weight over four, rounded up. */
  readonly vsize: number
  readonly coinbase: boolean
  readonly status: BackendStatus
}

/** A page of an address's history, newest first: its mempool transactions, then confirmed ones. */
export type HistoryPage = {
  readonly transactions: readonly BackendTransaction[]
  /** The cursor for the next page of confirmed transactions, or `undefined` when there is none. */
  readonly next: string | undefined
}

/** Fee rates in satoshis per virtual byte. */
export type FeeEstimates = {
  /** For the next block. */
  readonly fastest: number
  /** For about three blocks. */
  readonly halfHour: number
  /** For about six blocks. */
  readonly hour: number
  /** For a day or so. */
  readonly economy: number
  /** What the backend's node relays at all. */
  readonly minimum: number
  /** Every confirmation target the backend estimates, in blocks: Esplora's `/fee-estimates`. */
  readonly byTarget: Readonly<Record<number, number>>
}

/**
 * Where a sync reads the chain and sends transactions: Esplora (`esploraBackend`), or anything else that answers the
 * same questions (an Electrum server, a Bitcoin Core node with an address index). The backend sees every address the
 * account asks about and is trusted for what it answers: run your own for privacy, and treat balances as its word.
 * Every call takes an `AbortSignal` and fails with a `SyncError`.
 */
export type BitcoinBackend = {
  /** The network it serves, as `@hzblj/crypto-bitcoin` names them (testnet4 is `testnet`). */
  readonly network: BitcoinNetworkName
  /** The tip of the best chain. */
  readonly tip: (options?: RequestOptions) => Promise<BlockRef>
  /** The hash of the best chain's block at `height`, or `undefined` above the tip. */
  readonly blockHash: (height: number, options?: RequestOptions) => Promise<string | undefined>
  readonly addressSummary: (address: string, options?: RequestOptions) => Promise<AddressSummary>
  /** The newest page of the address's history, or the page of confirmed transactions after cursor `after`. */
  readonly addressHistory: (
    address: string,
    options?: RequestOptions & {readonly after?: string}
  ) => Promise<HistoryPage>
  /** A transaction, or `undefined` when the backend does not know it (dropped, replaced, never seen). */
  readonly transaction: (txid: string, options?: RequestOptions) => Promise<BackendTransaction | undefined>
  /** A transaction's raw bytes as hex: what a PSBT carries as an input's previous transaction. */
  readonly transactionHex: (txid: string, options?: RequestOptions) => Promise<string>
  /** Where a transaction is, or `undefined` when the backend does not know it. */
  readonly transactionStatus: (txid: string, options?: RequestOptions) => Promise<BackendStatus | undefined>
  readonly feeEstimates: (options?: RequestOptions) => Promise<FeeEstimates>
  /** Sends a signed transaction (hex) to the network; resolves to its txid. A refusal is `BROADCAST_REJECTED`. */
  readonly broadcast: (hex: string, options?: RequestOptions) => Promise<string>
}
