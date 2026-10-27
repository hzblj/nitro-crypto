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

/**
 * A page of an address's history: every transaction that pays the address or spends from it, newest first. The first
 * page holds its mempool transactions (Esplora lists up to 50) and then its newest confirmed ones; each later page,
 * asked for with `after`, holds the confirmed ones older than the cursor.
 */
export type HistoryPage = {
  readonly transactions: readonly BackendTransaction[]
  /**
   * The cursor for the next page of older confirmed transactions (Esplora's: the last txid of this one), or
   * `undefined` when there is none. The sync stops paging as soon as the confirmed transactions it knows for the
   * address reach its summary's `txCount`, so a backend may answer every page at once and say `undefined`.
   */
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
 * same questions: an Electrum server through a native socket, a company's own API, a cache in front of another
 * backend. The sync calls nothing else, so a backend is these eleven members and its own idea of how to get them.
 *
 * The contract, for a backend of your own:
 *
 * - **Every call takes `options.signal`** and should stop when it fires (reject with `SyncError('ABORTED')`).
 * - **Every failure is a `SyncError`** with the code that fits (`NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED`,
 *   `BACKEND_ERROR`, `UNREACHABLE`, `INVALID_RESPONSE`, `BROADCAST_REJECTED`): the sync passes them on as they are.
 * - **Unknown is `undefined`, not an error,** for `blockHash`, `transaction` and `transactionStatus`: the sync forgets a
 *   pending transaction the backend no longer knows (dropped or replaced) and rechecks blocks a reorganization moved.
 * - **Summaries and histories agree.** An address's `addressSummary` counts exactly the transactions its history
 *   lists, as Esplora's `chain_stats` and `mempool_stats` do. When they disagree the sync reads the whole history
 *   again, and when that still disagrees it asks again at the next sync: a backend that lags behind itself costs
 *   requests, not correctness.
 * - **Addresses are as the account derives them:** lowercase Bech32 (or Bech32m) for SegWit and Taproot. Inputs and
 *   outputs name their addresses the same way; a script without an address is `undefined`.
 *
 * The backend sees every address the account asks about and is trusted for what it answers: run your own for privacy,
 * and treat balances as its word. Previous transactions (`transactionHex`) are checked against their coins before a
 * PSBT carries them.
 *
 * ```ts
 * const electrum = (socket: ElectrumSocket): BitcoinBackend => ({
 *   network: 'mainnet',
 *   tip: async () => headerToBlockRef(await socket.request('blockchain.headers.subscribe')),
 *   addressSummary: async address => summarize(await socket.request('blockchain.scripthash.get_history', [scripthash(address)])),
 *   // ... blockHash, addressHistory, transaction, transactionHex, transactionStatus, feeEstimates, broadcast
 * })
 * ```
 */
export type BitcoinBackend = {
  /** The network it serves, as `@hzblj/crypto-bitcoin` names them (testnet4 and testnet3 are `testnet`). */
  readonly network: BitcoinNetworkName
  /** The tip of the best chain: its height and hash, consistent with each other. */
  readonly tip: (options?: RequestOptions) => Promise<BlockRef>
  /** The hash of the best chain's block at `height`, or `undefined` above the tip. */
  readonly blockHash: (height: number, options?: RequestOptions) => Promise<string | undefined>
  /** What the address received and spent, confirmed and in the mempool, as Esplora's `/address/:address` counts it. */
  readonly addressSummary: (address: string, options?: RequestOptions) => Promise<AddressSummary>
  /** The newest page of the address's history, or with `after` the confirmed page after that cursor (`HistoryPage`). */
  readonly addressHistory: (
    address: string,
    options?: RequestOptions & {readonly after?: string}
  ) => Promise<HistoryPage>
  /** A transaction, or `undefined` when the backend does not know it (dropped, replaced, never seen). */
  readonly transaction: (txid: string, options?: RequestOptions) => Promise<BackendTransaction | undefined>
  /**
   * A transaction's raw bytes as lowercase hex, witnesses included or not: what a PSBT carries as an input's previous
   * transaction. Checked against the txid it was asked for, so a wrong one fails the PSBT (`INVALID_RESPONSE`).
   */
  readonly transactionHex: (txid: string, options?: RequestOptions) => Promise<string>
  /** Where a transaction is, or `undefined` when the backend does not know it. */
  readonly transactionStatus: (txid: string, options?: RequestOptions) => Promise<BackendStatus | undefined>
  readonly feeEstimates: (options?: RequestOptions) => Promise<FeeEstimates>
  /**
   * Sends a signed transaction (lowercase hex) to the network; resolves to its txid. A node's refusal is
   * `BROADCAST_REJECTED` with its reason; one the node already has may be either (the sync takes "already" as success).
   */
  readonly broadcast: (hex: string, options?: RequestOptions) => Promise<string>
}
