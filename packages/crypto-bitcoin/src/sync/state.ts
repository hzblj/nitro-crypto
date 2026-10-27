import {MAX_MONEY} from '../transaction'
import type {AddressSummary, BackendInput, BackendOutput, BlockRef} from './backend'
import {SyncError} from './errors'

/** A transaction as the sync keeps it: what the backend said, where it is, and when this device first saw it. */
export type StoredTransaction = {
  readonly txid: string
  readonly inputs: readonly BackendInput[]
  readonly outputs: readonly BackendOutput[]
  readonly fee: bigint | undefined
  readonly vsize: number
  readonly coinbase: boolean
  /** The block it is in, or `undefined` while it waits in the mempool. */
  readonly block: {readonly height: number; readonly hash: string; readonly time: number} | undefined
  /** Milliseconds, this device's clock: when a sync first saw it unconfirmed, or broadcast it. */
  readonly firstSeen: number | undefined
  /** Milliseconds: when it was broadcast through this sync, until the backend lists it. */
  readonly broadcastAt: number | undefined
}

export type SyncState = {
  readonly tip: BlockRef | undefined
  readonly syncedAt: number | undefined
  /**
   * What the backend last said about each address with history, by `change/index`. `null` when its history did not
   * add up to it, so the next sync reads that address again.
   */
  readonly summaries: ReadonlyMap<string, AddressSummary | null>
  readonly transactions: ReadonlyMap<string, StoredTransaction>
}

export const EMPTY_STATE: SyncState = Object.freeze({
  summaries: new Map(),
  syncedAt: undefined,
  tip: undefined,
  transactions: new Map(),
})

export const addressKey = (change: 0 | 1, index: number) => `${change}/${index}`

export const parseAddressKey = (key: string): {readonly change: 0 | 1; readonly index: number} => {
  const [change, index] = key.split('/').map(Number)

  return {change: change === 1 ? 1 : 0, index: index ?? 0}
}

/** Satoshis as decimal text: JSON has no bigint. */
type Amount = string

export type SnapshotSummary = {
  readonly txCount: number
  readonly funded: Amount
  readonly spent: Amount
  readonly mempoolTxCount: number
  readonly mempoolFunded: Amount
  readonly mempoolSpent: Amount
}

export type SnapshotAddress = {
  readonly change: 0 | 1
  readonly index: number
  /** What the backend last said about it, or `null` when the next sync should read it again. */
  readonly summary: SnapshotSummary | null
}

export type SnapshotTransaction = {
  readonly txid: string
  readonly inputs: readonly {
    readonly txid: string
    readonly vout: number
    readonly sequence: number
    readonly address: string | null
    readonly value: Amount | null
  }[]
  readonly outputs: readonly {readonly address: string | null; readonly value: Amount}[]
  readonly fee: Amount | null
  readonly vsize: number
  readonly coinbase: boolean
  readonly block: {readonly height: number; readonly hash: string; readonly time: number} | null
  readonly firstSeen: number | null
  readonly broadcastAt: number | null
}

/**
 * An account's sync state as plain JSON (`bigint`s as decimal strings, no `undefined`): persist it (MMKV,
 * AsyncStorage, a file) and pass it back as `snapshot` to resume. It holds what the backend said, never an address
 * the app shows or pays to: those are always derived again from the key.
 */
export type SyncSnapshot = {
  readonly version: 1
  /** The account and network it belongs to: `p2wpkh:testnet:<key>`, or `address:testnet:<address>`. */
  readonly account: string
  readonly tip: BlockRef | null
  /** Milliseconds, when it was last synchronized. */
  readonly syncedAt: number | null
  readonly addresses: readonly SnapshotAddress[]
  readonly transactions: readonly SnapshotTransaction[]
}

const amount = (value: bigint): Amount => value.toString()

const optional = <T>(value: T | undefined): T | null => (value === undefined ? null : value)

export const toSnapshot = (state: SyncState, account: string): SyncSnapshot => ({
  account,
  addresses: [...state.summaries].map(([key, summary]) => ({
    ...parseAddressKey(key),
    summary: summary && {
      funded: amount(summary.funded),
      mempoolFunded: amount(summary.mempoolFunded),
      mempoolSpent: amount(summary.mempoolSpent),
      mempoolTxCount: summary.mempoolTxCount,
      spent: amount(summary.spent),
      txCount: summary.txCount,
    },
  })),
  syncedAt: optional(state.syncedAt),
  tip: state.tip ? {hash: state.tip.hash, height: state.tip.height} : null,
  transactions: [...state.transactions.values()].map(transaction => ({
    block: transaction.block ? {...transaction.block} : null,
    broadcastAt: optional(transaction.broadcastAt),
    coinbase: transaction.coinbase,
    fee: transaction.fee === undefined ? null : amount(transaction.fee),
    firstSeen: optional(transaction.firstSeen),
    inputs: transaction.inputs.map(input => ({
      address: optional(input.address),
      sequence: input.sequence,
      txid: input.txid,
      value: input.value === undefined ? null : amount(input.value),
      vout: input.vout,
    })),
    outputs: transaction.outputs.map(output => ({address: optional(output.address), value: amount(output.value)})),
    txid: transaction.txid,
    vsize: transaction.vsize,
  })),
  version: 1,
})

/** Far beyond any wallet's history, and a bound on what a corrupted snapshot makes this read. */
const MAX_ITEMS = 100_000
const HASH = /^[0-9a-f]{64}$/
const DIGITS = /^(0|[1-9][0-9]{0,15})$/

const broken = (what: string) => new SyncError('INVALID_SNAPSHOT', `The snapshot's ${what} is not valid.`)

const object = (value: unknown, what: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw broken(what)
  }

  return value as Record<string, unknown>
}

const array = (value: unknown, what: string): readonly unknown[] => {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw broken(what)
  }

  return value
}

const integer = (value: unknown, what: string, max = Number.MAX_SAFE_INTEGER): number => {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > max) {
    throw broken(what)
  }

  return value
}

const sats = (value: unknown, what: string): bigint => {
  if (typeof value !== 'string' || !DIGITS.test(value) || BigInt(value) > MAX_MONEY) {
    throw broken(what)
  }

  return BigInt(value)
}

const hash = (value: unknown, what: string): string => {
  if (typeof value !== 'string' || !HASH.test(value)) {
    throw broken(what)
  }

  return value
}

const nullable = <T>(value: unknown, read: (value: unknown) => T): T | undefined =>
  value === null ? undefined : read(value)

const address = (value: unknown): string | undefined =>
  nullable(value, text => {
    if (typeof text !== 'string' || text.length === 0 || text.length > 100) {
      throw broken('address')
    }

    return text
  })

const block = (value: unknown) =>
  nullable(value, raw => {
    const entry = object(raw, 'block')

    return Object.freeze({
      hash: hash(entry.hash, 'block hash'),
      height: integer(entry.height, 'block height'),
      time: integer(entry.time, 'block time'),
    })
  })

const readSummary = (value: unknown): AddressSummary => {
  const summary = object(value, 'address summary')

  return Object.freeze({
    funded: sats(summary.funded, 'funded sum'),
    mempoolFunded: sats(summary.mempoolFunded, 'mempool funded sum'),
    mempoolSpent: sats(summary.mempoolSpent, 'mempool spent sum'),
    mempoolTxCount: integer(summary.mempoolTxCount, 'mempool count'),
    spent: sats(summary.spent, 'spent sum'),
    txCount: integer(summary.txCount, 'transaction count'),
  })
}

const readTransaction = (value: unknown): StoredTransaction => {
  const transaction = object(value, 'transaction')
  const inputs = array(transaction.inputs, 'inputs').map(raw => {
    const input = object(raw, 'input')

    return Object.freeze({
      address: address(input.address),
      sequence: integer(input.sequence, 'input sequence', 0xffffffff),
      txid: hash(input.txid, 'input txid'),
      value: nullable(input.value, raw => sats(raw, 'input value')),
      vout: integer(input.vout, 'input index', 0xffffffff),
    })
  })
  const outputs = array(transaction.outputs, 'outputs').map(raw => {
    const output = object(raw, 'output')

    return Object.freeze({address: address(output.address), value: sats(output.value, 'output value')})
  })

  if (typeof transaction.coinbase !== 'boolean' || inputs.length === 0 || outputs.length === 0) {
    throw broken('transaction')
  }

  return Object.freeze({
    block: block(transaction.block),
    broadcastAt: nullable(transaction.broadcastAt, raw => integer(raw, 'broadcast time')),
    coinbase: transaction.coinbase,
    fee: nullable(transaction.fee, raw => sats(raw, 'fee')),
    firstSeen: nullable(transaction.firstSeen, raw => integer(raw, 'first seen')),
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    txid: hash(transaction.txid, 'txid'),
    vsize: integer(transaction.vsize, 'vsize'),
  })
}

/**
 * The state a snapshot holds, read strictly: `INVALID_SNAPSHOT` for anything this version did not write,
 * `SNAPSHOT_MISMATCH` for another account's or network's.
 */
export const fromSnapshot = (value: unknown, account: string): SyncState => {
  const snapshot = object(value, 'root')

  if (snapshot.version !== 1) {
    throw new SyncError('INVALID_SNAPSHOT', 'The snapshot is of a version this package does not read.')
  }

  if (snapshot.account !== account) {
    throw new SyncError('SNAPSHOT_MISMATCH')
  }

  const summaries = new Map<string, AddressSummary | null>()

  for (const raw of array(snapshot.addresses, 'addresses')) {
    const entry = object(raw, 'address')
    const change = entry.change

    if (change !== 0 && change !== 1) {
      throw broken('address branch')
    }

    const key = addressKey(change, integer(entry.index, 'address index', 0x7fffffff))

    if (summaries.has(key)) {
      throw broken('address list')
    }

    summaries.set(key, entry.summary === null ? null : readSummary(entry.summary))
  }

  const transactions = new Map<string, StoredTransaction>()

  for (const raw of array(snapshot.transactions, 'transactions')) {
    const transaction = readTransaction(raw)

    if (transactions.has(transaction.txid)) {
      throw broken('transaction list')
    }

    transactions.set(transaction.txid, transaction)
  }

  const tip = nullable(snapshot.tip, raw => {
    const entry = object(raw, 'tip')

    return Object.freeze({hash: hash(entry.hash, 'tip hash'), height: integer(entry.height, 'tip height')})
  })

  return Object.freeze({
    summaries,
    syncedAt: nullable(snapshot.syncedAt, raw => integer(raw, 'sync time')),
    tip,
    transactions,
  })
}
