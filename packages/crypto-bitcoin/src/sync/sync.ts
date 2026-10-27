import {bytes, type ExtendedPublicKey, hex, isCryptoError} from '@hzblj/nitro-crypto/adapter'

import type {BitcoinAccount, BitcoinWatchAccount} from '../account'
import type {BitcoinChain} from '../adapter'
import {checkPath} from '../path'
import type {
  BitcoinTransactionPlan,
  BitcoinTransactionRequest,
  BitcoinUtxo,
  SignedBitcoinTransaction,
} from '../transaction'
import {
  type AccountAddress,
  type AccountUtxo,
  type AccountView,
  account,
  isUsed,
  outpoint,
  sameSummary,
  summarize,
  touches,
  usage,
} from './accounting'
import type {AddressSummary, BackendTransaction, BitcoinBackend, BlockRef, FeeEstimates} from './backend'
import {isSyncError, SyncError} from './errors'
import {delay, type RequestOptions} from './http'
import {combinePsbts} from './psbt'
import {type ScriptSupport, type ScriptType, scriptSupport} from './script-types'
import {
  addressKey,
  EMPTY_STATE,
  fromSnapshot,
  parseAddressKey,
  type StoredTransaction,
  type SyncSnapshot,
  type SyncState,
  toSnapshot,
} from './state'

/** What the sync follows: an account by its extended public key, one key's address, or an address alone. */
export type SyncSource =
  | {
      /**
       * The account's extended public key: `wallet.extendedPublicKey("m/84'/1'/0'")` for a wallet in the engine, or
       * `parseExtendedKey(text, crypto.hash.sha256).extendedKey` for one a signer shared (xpub, tpub, zpub, vpub).
       * Its receiving (`/0/*`) and change (`/1/*`) addresses are found up to the gap limit.
       */
      readonly extendedKey: ExtendedPublicKey
      /**
       * The key's path from the master key, `m/84'/1'/0'`. Unless stated: BIP-84's (or the script type's) account at
       * the key's own index, on the adapter's network.
       */
      readonly path?: string
      /** The master key's BIP-32 fingerprint (`wallet.fingerprint`, or the signer's): PSBTs need it, a sync does not. */
      readonly fingerprint?: number
      /** `p2wpkh` unless stated. */
      readonly scriptType?: ScriptType
    }
  | {
      /** One key's address, receiving and change alike: an account of the engine, or a watch-only one. */
      readonly account: BitcoinWatchAccount<string>
    }
  | {
      /** An address alone, of any type: its balance and history, and no payments. */
      readonly address: string
    }

export type BitcoinSyncOptions = SyncSource & {
  /** The adapter's chain, `crypto.chains.bitcoin`: addresses, coin selection and PSBTs are its. */
  readonly chain: BitcoinChain<string>
  /** Where the chain is read and transactions sent: `esploraBackend({network})`, or your own. */
  readonly backend: BitcoinBackend
  /** Unused addresses in a row after the last used one before discovery stops, on each branch. 20 unless stated. */
  readonly gapLimit?: number
  /** What `snapshot()` returned before, to resume from: only what can have changed is read again. */
  readonly snapshot?: SyncSnapshot
  /**
   * Milliseconds a transaction broadcast here may stay unknown to the backend (a load-balanced one can lag) before a
   * sync forgets it. Ten minutes unless stated.
   */
  readonly broadcastGraceMs?: number
}

export type SyncOptions = RequestOptions & {
  /** Skip the network when the last sync is younger than this many milliseconds. */
  readonly maxAgeMs?: number
  /** Forget what the state knows and read every address's whole history again. */
  readonly full?: boolean
}

export type PaymentRequest = {
  /** Any address of the network. */
  readonly to: string
  /** Satoshis, or `max` to send every coin selection may spend, less the fee, with no change. */
  readonly amount: bigint | 'max'
  /** Satoshis per virtual byte, more than 0. */
  readonly feeRate: number
  /** Coin control: spend only these coins (each must be an unspent coin of the account). */
  readonly coins?: readonly {readonly txid: string; readonly vout: number}[]
  /**
   * Which unconfirmed coins selection may spend: `own` (the default) the account's own change, `all` any, `none`
   * none. Coinbase outputs wait for 100 confirmations whatever this says.
   */
  readonly unconfirmed?: 'own' | 'all' | 'none'
}

/** A payment from the account, planned and not yet signed: what a review screen shows. */
export type Payment = {
  /** `@hzblj/crypto-bitcoin`'s plan: coins, outputs (the recipient, then change), fee, size. */
  readonly plan: BitcoinTransactionPlan
  /** The coins it spends, with their addresses and paths. */
  readonly inputs: readonly AccountUtxo[]
  /** Where its change goes, when it has a change output. */
  readonly change: AccountAddress | undefined
  /** Satoshis per virtual byte its fee pays, at the estimated size. */
  readonly feeRate: number
  /** The transaction it replaces, for a fee bump. */
  readonly replaces: string | undefined
}

export type PsbtOptions = RequestOptions & {
  /**
   * Add each coin's whole previous transaction (`PSBT_IN_NON_WITNESS_UTXO`), read from the backend, so a signer can
   * check the values it signs: hardware wallets ask for it. On unless `false`.
   */
  readonly previousTransactions?: boolean
}

/** Where a transaction is, as the backend says now. */
export type TransactionStatus =
  | {
      readonly status: 'confirmed'
      readonly confirmations: number
      readonly height: number
      readonly blockHash: string
      readonly blockTime: number
    }
  | {readonly status: 'pending'}
  /** The backend does not know it: not propagated yet, dropped, or replaced. */
  | {readonly status: 'unknown'}

/** A watch-only Bitcoin account kept in sync with a backend. See `createBitcoinSync`. */
export type BitcoinSync = {
  readonly network: BitcoinChain<string>['network']['name']
  /** The script type of its addresses; `undefined` for an address watched alone. */
  readonly scriptType: ScriptType | undefined
  /** The account key's path from the master key (`m/84'/1'/0'`), or the single key's; `undefined` without one. */
  readonly path: string | undefined
  /** The master key's fingerprint PSBTs name, when known. */
  readonly fingerprint: number | undefined
  /** What its snapshots are tied to: the script type, the network and the key (or the address). */
  readonly id: string
  /**
   * Reads what changed since the last sync (or the snapshot) and resolves to the account as it is now. Concurrent
   * calls share one run. A failure leaves the state as it was.
   */
  readonly sync: (options?: SyncOptions) => Promise<AccountView>
  /** The account as of the last sync, or the snapshot: no network. */
  readonly view: () => AccountView
  /** Called with the new view after every change (a sync, a broadcast). Returns the unsubscribe. */
  readonly subscribe: (listener: (view: AccountView) => void) => () => void
  /** The state as plain JSON to persist, and to resume from with `snapshot`. */
  readonly snapshot: () => SyncSnapshot
  /** An address of the account by its branch (0 receiving, 1 change) and index, derived by the engine. */
  readonly addressAt: (change: 0 | 1, index: number) => AccountAddress
  readonly feeEstimates: (options?: RequestOptions) => Promise<FeeEstimates>
  /**
   * Plans a payment from the account's coins: largest first (the adapter's selection), change to the next change
   * address when it is worth an output, every input replaceable (BIP-125). Throws `INSUFFICIENT_FUNDS`,
   * `INVALID_ADDRESS`, `UNKNOWN_COIN` for coin control outside the account's coins, `INVALID_ARGUMENT`.
   */
  readonly createPayment: (request: PaymentRequest) => Payment
  /**
   * A replacement (BIP-125) of the account's own unconfirmed transaction at a higher fee rate: the same coins (or
   * fewer), the same recipient and amount, less change. Throws `FEE_BUMP_UNAVAILABLE` (not pending, not all its
   * coins the account's, more than one recipient, or spent by another pending transaction), `FEE_TOO_LOW` (saying
   * the rate it takes) and `INSUFFICIENT_FUNDS` (its coins cannot pay that fee).
   */
  readonly createFeeBump: (txid: string, request: {readonly feeRate: number}) => Payment
  /**
   * The payment as one PSBT (BIP-174) for the engine or an air-gapped signer: each input's coin and key origin (the
   * master fingerprint and its path), the origin on change, and (unless `previousTransactions: false`) each coin's
   * previous transaction. Needs the master fingerprint (`MISSING_FINGERPRINT`).
   */
  readonly createPsbt: (payment: Payment | BitcoinTransactionPlan, options?: PsbtOptions) => Promise<Uint8Array>
  /**
   * Signs a PSBT with keys the engine holds: every key of this account it names, each derived by `derive` (as
   * `path => wallet.deriveAccount({chain: 'bitcoin', path})`) and checked against the PSBT's (`KEY_MISMATCH`).
   * Signing is agreeing: show what it pays first. Finalize with `chain.finalizePsbt`.
   */
  readonly signPsbt: (
    psbt: Uint8Array,
    derive: (path: string) => Promise<BitcoinAccount<string>>
  ) => Promise<Uint8Array>
  /**
   * Sends a signed transaction (`chain.finalizePsbt`'s, or an account's `signTransaction`) and records it as pending,
   * so the balance and the coins reflect it before the next sync. Resolves to its txid. A node's refusal is
   * `BROADCAST_REJECTED` with its reason; one it already has is a success.
   */
  readonly broadcast: (
    transaction: Pick<SignedBitcoinTransaction, 'hex' | 'txid'>,
    options?: RequestOptions
  ) => Promise<string>
  readonly transactionStatus: (txid: string, options?: RequestOptions) => Promise<TransactionStatus>
}

type Source = {
  readonly id: string
  readonly scriptType: ScriptType | undefined
  readonly path: string | undefined
  readonly fingerprint: number | undefined
  /** The branches discovery walks: both for an account, the receiving one for a single address. */
  readonly single: boolean
  readonly at: (change: 0 | 1, index: number) => AccountAddress
  /** A watch-only account of one of its addresses, which plans payments and writes PSBTs. */
  readonly watch: (address: AccountAddress) => BitcoinWatchAccount<string>
}

const HARDENED = 0x80000000
const MAX_INDEX = 0x7fffffff
const TXID = /^[0-9a-f]{64}$/
const ZERO: AddressSummary = Object.freeze({
  funded: 0n,
  mempoolFunded: 0n,
  mempoolSpent: 0n,
  mempoolTxCount: 0,
  spent: 0n,
  txCount: 0,
})
/** BIP-125's incremental relay fee: a replacement pays at least this much more per vbyte of itself. */
const INCREMENTAL_RELAY_FEE = 1

/** A `CryptoError` of the adapter or the engine, as the sync reports it. */
const fromCrypto = (error: unknown, fallback: SyncError['code'] = 'INVALID_ARGUMENT'): unknown => {
  if (!isCryptoError(error)) {
    return error
  }

  if (error.code === 'INVALID_ADDRESS') {
    return new SyncError('INVALID_ADDRESS', error.message, {cause: error})
  }

  if (error.code === 'UNSUPPORTED') {
    return new SyncError('UNSUPPORTED', error.message, {cause: error})
  }

  if (
    error.code === 'INVALID_ARGUMENT' &&
    /^(Not enough funds|Sending everything leaves|There are no coins)/.test(error.message)
  ) {
    return new SyncError('INSUFFICIENT_FUNDS', error.message, {cause: error})
  }

  return new SyncError(fallback, error.message, {cause: error})
}

const guarded = <T>(run: () => T, fallback?: SyncError['code']): T => {
  try {
    return run()
  } catch (error) {
    throw fromCrypto(error, fallback)
  }
}

const checkTxid = (txid: string) => {
  if (typeof txid !== 'string' || !TXID.test(txid)) {
    throw new SyncError('INVALID_ARGUMENT', 'A txid is 64 lowercase hex digits.')
  }

  return txid
}

const checkFingerprint = (fingerprint: number | undefined) => {
  if (fingerprint !== undefined && (!Number.isInteger(fingerprint) || fingerprint < 0 || fingerprint > 0xffffffff)) {
    throw new SyncError('INVALID_ARGUMENT', 'A fingerprint is a 32-bit unsigned integer.')
  }

  return fingerprint
}

/** The account an extended public key is: its path checked against the key, its two branches derived once. */
const accountSource = (
  chain: BitcoinChain<string>,
  options: Extract<SyncSource, {readonly extendedKey: ExtendedPublicKey}>
): Source => {
  const support: ScriptSupport = scriptSupport(options.scriptType ?? 'p2wpkh')
  const key = options.extendedKey
  const fingerprint = checkFingerprint(options.fingerprint)

  if (
    !(key?.publicKey instanceof Uint8Array) ||
    key.publicKey.length !== 33 ||
    !(key.chainCode instanceof Uint8Array) ||
    key.chainCode.length !== 32
  ) {
    throw new SyncError('INVALID_EXTENDED_KEY', 'An extended public key has a 33-byte key and a 32-byte chain code.')
  }

  if (options.path === undefined && (key.depth !== 3 || key.childNumber < HARDENED)) {
    throw new SyncError('INVALID_ARGUMENT', 'The key is not an account key (depth 3, hardened): pass its path.')
  }

  const path = guarded(
    () => checkPath(options.path ?? `m/${support.purpose}'/${chain.network.coinType}'/${key.childNumber - HARDENED}'`),
    'INVALID_EXTENDED_KEY'
  )
  const steps = path.split('/').slice(1)
  const last = steps[steps.length - 1]

  if (steps.length !== key.depth) {
    throw new SyncError('INVALID_EXTENDED_KEY', 'The extended key is not at the depth its path says.')
  }

  if (last !== undefined && Number.parseInt(last, 10) + (last.endsWith("'") ? HARDENED : 0) !== key.childNumber) {
    throw new SyncError('INVALID_EXTENDED_KEY', 'The extended key is not at the index its path ends with.')
  }

  const derive = (from: ExtendedPublicKey, step: number) =>
    guarded(() => chain.derivePublic(from, `m/${step}`), 'INVALID_EXTENDED_KEY')
  const branches = [derive(key, 0), derive(key, 1)] as const
  const addresses = new Map<string, AccountAddress>()
  const watches = new Map<string, BitcoinWatchAccount<string>>()

  const at = (change: 0 | 1, index: number): AccountAddress => {
    if ((change !== 0 && change !== 1) || !Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
      throw new SyncError('INVALID_ARGUMENT', 'An address is on branch 0 or 1, at an index from 0 to 2^31 - 1.')
    }

    const id = addressKey(change, index)
    let entry = addresses.get(id)

    if (!entry) {
      const {publicKey} = derive(branches[change], index)
      const {address, scriptPubKey} = guarded(() => support.output(chain, publicKey), 'INVALID_EXTENDED_KEY')
      entry = Object.freeze({address, change, index, path: `${path}/${change}/${index}`, publicKey, scriptPubKey})
      addresses.set(id, entry)
    }

    return entry
  }

  return {
    at,
    fingerprint,
    id: `${support.type}:${chain.network.name}:${hex.encode(key.publicKey)}${hex.encode(key.chainCode)}`,
    path,
    scriptType: support.type,
    single: false,
    watch: (address: AccountAddress) => {
      let watch = watches.get(address.address)

      if (!watch) {
        watch = guarded(() =>
          support.watch(chain, {
            fingerprint: fingerprint ?? 0,
            path: address.path ?? '',
            publicKey: address.publicKey ?? new Uint8Array(),
          })
        )
        watches.set(address.address, watch)
      }

      return watch
    },
  }
}

/** One address: of a key whose account is known, or alone. */
const singleSource = (
  chain: BitcoinChain<string>,
  options: Exclude<SyncSource, {readonly extendedKey: ExtendedPublicKey}>
): Source => {
  const watch = 'account' in options ? options.account : undefined
  const text = 'account' in options ? options.account.address : options.address

  if (watch && watch.network !== chain.network.name) {
    throw new SyncError('NETWORK_MISMATCH', 'The account is of another network than the adapter.')
  }

  const validation = guarded(() => chain.validateAddress(text))

  if (!validation.valid) {
    throw new SyncError('INVALID_ADDRESS', validation.reason)
  }

  const entry: AccountAddress = Object.freeze({
    address: validation.normalized,
    change: 0,
    index: 0,
    path: watch?.path,
    publicKey: watch?.publicKey,
    scriptPubKey: validation.scriptPubKey,
  })

  return {
    at: (change: 0 | 1, index: number) => {
      if (change !== 0 || index !== 0) {
        throw new SyncError('INVALID_ARGUMENT', 'A sync of one address has it alone: branch 0, index 0.')
      }

      return entry
    },
    fingerprint: watch?.fingerprint,
    id: `address:${chain.network.name}:${entry.address}`,
    path: watch?.path,
    scriptType: watch ? watch.addressType : undefined,
    single: true,
    watch: () => {
      if (!watch) {
        throw new SyncError('MISSING_KEY')
      }

      return watch
    },
  }
}

const stored = (
  transaction: BackendTransaction,
  previous: StoredTransaction | undefined,
  seen: number,
  broadcastAt?: number
): StoredTransaction =>
  Object.freeze({
    block: transaction.status.confirmed
      ? Object.freeze({
          hash: transaction.status.blockHash,
          height: transaction.status.height,
          time: transaction.status.blockTime,
        })
      : undefined,
    broadcastAt,
    coinbase: transaction.coinbase,
    fee: transaction.fee,
    firstSeen: previous?.firstSeen ?? (transaction.status.confirmed ? undefined : seen),
    inputs: transaction.inputs,
    outputs: transaction.outputs,
    txid: transaction.txid,
    vsize: transaction.vsize,
  })

/** The state with a transaction added, and every pending one it double-spends gone: it replaced them. */
const withTransaction = (state: SyncState, transaction: StoredTransaction): SyncState => {
  const spends = new Set(transaction.inputs.map(input => outpoint(input.txid, input.vout)))
  const transactions = new Map(state.transactions)

  for (const other of state.transactions.values()) {
    if (
      other.txid !== transaction.txid &&
      !other.block &&
      other.inputs.some(input => spends.has(outpoint(input.txid, input.vout)))
    ) {
      transactions.delete(other.txid)
    }
  }

  transactions.set(transaction.txid, transaction)

  return Object.freeze({...state, transactions})
}

/**
 * A watch-only Bitcoin account kept in sync with a backend (Esplora by default): its addresses found from an extended
 * public key up to the gap limit, its coins, balance and history, its next receiving and change addresses, fee
 * estimates, payments as PSBTs for the engine or an air-gapped signer, fee bumps, and broadcasts. No key is held: the
 * engine derives the addresses publicly, and signing is the engine's or the signer's.
 *
 * ```ts
 * const sync = createBitcoinSync({
 *   backend: esploraBackend({network: 'testnet'}),
 *   chain: crypto.chains.bitcoin,
 *   extendedKey: wallet.extendedPublicKey("m/84'/1'/0'"),
 *   fingerprint: wallet.fingerprint,
 *   snapshot: saved, // what sync.snapshot() returned last time, if anything
 * })
 * const {balance, receiveAddress, transactions} = await sync.sync()
 * persist(sync.snapshot())
 * ```
 *
 * The backend sees every address of the account and is trusted for what it says: see the README's privacy notes.
 */
export const createBitcoinSync = (options: BitcoinSyncOptions): BitcoinSync => {
  const {backend, chain} = options

  if (!backend || !chain?.network) {
    throw new SyncError('INVALID_ARGUMENT', 'A sync needs the adapter`s chain and a backend.')
  }

  if (backend.network !== chain.network.name) {
    throw new SyncError(
      'NETWORK_MISMATCH',
      `The backend serves ${backend.network}; the adapter is on ${chain.network.name}.`
    )
  }

  const sources = ['extendedKey', 'account', 'address'].filter(name => name in options)

  if (sources.length !== 1) {
    throw new SyncError('INVALID_ARGUMENT', 'A sync follows one of an extended key, an account or an address.')
  }

  const gapLimit = options.gapLimit ?? 20
  const grace = options.broadcastGraceMs ?? 600_000

  if (!Number.isInteger(gapLimit) || gapLimit < 1 || gapLimit > 1000) {
    throw new SyncError('INVALID_ARGUMENT', 'A gap limit is an integer from 1 to 1000.')
  }

  if (!Number.isFinite(grace) || grace < 0) {
    throw new SyncError('INVALID_ARGUMENT', 'A grace period is a number of milliseconds.')
  }

  const source = 'extendedKey' in options ? accountSource(chain, options) : singleSource(chain, options)
  const byAddress = new Map<string, AccountAddress>()
  const at = (change: 0 | 1, index: number) => {
    const entry = source.at(change, index)
    byAddress.set(entry.address, entry)

    return entry
  }
  const own = (address: string | undefined) => (address === undefined ? undefined : byAddress.get(address))

  let state: SyncState = options.snapshot ? fromSnapshot(options.snapshot, source.id) : EMPTY_STATE
  let running: Promise<AccountView> | undefined
  let cached: {readonly state: SyncState; readonly view: AccountView} | undefined
  const listeners = new Set<(view: AccountView) => void>()

  /** The last used index of each branch the summaries know, every address up to the gap after it derived. */
  const lastUsed = (current: SyncState): [number, number] => {
    const last: [number, number] = [-1, -1]

    for (const [key, summary] of current.summaries) {
      const {change, index} = parseAddressKey(key)

      if (summary === null || isUsed(summary)) {
        last[change] = Math.max(last[change], index)
      }
    }

    if (source.single) {
      at(0, 0)

      return last
    }

    for (const change of [0, 1] as const) {
      for (let index = 0; index <= last[change] + gapLimit; index++) {
        at(change, index)
      }
    }

    // Transactions recorded at broadcast touch addresses the summaries have not heard of yet: their change.
    for (const transaction of current.transactions.values()) {
      for (const entry of [...transaction.inputs, ...transaction.outputs]) {
        const mine = own(entry.address)

        if (mine) {
          last[mine.change] = Math.max(last[mine.change], mine.index)
        }
      }
    }

    return last
  }

  const view = (): AccountView => {
    if (cached?.state === state) {
      return cached.view
    }

    const current = state
    const last = lastUsed(current)
    const {balance, transactions, utxos} = account(current, own)
    const result: AccountView = Object.freeze({
      addresses: usage(current, own, utxos),
      balance,
      changeAddress: source.single ? at(0, 0) : at(1, last[1] + 1),
      receiveAddress: source.single ? at(0, 0) : at(0, last[0] + 1),
      syncedAt: current.syncedAt,
      tip: current.tip,
      transactions,
      utxos,
    })
    cached = {state: current, view: result}

    return result
  }

  const commit = (next: SyncState) => {
    state = next
    const result = view()

    for (const listener of listeners) {
      listener(result)
    }

    return result
  }

  const run = async (signal: AbortSignal | undefined, full: boolean): Promise<AccountView> => {
    const startedAt = Date.now()
    const request = {signal}
    const base = full ? EMPTY_STATE : state
    const transactions = new Map(base.transactions)
    const summaries = new Map(base.summaries)
    const dirty = new Map<string, AccountAddress>()
    const markTouched = (transaction: StoredTransaction) => {
      for (const entry of [...transaction.inputs, ...transaction.outputs]) {
        const mine = own(entry.address)

        if (mine) {
          dirty.set(mine.address, mine)
        }
      }
    }

    lastUsed(base)
    const tip = await backend.tip(request)

    // Reorganizations: walk the blocks of the account's confirmed transactions, newest first, while the backend's
    // best chain has another block at their height. Below the first that agrees, everything does.
    const recheck = new Set<string>()

    if (base.tip?.hash !== tip.hash) {
      const blocks = new Map<string, {readonly height: number; readonly hash: string; readonly txids: string[]}>()

      for (const transaction of transactions.values()) {
        if (transaction.block) {
          const {hash, height} = transaction.block
          const block = blocks.get(hash) ?? {hash, height, txids: []}
          block.txids.push(transaction.txid)
          blocks.set(hash, block)
        }
      }

      for (const block of [...blocks.values()].sort((a, b) => b.height - a.height)) {
        const hash = block.height > tip.height ? undefined : await backend.blockHash(block.height, request)

        if (hash === block.hash) {
          break
        }

        for (const txid of block.txids) {
          recheck.add(txid)
        }
      }
    }

    // Every pending transaction, and every one a reorganization moved: where is it now?
    for (const transaction of transactions.values()) {
      if (!transaction.block) {
        recheck.add(transaction.txid)
      }
    }

    const statuses = await Promise.all(
      [...recheck].map(async txid => [txid, await backend.transactionStatus(txid, request)] as const)
    )

    for (const [txid, status] of statuses) {
      const transaction = transactions.get(txid)

      if (!transaction) {
        continue
      }

      if (status === undefined) {
        // Dropped, replaced, or reorganized away and double-spent: gone, unless it was broadcast here a moment ago.
        if (transaction.broadcastAt === undefined || startedAt - transaction.broadcastAt >= grace) {
          transactions.delete(txid)
          markTouched(transaction)
        }

        continue
      }

      const block = status.confirmed
        ? {hash: status.blockHash, height: status.height, time: status.blockTime}
        : undefined

      if (block?.hash !== transaction.block?.hash) {
        markTouched(transaction)
      }

      transactions.set(
        txid,
        Object.freeze({...transaction, block, broadcastAt: undefined, firstSeen: transaction.firstSeen ?? startedAt})
      )
    }

    // Discovery: every address up to the gap limit past the last used one, on both branches. An address whose
    // summary changed (or that a vanished transaction touched) has its history read again; the others are not.
    for (const change of source.single ? ([0] as const) : ([0, 1] as const)) {
      let last = -1

      for (const [key, summary] of summaries) {
        const position = parseAddressKey(key)

        if (position.change === change && (summary === null || isUsed(summary))) {
          last = Math.max(last, position.index)
        }
      }

      for (let next = 0; next <= (source.single ? 0 : last + gapLimit); ) {
        const end = source.single ? 0 : last + gapLimit
        const window = Array.from({length: end - next + 1}, (_, offset) => at(change, next + offset))
        const answers = await Promise.all(window.map(entry => backend.addressSummary(entry.address, request)))

        answers.forEach((summary, offset) => {
          const entry = window[offset] as AccountAddress
          const key = addressKey(change, entry.index)
          const known = summaries.get(key)

          if (isUsed(summary)) {
            last = Math.max(last, entry.index)
          }

          if (known === undefined ? isUsed(summary) : known === null || !sameSummary(known, summary)) {
            dirty.set(entry.address, entry)
          }

          if (isUsed(summary)) {
            summaries.set(key, summary)
          } else {
            summaries.delete(key)
          }
        })

        next = end + 1
      }
    }

    const confirmedTouching = (address: string) => {
      const found = new Set<string>()

      for (const transaction of transactions.values()) {
        if (transaction.block && touches(transaction, address)) {
          found.add(transaction.txid)
        }
      }

      return found
    }

    const upsert = (transaction: BackendTransaction) => {
      transactions.set(transaction.txid, stored(transaction, transactions.get(transaction.txid), startedAt))
    }

    const readAll = async (entry: AccountAddress) => {
      const all = new Map<string, BackendTransaction>()
      let page = await backend.addressHistory(entry.address, request)

      for (;;) {
        for (const transaction of page.transactions) {
          all.set(transaction.txid, transaction)
        }

        if (!page.next || page.transactions.length === 0) {
          return all
        }

        page = await backend.addressHistory(entry.address, {...request, after: page.next})
      }
    }

    // History: the newest pages of each changed address, until the confirmed transactions known for it reach the
    // count its summary gives. When the history and the summary still disagree, the whole history is read again and
    // anything the backend no longer lists for the address is forgotten.
    await Promise.all(
      [...dirty.values()].map(async entry => {
        const key = addressKey(entry.change, entry.index)
        const expected = summaries.get(key) ?? ZERO
        let page = await backend.addressHistory(entry.address, request)

        for (;;) {
          for (const transaction of page.transactions) {
            upsert(transaction)
          }

          if (!page.next || confirmedTouching(entry.address).size >= expected.txCount) {
            break
          }

          page = await backend.addressHistory(entry.address, {...request, after: page.next})
        }

        if (sameSummary(summarize(transactions.values(), entry.address), expected)) {
          return
        }

        const all = await readAll(entry)

        for (const transaction of [...transactions.values()]) {
          const recent = transaction.broadcastAt !== undefined && startedAt - transaction.broadcastAt < grace

          if (touches(transaction, entry.address) && !all.has(transaction.txid) && !recent) {
            transactions.delete(transaction.txid)
          }
        }

        for (const transaction of all.values()) {
          upsert(transaction)
        }

        // A block or a transaction may have arrived between the summary and the history: ask once more.
        const fresh = await backend.addressSummary(entry.address, request)
        const agrees = sameSummary(summarize(transactions.values(), entry.address), fresh)

        if (isUsed(fresh) || !agrees) {
          summaries.set(key, agrees ? fresh : null)
        } else {
          summaries.delete(key)
        }
      })
    )

    if (full) {
      for (const [txid, transaction] of transactions) {
        const firstSeen = state.transactions.get(txid)?.firstSeen

        if (firstSeen !== undefined && transaction.firstSeen !== firstSeen) {
          transactions.set(txid, Object.freeze({...transaction, firstSeen}))
        }
      }
    }

    let next: SyncState = Object.freeze({summaries, syncedAt: Date.now(), tip, transactions})

    // Broadcasts recorded while this ran are not in what it read: keep them.
    for (const transaction of state.transactions.values()) {
      if (
        transaction.broadcastAt !== undefined &&
        transaction.broadcastAt >= startedAt &&
        !next.transactions.has(transaction.txid)
      ) {
        next = withTransaction(next, transaction)
      }
    }

    return commit(next)
  }

  const sync = (syncOptions: SyncOptions = {}): Promise<AccountView> => {
    const {full = false, maxAgeMs, signal} = syncOptions

    if (maxAgeMs !== undefined && state.syncedAt !== undefined && Date.now() - state.syncedAt < maxAgeMs) {
      return Promise.resolve(view())
    }

    if (!running) {
      running = run(signal, full).finally(() => {
        running = undefined
      })
    }

    return running
  }

  /** The account's address a coin pays, from the transaction that made it. */
  const ownerOf = (coin: {readonly txid: string; readonly vout: number}) => {
    const output = state.transactions.get(coin.txid)?.outputs[coin.vout]
    const owner = own(output?.address)

    if (!output || !owner) {
      throw new SyncError('UNKNOWN_COIN', 'A coin of the plan is not one of this account`s.')
    }

    return {owner, value: output.value}
  }

  const changeTarget = () => view().changeAddress

  const plan = (watch: BitcoinWatchAccount<string>, request: BitcoinTransactionRequest) =>
    guarded(() => watch.createTransaction(request))

  const createPayment = (request: PaymentRequest): Payment => {
    const current = view()
    const change = current.changeAddress
    // An address watched alone has no key to plan with: say so before anything else.
    const watch = source.watch(change)
    const policy = request.unconfirmed ?? 'own'

    if (policy !== 'own' && policy !== 'all' && policy !== 'none') {
      throw new SyncError('INVALID_ARGUMENT', 'Unconfirmed coins are `own`, `all` or `none`.')
    }

    const unspent = new Map(current.utxos.map(utxo => [outpoint(utxo.txid, utxo.vout), utxo]))
    let coins: AccountUtxo[]

    if (request.coins) {
      coins = request.coins.map(coin => {
        const utxo = unspent.get(outpoint(coin.txid, coin.vout))

        if (!utxo) {
          throw new SyncError('UNKNOWN_COIN', 'A coin to spend is not an unspent coin of this account.')
        }

        return utxo
      })
    } else {
      coins = current.utxos.filter(
        utxo =>
          (!utxo.coinbase || utxo.confirmations >= 100) &&
          (utxo.confirmations > 0 || policy === 'all' || (policy === 'own' && utxo.trusted))
      )
    }

    if (coins.length === 0) {
      throw new SyncError('INSUFFICIENT_FUNDS', 'There are no coins to spend yet.')
    }

    const result = plan(watch, {
      amount: request.amount,
      feeRate: request.feeRate,
      to: request.to,
      utxos: coins.map(({txid, value, vout}): BitcoinUtxo => ({txid, value, vout})),
    })

    return paymentOf(result, change, undefined, coins)
  }

  const paymentOf = (
    result: BitcoinTransactionPlan,
    change: AccountAddress,
    replaces: string | undefined,
    coins: readonly AccountUtxo[]
  ): Payment => {
    const byOutpoint = new Map(coins.map(coin => [outpoint(coin.txid, coin.vout), coin]))

    return Object.freeze({
      change: result.outputs.some((output, index) => index > 0 && output.address === change.address)
        ? change
        : undefined,
      feeRate: Number(result.fee) / result.vsize,
      inputs: Object.freeze(
        result.inputs.map(input => byOutpoint.get(outpoint(input.txid, input.vout)) as AccountUtxo)
      ),
      plan: result,
      replaces,
    })
  }

  const createFeeBump = (txid: string, request: {readonly feeRate: number}): Payment => {
    checkTxid(txid)
    const original = state.transactions.get(txid)
    const unavailable = (message: string) => new SyncError('FEE_BUMP_UNAVAILABLE', message)

    if (!original) {
      throw unavailable('This account has no such transaction.')
    }

    if (original.block) {
      throw unavailable('The transaction is confirmed.')
    }

    if (original.fee === undefined || original.inputs.some(input => !own(input.address) || input.value === undefined)) {
      throw unavailable('Only a transaction that spends this account`s coins alone can be replaced by it.')
    }

    for (const other of state.transactions.values()) {
      if (other.inputs.some(input => input.txid === txid)) {
        throw unavailable('Another pending transaction spends its outputs: replacing it would drop that one too.')
      }
    }

    const external = original.outputs.filter(output => !own(output.address))
    const recipient = external[0]

    if (external.length > 1 || (recipient && recipient.address === undefined)) {
      throw unavailable('A replacement here pays one recipient: this transaction pays several, or a script.')
    }

    const ownOutputs = original.outputs.filter(output => own(output.address))
    // The change goes back where it went; a consolidation (no recipient) sends everything there, less the new fee.
    const change = own(ownOutputs[0]?.address) ?? changeTarget()
    const coins: AccountUtxo[] = original.inputs.map(input => {
      const mine = own(input.address) as AccountAddress

      return Object.freeze({
        address: mine.address,
        change: mine.change,
        coinbase: false,
        confirmations: 0,
        height: undefined,
        index: mine.index,
        path: mine.path,
        scriptPubKey: mine.scriptPubKey,
        trusted: true,
        txid: input.txid,
        value: input.value as bigint,
        vout: input.vout,
      })
    })
    const result = plan(source.watch(change), {
      amount: recipient ? recipient.value : 'max',
      changeAddress: change.address,
      feeRate: request.feeRate,
      to: recipient?.address ?? change.address,
      utxos: coins.map(({txid: id, value, vout}): BitcoinUtxo => ({txid: id, value, vout})),
    })
    const minimumFee = original.fee + BigInt(Math.ceil(result.vsize * INCREMENTAL_RELAY_FEE))
    const originalRate = Number(original.fee) / original.vsize

    if (result.fee < minimumFee || Number(result.fee) / result.vsize <= originalRate) {
      const rate = Math.max(Number(minimumFee) / result.vsize, originalRate)

      throw new SyncError(
        'FEE_TOO_LOW',
        `A replacement must pay at least ${minimumFee} sats here (above ${Math.ceil(rate * 100) / 100} sat/vB).`
      )
    }

    return paymentOf(result, change, txid, coins)
  }

  const createPsbt = async (payment: Payment | BitcoinTransactionPlan, psbtOptions: PsbtOptions = {}) => {
    const target = 'plan' in payment ? payment.plan : payment

    if (source.fingerprint === undefined) {
      throw new SyncError(source.scriptType === undefined ? 'MISSING_KEY' : 'MISSING_FINGERPRINT')
    }

    const inputs = target.inputs.map(input => {
      const {owner, value} = ownerOf(input)

      if (value !== input.value) {
        throw new SyncError('UNKNOWN_COIN', 'A coin of the plan has another value than the account`s.')
      }

      return owner
    })
    const written = new Map<string, Uint8Array>()
    const psbtOf = (entry: AccountAddress) => {
      let psbt = written.get(entry.address)

      if (!psbt) {
        const watch = source.watch(entry)
        psbt = guarded(() => watch.createPsbt(target))
        written.set(entry.address, psbt)
      }

      return psbt
    }
    const previous =
      psbtOptions.previousTransactions === false
        ? new Map<string, Uint8Array>()
        : new Map(
            await Promise.all(
              [...new Set(target.inputs.map(input => input.txid))].map(
                async txid =>
                  [txid, hex.decode(await backend.transactionHex(txid, {signal: psbtOptions.signal}))] as const
              )
            )
          )
    const combined = combinePsbts({
      inputs: inputs.map(psbtOf),
      outputs: target.outputs.map(output => {
        const mine = own(output.address)

        return mine && mine.publicKey ? psbtOf(mine) : undefined
      }),
      previous: target.inputs.map(input => previous.get(input.txid)),
    })

    // Read back strictly, as a signer will: previous transactions that are not the coins' are the backend's lie.
    let decoded: ReturnType<BitcoinChain<string>['decodePsbt']>

    try {
      decoded = chain.decodePsbt(combined)
    } catch (error) {
      throw isCryptoError(error)
        ? new SyncError('INVALID_RESPONSE', 'A previous transaction from the backend is not the coin it spends.', {
            cause: error,
          })
        : error
    }

    decoded.inputs.forEach((input, index) => {
      if (input.spent?.value !== target.inputs[index]?.value) {
        throw new SyncError('INVALID_RESPONSE', 'A previous transaction from the backend disagrees with its coin.')
      }
    })

    return combined
  }

  const signPsbt = async (psbt: Uint8Array, derive: (path: string) => Promise<BitcoinAccount<string>>) => {
    if (source.fingerprint === undefined) {
      throw new SyncError('MISSING_FINGERPRINT')
    }

    const decoded = guarded(() => chain.decodePsbt(psbt))
    const keys = new Map<string, Uint8Array>()

    for (const input of decoded.inputs) {
      for (const origin of input.derivations) {
        if (origin.fingerprint === source.fingerprint && !input.finalized) {
          keys.set(origin.path, origin.publicKey)
        }
      }
    }

    if (keys.size === 0) {
      throw new SyncError('INVALID_ARGUMENT', 'The PSBT names no key of this account.')
    }

    let signed = psbt

    for (const [path, publicKey] of keys) {
      const signer = await derive(path)

      if (!bytes.equal(signer.publicKey, publicKey)) {
        throw new SyncError('KEY_MISMATCH', 'The key derived at a path of the PSBT is not the key it names there.')
      }

      try {
        signed = (await signer.signPsbt(signed)).psbt
      } catch (error) {
        throw fromCrypto(error)
      }
    }

    return signed
  }

  const broadcast = async (
    transaction: Pick<SignedBitcoinTransaction, 'hex' | 'txid'>,
    request: RequestOptions = {}
  ): Promise<string> => {
    const txid = checkTxid(transaction?.txid)
    let answered: string

    try {
      answered = await backend.broadcast(transaction.hex, request)
    } catch (error) {
      // A transaction the node already has (a retry, or someone else broadcast it) is out there: that is success.
      if (
        isSyncError(error, 'BROADCAST_REJECTED') &&
        /already|txn-already-known|known transaction/i.test(error.message)
      ) {
        answered = txid
      } else {
        throw error
      }
    }

    if (answered !== txid) {
      throw new SyncError('INVALID_RESPONSE', 'The backend accepted the transaction under another txid.')
    }

    // Record it, so the coins it spends are spent now. The broadcast succeeded: failing to record it is not a failure.
    for (const wait of [0, 1000, 2000]) {
      try {
        await delay(wait, request.signal)
        const found = await backend.transaction(txid, request)

        if (found) {
          const broadcastAt = Date.now()
          const record = stored(
            found,
            state.transactions.get(txid),
            broadcastAt,
            found.status.confirmed ? undefined : broadcastAt
          )
          commit(withTransaction(state, record))
          break
        }
      } catch {
        break
      }
    }

    return txid
  }

  const transactionStatus = async (txid: string, request?: RequestOptions): Promise<TransactionStatus> => {
    const status = await backend.transactionStatus(checkTxid(txid), request)

    if (!status) {
      return {status: 'unknown'}
    }

    if (!status.confirmed) {
      return {status: 'pending'}
    }

    const tip: BlockRef | undefined = state.tip

    return {
      blockHash: status.blockHash,
      blockTime: status.blockTime,
      confirmations: Math.max(1, (tip?.height ?? status.height) - status.height + 1),
      height: status.height,
      status: 'confirmed',
    }
  }

  view()

  return Object.freeze({
    addressAt: at,
    broadcast,
    createFeeBump,
    createPayment,
    createPsbt,
    feeEstimates: (request?: RequestOptions) => backend.feeEstimates(request),
    fingerprint: source.fingerprint,
    id: source.id,
    network: chain.network.name,
    path: source.path,
    scriptType: source.scriptType,
    signPsbt,
    snapshot: () => toSnapshot(state, source.id),
    subscribe: (listener: (view: AccountView) => void) => {
      listeners.add(listener)

      return () => {
        listeners.delete(listener)
      }
    },
    sync,
    transactionStatus,
    view,
  })
}
