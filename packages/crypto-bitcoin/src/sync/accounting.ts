import type {AddressSummary, BlockRef} from './backend'
import type {StoredTransaction, SyncState} from './state'

/** An address of the account, and where it sits in it. */
export type AccountAddress = {
  /** Normalized: lowercase for SegWit. */
  readonly address: string
  /** 0 for receiving addresses, 1 for change (BIP-44). */
  readonly change: 0 | 1
  readonly index: number
  /** From the master key, `m/84'/1'/0'/0/5`; `undefined` for an account watched by its address alone. */
  readonly path: string | undefined
  /** Compressed, 33 bytes; `undefined` for an account watched by its address alone. */
  readonly publicKey: Uint8Array | undefined
  /** The output script that pays it. */
  readonly scriptPubKey: Uint8Array
}

/** An address with history, and what it holds. */
export type AddressUsage = AccountAddress & {
  /** Transactions that pay it or spend from it, confirmed or not. */
  readonly transactions: number
  /** Satoshis in its unspent coins, mempool included. */
  readonly balance: bigint
}

/** A coin the account can spend: an output of a transaction no other transaction spends, confirmed or not. */
export type AccountUtxo = {
  readonly txid: string
  readonly vout: number
  /** Satoshis. */
  readonly value: bigint
  readonly address: string
  readonly change: 0 | 1
  readonly index: number
  /** Where its key is, from the master key: what the PSBT tells the signer. */
  readonly path: string | undefined
  readonly scriptPubKey: Uint8Array
  /** 0 while its transaction is in the mempool. */
  readonly confirmations: number
  readonly height: number | undefined
  /**
   * Whether nobody but this account can take it back: confirmed, or made by a transaction that spends only this
   * account's coins (its change). What coin selection spends while unconfirmed, by default.
   */
  readonly trusted: boolean
  /** A coinbase output, which can be spent only after 100 confirmations. */
  readonly coinbase: boolean
}

export type AccountBalance = {
  /** Satoshis in confirmed transactions, less what confirmed transactions spent: Esplora's `chain_stats`. */
  readonly confirmed: bigint
  /** What the mempool adds or takes (it can be negative): Esplora's `mempool_stats`. */
  readonly unconfirmed: bigint
  /** `confirmed + unconfirmed`: every unspent coin. */
  readonly total: bigint
  /** What a payment can spend now: trusted coins, coinbase outputs once mature. */
  readonly spendable: bigint
}

/** One transaction from the account's side: what it did to the balance, and where it is. */
export type AccountTransaction = {
  readonly txid: string
  /**
   * `received` when none of its coins were the account's, `self` when every coin it spends and every output it pays
   * is the account's (a consolidation), `sent` otherwise (or `received`, when a transaction that shares its inputs
   * with others leaves the account with more).
   */
  readonly kind: 'received' | 'sent' | 'self'
  /** For people: what others got (`sent`), what the account got (`received`), what came back to it (`self`). */
  readonly amount: bigint
  /** The change to the balance, signed: `received - sent`, the fee included. */
  readonly net: bigint
  /** Satoshis its outputs pay the account. */
  readonly received: bigint
  /** Satoshis of the account's coins it spends. */
  readonly sent: bigint
  /**
   * What the account paid in fees: the whole fee when every input is the account's, 0 when none is, `undefined` when
   * it shares its inputs with others (a coinjoin, a payjoin), as a transaction does not say who paid what.
   */
  readonly fee: bigint | undefined
  /** The transaction's whole fee, when the backend knows it. */
  readonly transactionFee: bigint | undefined
  /** Satoshis per virtual byte, when the fee is known. */
  readonly feeRate: number | undefined
  readonly vsize: number
  /** The other side's addresses: who was paid (`sent`, `self`: none), or whose coins paid (`received`). */
  readonly counterparties: readonly string[]
  /** 0 while it is in the mempool. */
  readonly confirmations: number
  readonly height: number | undefined
  readonly blockHash: string | undefined
  /** The block's timestamp, in seconds. */
  readonly blockTime: number | undefined
  /** Milliseconds, this device's clock: when it was first seen unconfirmed. */
  readonly firstSeen: number | undefined
  /** Unconfirmed, and signalling replaceability (BIP-125): it can be fee-bumped, or replaced by its sender. */
  readonly replaceable: boolean
}

/** What a sync knows of the account: its balance, coins, history and next addresses, from the last sync. */
export type AccountView = {
  readonly balance: AccountBalance
  /** Every unspent coin, largest first. */
  readonly utxos: readonly AccountUtxo[]
  /** Newest first: the mempool's, then by block. */
  readonly transactions: readonly AccountTransaction[]
  /** The first receiving address after the last one with history: the one to show for the next payment in. */
  readonly receiveAddress: AccountAddress
  /** The first change address after the last one with history: where the next payment's change goes. */
  readonly changeAddress: AccountAddress
  /** Every address with history, receiving then change, by index. */
  readonly addresses: readonly AddressUsage[]
  /** The best chain's tip at the last sync. */
  readonly tip: BlockRef | undefined
  /** Milliseconds, when the last sync finished; `undefined` before the first. */
  readonly syncedAt: number | undefined
}

export type Lookup = (address: string | undefined) => AccountAddress | undefined

const COINBASE_MATURITY = 100

/** The highest sequence that signals BIP-125 replaceability, plus one. */
const FINAL_SEQUENCE = 0xfffffffe

export const confirmationsOf = (transaction: StoredTransaction, tip: BlockRef | undefined) =>
  transaction.block ? Math.max(1, (tip?.height ?? transaction.block.height) - transaction.block.height + 1) : 0

export const outpoint = (txid: string, vout: number) => `${txid}:${vout}`

/** Whether a transaction pays or spends from `address`. */
export const touches = (transaction: StoredTransaction, address: string) =>
  transaction.outputs.some(output => output.address === address) ||
  transaction.inputs.some(input => input.address === address)

/** What the transactions say about one address, as Esplora's summary would: to check one against the other. */
export const summarize = (transactions: Iterable<StoredTransaction>, address: string): AddressSummary => {
  let txCount = 0
  let funded = 0n
  let spent = 0n
  let mempoolTxCount = 0
  let mempoolFunded = 0n
  let mempoolSpent = 0n

  for (const transaction of transactions) {
    if (!touches(transaction, address)) {
      continue
    }

    const paid = transaction.outputs.reduce(
      (sum, output) => (output.address === address ? sum + output.value : sum),
      0n
    )
    const taken = transaction.inputs.reduce(
      (sum, input) => (input.address === address ? sum + (input.value ?? 0n) : sum),
      0n
    )

    if (transaction.block) {
      txCount++
      funded += paid
      spent += taken
    } else {
      mempoolTxCount++
      mempoolFunded += paid
      mempoolSpent += taken
    }
  }

  return {funded, mempoolFunded, mempoolSpent, mempoolTxCount, spent, txCount}
}

export const sameSummary = (a: AddressSummary, b: AddressSummary) =>
  a.txCount === b.txCount &&
  a.funded === b.funded &&
  a.spent === b.spent &&
  a.mempoolTxCount === b.mempoolTxCount &&
  a.mempoolFunded === b.mempoolFunded &&
  a.mempoolSpent === b.mempoolSpent

export const isUsed = (summary: AddressSummary) => summary.txCount + summary.mempoolTxCount > 0

/**
 * Whether every coin a transaction spends is the account's, all the way down its unconfirmed ancestors: then no one
 * else can double-spend it, and its outputs are safe to spend before it confirms (Bitcoin Core's "trusted").
 */
const trustOf = (state: SyncState, own: Lookup) => {
  const known = new Map<string, boolean>()

  const trusted = (txid: string, depth = 0): boolean => {
    const transaction = state.transactions.get(txid)

    if (!transaction) {
      return false
    }

    if (transaction.block) {
      return true
    }

    const cached = known.get(txid)

    if (cached !== undefined) {
      return cached
    }

    // A mempool chain is at most 25 deep by default policy; anything deeper is not worth trusting.
    const result =
      depth < 100 &&
      transaction.inputs.every(input => own(input.address) !== undefined && trusted(input.txid, depth + 1))
    known.set(txid, result)

    return result
  }

  return trusted
}

const describe = (
  transaction: StoredTransaction,
  own: Lookup,
  tip: BlockRef | undefined
): AccountTransaction | undefined => {
  const ownInputs = transaction.inputs.filter(input => own(input.address))
  const ownOutputs = transaction.outputs.filter(output => own(output.address))

  if (ownInputs.length === 0 && ownOutputs.length === 0) {
    return undefined
  }

  const received = ownOutputs.reduce((sum, output) => sum + output.value, 0n)
  const sent = ownInputs.reduce((sum, input) => sum + (input.value ?? 0n), 0n)
  const net = received - sent
  const allInputs = ownInputs.length === transaction.inputs.length
  const fee = ownInputs.length === 0 ? 0n : allInputs ? transaction.fee : undefined
  const kind =
    ownInputs.length === 0
      ? 'received'
      : allInputs && ownOutputs.length === transaction.outputs.length
        ? 'self'
        : net < 0n
          ? 'sent'
          : 'received'
  const others = (kind === 'received' ? transaction.inputs : transaction.outputs)
    .map(entry => entry.address)
    .filter((address): address is string => address !== undefined && !own(address))

  return Object.freeze({
    amount: kind === 'self' ? received : kind === 'received' ? net : -net - (fee ?? 0n),
    blockHash: transaction.block?.hash,
    blockTime: transaction.block?.time,
    confirmations: confirmationsOf(transaction, tip),
    counterparties: Object.freeze([...new Set(others)]),
    fee,
    feeRate:
      transaction.fee === undefined || transaction.vsize === 0
        ? undefined
        : Number(transaction.fee) / transaction.vsize,
    firstSeen: transaction.firstSeen,
    height: transaction.block?.height,
    kind,
    net,
    received,
    replaceable: !transaction.block && transaction.inputs.some(input => input.sequence < FINAL_SEQUENCE),
    sent,
    transactionFee: transaction.fee,
    txid: transaction.txid,
    vsize: transaction.vsize,
  })
}

const newestFirst = (a: AccountTransaction, b: AccountTransaction) => {
  if (a.height === undefined || b.height === undefined) {
    if (a.height !== b.height) {
      return a.height === undefined ? -1 : 1
    }

    return (b.firstSeen ?? 0) - (a.firstSeen ?? 0) || a.txid.localeCompare(b.txid)
  }

  return b.height - a.height || a.txid.localeCompare(b.txid)
}

/** The coins, the balance and the history the state's transactions add up to, from the account's side. */
export const account = (state: SyncState, own: Lookup) => {
  const spentBy = new Map<string, StoredTransaction>()

  for (const transaction of state.transactions.values()) {
    for (const input of transaction.inputs) {
      spentBy.set(outpoint(input.txid, input.vout), transaction)
    }
  }

  const trusted = trustOf(state, own)
  const utxos: AccountUtxo[] = []
  let confirmed = 0n
  let unconfirmed = 0n
  let spendable = 0n

  for (const transaction of state.transactions.values()) {
    transaction.outputs.forEach((output, vout) => {
      const mine = own(output.address)

      if (!mine) {
        return
      }

      const spender = spentBy.get(outpoint(transaction.txid, vout))

      if (transaction.block) {
        // Confirmed coins count until a confirmed transaction spends them; a mempool spend is the mempool's delta.
        if (!spender?.block) {
          confirmed += output.value
        }
      } else {
        unconfirmed += output.value
      }

      if (spender) {
        return
      }

      const confirmations = confirmationsOf(transaction, state.tip)
      const utxo: AccountUtxo = Object.freeze({
        address: mine.address,
        change: mine.change,
        coinbase: transaction.coinbase,
        confirmations,
        height: transaction.block?.height,
        index: mine.index,
        path: mine.path,
        scriptPubKey: mine.scriptPubKey,
        trusted: trusted(transaction.txid),
        txid: transaction.txid,
        value: output.value,
        vout,
      })
      utxos.push(utxo)

      if (utxo.trusted && (!utxo.coinbase || confirmations >= COINBASE_MATURITY)) {
        spendable += output.value
      }
    })

    if (!transaction.block) {
      for (const input of transaction.inputs) {
        if (own(input.address)) {
          unconfirmed -= input.value ?? 0n
        }
      }
    }
  }

  utxos.sort((a, b) =>
    a.value === b.value ? a.txid.localeCompare(b.txid) || a.vout - b.vout : a.value > b.value ? -1 : 1
  )

  const transactions = [...state.transactions.values()]
    .map(transaction => describe(transaction, own, state.tip))
    .filter((transaction): transaction is AccountTransaction => transaction !== undefined)
    .sort(newestFirst)

  return {
    balance: Object.freeze({confirmed, spendable, total: confirmed + unconfirmed, unconfirmed}),
    transactions: Object.freeze(transactions),
    utxos: Object.freeze(utxos),
  }
}

/** Every address with history: how many transactions touch it, and what its coins hold. */
export const usage = (state: SyncState, own: Lookup, utxos: readonly AccountUtxo[]): readonly AddressUsage[] => {
  const counts = new Map<string, number>()

  for (const transaction of state.transactions.values()) {
    const addresses = new Set(
      [...transaction.inputs, ...transaction.outputs]
        .map(entry => entry.address)
        .filter((address): address is string => own(address) !== undefined)
    )

    for (const address of addresses) {
      counts.set(address, (counts.get(address) ?? 0) + 1)
    }
  }

  const balances = new Map<string, bigint>()

  for (const utxo of utxos) {
    balances.set(utxo.address, (balances.get(utxo.address) ?? 0n) + utxo.value)
  }

  return Object.freeze(
    [...counts]
      .map(([address, transactions]) => {
        const mine = own(address) as AccountAddress

        return Object.freeze({...mine, balance: balances.get(address) ?? 0n, transactions})
      })
      .sort((a, b) => a.change - b.change || a.index - b.index)
  )
}
