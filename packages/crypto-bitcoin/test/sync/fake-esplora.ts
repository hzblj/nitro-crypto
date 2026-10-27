import {createHash} from 'node:crypto'

import {hex} from '@hzblj/nitro-crypto/adapter'
import {Address, OutScript, TEST_NETWORK, Transaction} from '@scure/btc-signer'

import {serializeTransaction} from '../../src/transaction'

/**
 * An Esplora server over an in-memory chain, for the sync's tests: blocks, a mempool, real transaction bytes (so their
 * ids and the PSBTs' previous transactions check out), reorganizations, drops and replacements, every route the
 * backend uses, and a log of what was asked. Its JSON is Esplora's, as mempool.space answers it.
 */

const sha256 = (data: Uint8Array) => new Uint8Array(createHash('sha256').update(data).digest())
const hash256 = (data: Uint8Array) => sha256(sha256(data))

const ADDRESS = Address(TEST_NETWORK)

/** Someone else's address: where the coins that fund the account come from. */
export const STRANGER = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'

type Coin = {readonly script: Uint8Array; readonly value: bigint}

type FakeTransaction = {
  readonly txid: string
  readonly hex: string
  readonly inputs: readonly {readonly txid: string; readonly vout: number; readonly sequence: number}[]
  readonly outputs: readonly Coin[]
  readonly weight: number
}

type Block = {readonly height: number; readonly hash: string; readonly time: number; readonly txids: string[]}

export type Payee = {readonly address: string; readonly value: bigint | number}

const scriptOf = (address: string) => OutScript.encode(ADDRESS.decode(address))

const addressOf = (script: Uint8Array): string | undefined => {
  try {
    return ADDRESS.encode(OutScript.decode(script))
  } catch {
    return undefined
  }
}

const json = (body: unknown, status = 200) =>
  new Response(
    JSON.stringify(body, (_, value) => (typeof value === 'bigint' ? Number(value) : value)),
    {
      headers: {'content-type': 'application/json'},
      status,
    }
  )

const text = (body: string, status = 200) => new Response(body, {status})

export const createFakeEsplora = ({recommended = true} = {}) => {
  const transactions = new Map<string, FakeTransaction>()
  const foreign = new Map<string, Coin>()
  let blocks: Block[] = [{hash: '00'.repeat(32), height: 0, time: 1_700_000_000, txids: []}]
  let mempool: string[] = []
  let salt = 0
  const requests: string[] = []
  const failures: {
    readonly pattern: RegExp
    status: number
    times: number
    readonly headers?: Record<string, string>
  }[] = []

  const tip = () => blocks[blocks.length - 1] as Block
  const blockOf = (txid: string) => blocks.find(block => block.txids.includes(txid))
  const known = (txid: string) => transactions.has(txid) && (mempool.includes(txid) || blockOf(txid) !== undefined)
  const coinOf = (txid: string, vout: number): Coin | undefined =>
    transactions.get(txid)?.outputs[vout] ?? foreign.get(`${txid}:${vout}`)

  const live = () => [
    ...blocks.flatMap(block => block.txids.map(txid => transactions.get(txid) as FakeTransaction)),
    ...mempool.map(txid => transactions.get(txid) as FakeTransaction),
  ]

  /** A transaction of the chain from its parts, unsigned (no witness): its id is what the bytes hash to. */
  const build = (
    inputs: readonly {readonly txid: string; readonly vout: number; readonly sequence?: number}[],
    outputs: readonly Payee[]
  ): FakeTransaction => {
    const raw = serializeTransaction({
      inputs: inputs.map(input => ({
        sequence: input.sequence ?? 0xfffffffd,
        txid: hex.decode(input.txid).reverse(),
        value: 0n,
        vout: input.vout,
      })),
      locktime: 0,
      outputs: outputs.map(output => ({scriptPubKey: scriptOf(output.address), value: BigInt(output.value)})),
      version: 2,
    })

    return {
      hex: hex.encode(raw),
      inputs: inputs.map(input => ({sequence: input.sequence ?? 0xfffffffd, txid: input.txid, vout: input.vout})),
      outputs: outputs.map(output => ({script: scriptOf(output.address), value: BigInt(output.value)})),
      txid: hex.encode(hash256(raw).reverse()),
      weight: raw.length * 4,
    }
  }

  const spenderOf = (txid: string, vout: number) =>
    live().find(transaction => transaction.inputs.some(input => input.txid === txid && input.vout === vout))

  /** Out of the mempool with every descendant: dropped, or replaced. */
  const evict = (txid: string) => {
    if (!mempool.includes(txid)) {
      return
    }

    mempool = mempool.filter(id => id !== txid)
    const transaction = transactions.get(txid) as FakeTransaction

    transaction.outputs.forEach((_, vout) => {
      const child = spenderOf(txid, vout)

      if (child) {
        evict(child.txid)
      }
    })
  }

  const accept = (transaction: FakeTransaction) => {
    for (const input of transaction.inputs) {
      const spender = spenderOf(input.txid, input.vout)

      if (!coinOf(input.txid, input.vout) || (spender && !mempool.includes(spender.txid))) {
        throw new Error('bad-txns-inputs-missingorspent')
      }

      // Full RBF, as Bitcoin Core 28 relays by default.
      if (spender) {
        evict(spender.txid)
      }
    }

    transactions.set(transaction.txid, transaction)
    mempool.push(transaction.txid)

    return transaction.txid
  }

  const fee = (transaction: FakeTransaction) =>
    transaction.inputs.reduce((sum, input) => sum + (coinOf(input.txid, input.vout)?.value ?? 0n), 0n) -
    transaction.outputs.reduce((sum, output) => sum + output.value, 0n)

  const status = (txid: string) => {
    const block = blockOf(txid)

    return block
      ? {block_hash: block.hash, block_height: block.height, block_time: block.time, confirmed: true}
      : {confirmed: false}
  }

  const esplora = (transaction: FakeTransaction) => ({
    fee: fee(transaction),
    locktime: 0,
    size: transaction.hex.length / 2,
    status: status(transaction.txid),
    txid: transaction.txid,
    version: 2,
    vin: transaction.inputs.map(input => {
      const coin = coinOf(input.txid, input.vout) as Coin

      return {
        is_coinbase: false,
        prevout: {
          scriptpubkey: hex.encode(coin.script),
          scriptpubkey_address: addressOf(coin.script),
          value: coin.value,
        },
        scriptsig: '',
        sequence: input.sequence,
        txid: input.txid,
        vout: input.vout,
        witness: [],
      }
    }),
    vout: transaction.outputs.map(output => ({
      scriptpubkey: hex.encode(output.script),
      scriptpubkey_address: addressOf(output.script),
      value: output.value,
    })),
    weight: transaction.weight,
  })

  const touches = (transaction: FakeTransaction, address: string) =>
    transaction.outputs.some(output => addressOf(output.script) === address) ||
    transaction.inputs.some(input => {
      const coin = coinOf(input.txid, input.vout)

      return coin !== undefined && addressOf(coin.script) === address
    })

  const stats = (list: readonly FakeTransaction[], address: string) => {
    const touching = list.filter(transaction => touches(transaction, address))
    const funded = touching.flatMap(transaction =>
      transaction.outputs.filter(output => addressOf(output.script) === address)
    )
    const spent = touching.flatMap(transaction =>
      transaction.inputs
        .map(input => coinOf(input.txid, input.vout) as Coin)
        .filter(coin => addressOf(coin.script) === address)
    )

    return {
      funded_txo_count: funded.length,
      funded_txo_sum: funded.reduce((sum, coin) => sum + coin.value, 0n),
      spent_txo_count: spent.length,
      spent_txo_sum: spent.reduce((sum, coin) => sum + coin.value, 0n),
      tx_count: touching.length,
    }
  }

  /** Confirmed transactions touching `address`, newest first, as Esplora pages them. */
  const confirmedHistory = (address: string) =>
    [...blocks]
      .reverse()
      .flatMap(block => [...block.txids].reverse())
      .map(txid => transactions.get(txid) as FakeTransaction)
      .filter(transaction => touches(transaction, address))

  const route = (method: string, path: string, body: string | undefined): Response => {
    let match: RegExpExecArray | null

    if (method === 'POST' && path === '/tx') {
      try {
        const parsed = Transaction.fromRaw(hex.decode(body ?? ''), {allowUnknownOutputs: true})
        const transaction: FakeTransaction = {
          hex: body ?? '',
          inputs: Array.from({length: parsed.inputsLength}, (_, index) => {
            const input = parsed.getInput(index)

            return {
              sequence: input.sequence ?? 0xffffffff,
              txid: hex.encode(input.txid ?? new Uint8Array()),
              vout: input.index ?? 0,
            }
          }),
          outputs: Array.from({length: parsed.outputsLength}, (_, index) => {
            const output = parsed.getOutput(index)

            return {script: output.script ?? new Uint8Array(), value: output.amount ?? 0n}
          }),
          txid: parsed.id,
          weight: parsed.weight,
        }

        if (known(transaction.txid)) {
          return text('sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}', 400)
        }

        return text(accept(transaction))
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)

        return text(`sendrawtransaction RPC error: {"code":-25,"message":"${message}"}`, 400)
      }
    }

    if (path === '/blocks/tip/height') {
      return text(String(tip().height))
    }

    if ((match = /^\/block-height\/(\d+)$/.exec(path))) {
      const block = blocks[Number(match[1])]

      return block ? text(block.hash) : text('Block not found', 404)
    }

    if ((match = /^\/address\/([a-z0-9]+)$/.exec(path))) {
      const address = match[1] as string
      const confirmed = blocks.flatMap(block => block.txids.map(txid => transactions.get(txid) as FakeTransaction))
      const pending = mempool.map(txid => transactions.get(txid) as FakeTransaction)

      return json({address, chain_stats: stats(confirmed, address), mempool_stats: stats(pending, address)})
    }

    if ((match = /^\/address\/([a-z0-9]+)\/txs$/.exec(path))) {
      const address = match[1] as string
      const pending = [...mempool]
        .reverse()
        .map(txid => transactions.get(txid) as FakeTransaction)
        .filter(transaction => touches(transaction, address))

      return json([...pending.slice(0, 50), ...confirmedHistory(address).slice(0, 25)].map(esplora))
    }

    if ((match = /^\/address\/([a-z0-9]+)\/txs\/chain\/([0-9a-f]{64})$/.exec(path))) {
      const history = confirmedHistory(match[1] as string)
      const after = history.findIndex(transaction => transaction.txid === match?.[2])

      return json(after < 0 ? [] : history.slice(after + 1, after + 26).map(esplora))
    }

    if ((match = /^\/tx\/([0-9a-f]{64})(\/hex|\/status)?$/.exec(path))) {
      const txid = match[1] as string
      const transaction = transactions.get(txid)

      if (!transaction || !known(txid)) {
        return text('Transaction not found', 404)
      }

      return match[2] === '/hex'
        ? text(transaction.hex)
        : json(match[2] === '/status' ? status(txid) : esplora(transaction))
    }

    if (path === '/fee-estimates') {
      return json({1: 20.5, 3: 10.25, 6: 5.1, 144: 1.4, 1008: 1})
    }

    if (path === '/v1/fees/recommended') {
      return recommended
        ? json({economyFee: 2, fastestFee: 21, halfHourFee: 11, hourFee: 6, minimumFee: 1})
        : text('Not found', 404)
    }

    return text('Not found', 404)
  }

  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    const path = url.replace(/^https?:\/\/[^/]+\/api/, '')
    const method = init?.method ?? 'GET'
    requests.push(`${method} ${path}`)

    if (init?.signal?.aborted) {
      throw new DOMException('The operation was aborted.', 'AbortError')
    }

    const failure = failures.find(candidate => candidate.times > 0 && candidate.pattern.test(path))

    if (failure) {
      failure.times--

      return new Response('Too busy', {headers: failure.headers, status: failure.status})
    }

    return route(method, path, typeof init?.body === 'string' ? init.body : undefined)
  }) as typeof globalThis.fetch

  let funding = 0

  return {
    /** Spends any coins (the account's or a stranger's) to `outputs`, into the mempool. */
    add: (
      inputs: readonly {readonly txid: string; readonly vout: number; readonly sequence?: number}[],
      outputs: readonly Payee[]
    ) => accept(build(inputs, outputs)),
    blocks: () => blocks,
    /** Out of the mempool, as if it expired or a conflicting transaction won. */
    drop: (txid: string) => evict(txid),
    fail: (pattern: RegExp, status: number, times: number, headers?: Record<string, string>) =>
      failures.push({headers, pattern, status, times}),
    fetch,
    /** A stranger's coin paid to `outputs`: a transaction in the mempool, `fee` sats to the miners. */
    fund: (outputs: readonly Payee[], {fee: paid = 500n, sequence = 0xfffffffd} = {}) => {
      const source = hex.encode(sha256(Uint8Array.of(0xf0, funding >> 8, funding & 0xff)))
      funding++
      const total = outputs.reduce((sum, output) => sum + BigInt(output.value), 0n) + paid
      foreign.set(`${source}:0`, {script: scriptOf(STRANGER), value: total})

      return accept(build([{sequence, txid: source, vout: 0}], outputs))
    },
    hex: (txid: string) => transactions.get(txid)?.hex ?? '',
    inMempool: (txid: string) => mempool.includes(txid),
    /** Mines the mempool (or `only` these of it) into a block. */
    mine: (only?: readonly string[]) => {
      const txids = only ? mempool.filter(txid => only.includes(txid)) : [...mempool]
      mempool = mempool.filter(txid => !txids.includes(txid))
      const height = tip().height + 1
      const hash = hex.encode(sha256(Uint8Array.of(height >> 8, height & 0xff, salt)))
      blocks.push({hash, height, time: 1_700_000_000 + height * 600, txids})

      return hash
    },
    /**
     * Takes the last `depth` blocks off the chain: their transactions back to the mempool (but `drop`), then mines
     * `blocks` new ones with whatever the mempool holds.
     */
    reorg: (depth: number, {drop = [] as readonly string[], mine = 0} = {}) => {
      const removed = blocks.slice(blocks.length - depth)
      blocks = blocks.slice(0, blocks.length - depth)
      mempool = [...removed.flatMap(block => block.txids).filter(txid => !drop.includes(txid)), ...mempool]
      salt++

      for (let count = 0; count < mine; count++) {
        const height = tip().height + 1
        blocks.push({
          hash: hex.encode(sha256(Uint8Array.of(height >> 8, height & 0xff, salt))),
          height,
          time: 1_700_000_000 + height * 600,
          txids: count === 0 ? [...mempool] : [],
        })

        if (count === 0) {
          mempool = []
        }
      }
    },
    /** A stranger replaces their unconfirmed payment `txid` (BIP-125) with one paying `outputs`. */
    replace: (txid: string, outputs: readonly Payee[]) => {
      const original = transactions.get(txid) as FakeTransaction

      return accept(build(original.inputs, outputs))
    },
    requests,
    reset: () => {
      requests.length = 0
    },
  }
}

export type FakeEsplora = ReturnType<typeof createFakeEsplora>
