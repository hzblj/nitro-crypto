import {type BitcoinNetworkName, NETWORKS} from '../networks'
import {MAX_MONEY} from '../transaction'
import type {
  AddressSummary,
  BackendInput,
  BackendOutput,
  BackendStatus,
  BackendTransaction,
  BitcoinBackend,
  FeeEstimates,
} from './backend'
import {SyncError} from './errors'
import {createHttpClient, type HttpOptions, type RequestOptions} from './http'

/**
 * mempool.space's public Esplora API for each network it serves. Testnet is testnet4, the one Bitcoin Core 28 and
 * later run. Regtest has no public server: pass `url`.
 */
export const ESPLORA_URLS: Readonly<Partial<Record<BitcoinNetworkName, string>>> = Object.freeze({
  mainnet: 'https://mempool.space/api',
  signet: 'https://mempool.space/signet/api',
  testnet: 'https://mempool.space/testnet4/api',
})

export type EsploraOptions = HttpOptions & {
  /** The network the server serves: checked against the account's, so a mainnet key never asks a testnet server. */
  readonly network: BitcoinNetworkName
  /**
   * The API's base URL: your own Esplora (electrs, or a mempool instance), `https://esplora.example.com/api`, or a
   * public one such as `https://mempool.space/testnet4/api` or `https://blockstream.info/api`. mempool.space's for the
   * network unless stated; required for regtest. A wallet with real users should run or rent its own: public servers
   * rate-limit, and block an IP address that asks too much.
   */
  readonly url?: string
}

/** Hosts that serve Esplora to everyone, for free, and protect themselves: `PUBLIC_PACING` applies to them. */
export const PUBLIC_ESPLORA_HOSTS: readonly string[] = Object.freeze(['mempool.space', 'blockstream.info'])

/**
 * The defaults for a public server (mempool.space, blockstream.info). Neither publishes its limits, and mempool.space
 * blocked the IP address these were written on after a minute or so of syncing a large account two requests at a
 * time, unpaced: its every address was refused afterwards, mainnet included. Two requests a second, in bursts of five,
 * two at once, stays far under that. A one-address sync (about six requests) is immediate; a fresh account's first
 * sync (about 45 requests at the default gap limit) takes some 20 seconds; a long history spreads out instead of
 * piling up. Retries start at a second.
 */
export const PUBLIC_PACING = Object.freeze({burst: 5, concurrency: 2, requestsPerSecond: 2, retryDelayMs: 1000})

/**
 * The defaults for any other `url`: your own server. Fifty requests a second in bursts of twenty, eight at once:
 * electrs answers that without effort, and the cap only keeps a runaway loop from becoming a flood.
 */
export const OWN_PACING = Object.freeze({burst: 20, concurrency: 8, requestsPerSecond: 50, retryDelayMs: 500})

/** Whether a URL is one of `PUBLIC_ESPLORA_HOSTS`, or a subdomain of one. */
export const isPublicEsplora = (url: string): boolean => {
  const host = /^https?:\/\/([^/:?#]+)/i.exec(url)?.[1]?.toLowerCase() ?? ''

  return PUBLIC_ESPLORA_HOSTS.some(known => host === known || host.endsWith(`.${known}`))
}

/** Esplora's page of confirmed transactions in an address's history. */
const CHAIN_PAGE = 25

const TXID = /^[0-9a-f]{64}$/
const HEX = /^(?:[0-9a-f]{2})+$/

const invalid = (what: string) =>
  new SyncError('INVALID_RESPONSE', `The backend's ${what} is not what Esplora answers.`)

const record = (value: unknown, what: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid(what)
  }

  return value as Record<string, unknown>
}

const list = (value: unknown, what: string): readonly unknown[] => {
  if (!Array.isArray(value)) {
    throw invalid(what)
  }

  return value
}

const integer = (value: unknown, what: string, max = Number.MAX_SAFE_INTEGER): number => {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > max) {
    throw invalid(what)
  }

  return value
}

const satoshis = (value: unknown, what: string): bigint => {
  const amount = BigInt(integer(value, what))

  if (amount > MAX_MONEY) {
    throw invalid(what)
  }

  return amount
}

const txid = (value: unknown, what: string): string => {
  if (typeof value !== 'string' || !TXID.test(value)) {
    throw invalid(what)
  }

  return value
}

/** A txid the caller passed: lowercase hex, 64 digits. */
const argument = (value: string, what = 'A txid'): string => {
  if (typeof value !== 'string' || !TXID.test(value)) {
    throw new SyncError('INVALID_ARGUMENT', `${what} is 64 lowercase hex digits.`)
  }

  return value
}

const optionalAddress = (value: unknown, what: string): string | undefined => {
  if (value === undefined || value === null) {
    return undefined
  }

  if (typeof value !== 'string' || value.length === 0 || value.length > 100) {
    throw invalid(what)
  }

  return value
}

const parseStatus = (value: unknown): BackendStatus => {
  const status = record(value, 'transaction status')

  if (status.confirmed === false) {
    return {confirmed: false}
  }

  if (status.confirmed !== true) {
    throw invalid('transaction status')
  }

  return {
    blockHash: txid(status.block_hash, 'block hash'),
    blockTime: integer(status.block_time, 'block time'),
    confirmed: true,
    height: integer(status.block_height, 'block height'),
  }
}

const parseInput = (value: unknown): BackendInput & {readonly coinbase: boolean} => {
  const input = record(value, 'transaction input')
  const coinbase = input.is_coinbase === true
  const prevout = input.prevout === null || input.prevout === undefined ? undefined : record(input.prevout, 'prevout')

  return {
    address: prevout && optionalAddress(prevout.scriptpubkey_address, 'prevout address'),
    coinbase,
    sequence: integer(input.sequence, 'input sequence', 0xffffffff),
    txid: txid(input.txid, 'input txid'),
    value: prevout && satoshis(prevout.value, 'prevout value'),
    vout: integer(input.vout, 'input index', 0xffffffff),
  }
}

const parseOutput = (value: unknown): BackendOutput => {
  const output = record(value, 'transaction output')

  return {
    address: optionalAddress(output.scriptpubkey_address, 'output address'),
    value: satoshis(output.value, 'output value'),
  }
}

/** Esplora's transaction JSON, read strictly: anything it does not document is `INVALID_RESPONSE`. */
export const parseEsploraTransaction = (value: unknown): BackendTransaction => {
  const transaction = record(value, 'transaction')
  const inputs = list(transaction.vin, 'transaction inputs').map(parseInput)
  const outputs = list(transaction.vout, 'transaction outputs').map(parseOutput)
  const weight = integer(transaction.weight, 'transaction weight')
  const coinbase = inputs.some(input => input.coinbase)

  if (inputs.length === 0 || outputs.length === 0) {
    throw invalid('transaction')
  }

  return Object.freeze({
    coinbase,
    fee: coinbase ? 0n : transaction.fee === undefined ? undefined : satoshis(transaction.fee, 'transaction fee'),
    inputs: Object.freeze(inputs.map(({coinbase: _, ...input}) => Object.freeze(input))),
    outputs: Object.freeze(outputs.map(output => Object.freeze(output))),
    status: Object.freeze(parseStatus(transaction.status)),
    txid: txid(transaction.txid, 'txid'),
    vsize: Math.ceil(weight / 4),
  })
}

const parseStats = (value: unknown, what: string) => {
  const stats = record(value, what)

  return {
    count: integer(stats.tx_count, what),
    funded: satoshis(stats.funded_txo_sum, what),
    spent: satoshis(stats.spent_txo_sum, what),
  }
}

const rate = (value: unknown, what: string): number => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1_000_000) {
    throw invalid(what)
  }

  return value
}

/**
 * The named rates from mempool.space's `/v1/fees/recommended` when the server has it, else from the confirmation
 * targets of `/fee-estimates` (every Esplora has those): the rate of the nearest target at or above each.
 */
const feeLevels = (byTarget: Readonly<Record<number, number>>, recommended: unknown): FeeEstimates => {
  if (recommended !== undefined) {
    const fees = record(recommended, 'recommended fees')

    return {
      byTarget,
      economy: rate(fees.economyFee, 'economy fee'),
      fastest: rate(fees.fastestFee, 'fastest fee'),
      halfHour: rate(fees.halfHourFee, 'half-hour fee'),
      hour: rate(fees.hourFee, 'hour fee'),
      minimum: rate(fees.minimumFee, 'minimum fee'),
    }
  }

  const targets = Object.keys(byTarget)
    .map(Number)
    .sort((a, b) => a - b)
  const at = (blocks: number) => {
    const target = targets.find(candidate => candidate >= blocks) ?? targets[targets.length - 1]

    return target === undefined ? 1 : Math.max(1, byTarget[target] ?? 1)
  }

  return {
    byTarget,
    economy: at(144),
    fastest: at(1),
    halfHour: at(3),
    hour: at(6),
    minimum: Math.max(1, Math.min(...targets.map(target => byTarget[target] ?? 1), Number.POSITIVE_INFINITY) || 1),
  }
}

/**
 * A backend over an Esplora HTTP API: your own electrs or mempool instance, or mempool.space and blockstream.info.
 * Every request has a timeout, follows the caller's `AbortSignal`, is retried with backoff on 429 and 5xx (honouring
 * `Retry-After`), waits its turn behind `concurrency` others and starts no faster than `requestsPerSecond`; a server
 * that cannot be reached at all is left alone for a while (`UNREACHABLE`). Every answer is read strictly.
 *
 * Public servers get polite defaults (`PUBLIC_PACING`: two requests a second), any other `url` fast ones
 * (`OWN_PACING`); every option overrides them.
 *
 * ```ts
 * const own = esploraBackend({network: 'mainnet', url: 'https://esplora.example.com/api'}) // what a real wallet uses
 * const trial = esploraBackend({network: 'testnet'}) // mempool.space's testnet4, paced
 * ```
 */
export const esploraBackend = (options: EsploraOptions): BitcoinBackend => {
  const network = NETWORKS[options.network]

  if (!network) {
    throw new SyncError('INVALID_ARGUMENT', 'A network is mainnet, testnet, signet or regtest.')
  }

  const url = options.url ?? ESPLORA_URLS[options.network]

  if (!url || !/^https?:\/\/\S+$/.test(url)) {
    throw new SyncError(
      'INVALID_ARGUMENT',
      options.url === undefined
        ? `There is no public Esplora for ${network.name}: pass its url.`
        : 'An Esplora url is an http or https URL.'
    )
  }

  const pacing = isPublicEsplora(url) ? PUBLIC_PACING : OWN_PACING
  const http = createHttpClient(url, {
    ...options,
    burst: options.burst ?? pacing.burst,
    concurrency: options.concurrency ?? pacing.concurrency,
    requestsPerSecond: options.requestsPerSecond ?? pacing.requestsPerSecond,
    retryDelayMs: options.retryDelayMs ?? pacing.retryDelayMs,
  })

  const tip = async (request?: RequestOptions) => {
    const height = Number(await http.text({path: '/blocks/tip/height'}, request))

    if (!Number.isInteger(height) || height < 0) {
      throw invalid('tip height')
    }

    const hash = await blockHash(height, request)

    if (hash === undefined) {
      throw invalid('tip')
    }

    return {hash, height}
  }

  const blockHash = async (height: number, request?: RequestOptions) => {
    const text = await http.text({notFound: true, path: `/block-height/${height}`}, request)

    return text === undefined ? undefined : txid(text.trim(), 'block hash')
  }

  const addressSummary = async (address: string, request?: RequestOptions): Promise<AddressSummary> => {
    const summary = record(await http.json({path: `/address/${encodeURIComponent(address)}`}, request), 'address')
    const chain = parseStats(summary.chain_stats, 'chain stats')
    const mempool = parseStats(summary.mempool_stats, 'mempool stats')

    return Object.freeze({
      funded: chain.funded,
      mempoolFunded: mempool.funded,
      mempoolSpent: mempool.spent,
      mempoolTxCount: mempool.count,
      spent: chain.spent,
      txCount: chain.count,
    })
  }

  const addressHistory = async (address: string, request: RequestOptions & {readonly after?: string} = {}) => {
    const after = request.after === undefined ? '' : `/chain/${argument(request.after, 'A cursor')}`
    const page = list(
      await http.json({path: `/address/${encodeURIComponent(address)}/txs${after}`}, request),
      'history'
    )
    const transactions = page.map(parseEsploraTransaction)
    const confirmed = transactions.filter(transaction => transaction.status.confirmed)
    const last = confirmed[confirmed.length - 1]

    return Object.freeze({
      next: last && confirmed.length >= CHAIN_PAGE ? last.txid : undefined,
      transactions: Object.freeze(transactions),
    })
  }

  const feeEstimates = async (request?: RequestOptions) => {
    const [targets, recommended] = await Promise.all([
      http.json({path: '/fee-estimates'}, request),
      http.json({notFound: true, path: '/v1/fees/recommended'}, request),
    ])
    const byTarget = Object.fromEntries(
      Object.entries(record(targets, 'fee estimates')).map(([target, value]) => {
        const blocks = Number(target)

        if (!Number.isInteger(blocks) || blocks < 1) {
          throw invalid('fee estimates')
        }

        return [blocks, rate(value, 'fee estimate')]
      })
    )

    return Object.freeze(feeLevels(Object.freeze(byTarget), recommended))
  }

  return Object.freeze({
    addressHistory,
    addressSummary,
    blockHash,
    broadcast: async (hex: string, request?: RequestOptions) => {
      if (typeof hex !== 'string' || !HEX.test(hex)) {
        throw new SyncError('INVALID_ARGUMENT', 'A transaction to broadcast is its hex, lowercase.')
      }

      return txid((await http.text({body: hex, broadcast: true, method: 'POST', path: '/tx'}, request))?.trim(), 'txid')
    },
    feeEstimates,
    network: network.name,
    tip,
    transaction: async (id: string, request?: RequestOptions) => {
      const answer = await http.json({notFound: true, path: `/tx/${argument(id)}`}, request)

      return answer === undefined ? undefined : parseEsploraTransaction(answer)
    },
    transactionHex: async (id: string, request?: RequestOptions) => {
      const hex = (await http.text({path: `/tx/${argument(id)}/hex`}, request))?.trim().toLowerCase()

      if (!hex || !HEX.test(hex)) {
        throw invalid('raw transaction')
      }

      return hex
    },
    transactionStatus: async (id: string, request?: RequestOptions) => {
      const answer = await http.json({notFound: true, path: `/tx/${argument(id)}/status`}, request)

      return answer === undefined ? undefined : Object.freeze(parseStatus(answer))
    },
  })
}
