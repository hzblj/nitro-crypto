import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {esploraBackend} from '../../src/sync'
import {createLimiter, reasonOf} from '../../src/sync/http'
import {createFakeEsplora, STRANGER} from './fake-esplora'
import {rejectsSync, URL} from './helpers'

const backendOver = (fetch: typeof globalThis.fetch, options: {timeoutMs?: number; retries?: number} = {}) =>
  esploraBackend({fetch, network: 'testnet', retryDelayMs: 1, url: URL, ...options})

/** A `fetch` that answers from a list, recording each call, and waits for the abort when an answer is `hang`. */
const scripted = (answers: readonly (Response | 'hang' | Error)[]) => {
  const calls: string[] = []
  let next = 0
  const fetch = ((input: string | URL | Request, init?: RequestInit) => {
    calls.push(String(input))
    const answer = answers[Math.min(next++, answers.length - 1)]

    if (answer === 'hang') {
      return new Promise((_, reject) =>
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      )
    }

    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer?.clone())
  }) as typeof globalThis.fetch

  return {calls, fetch}
}

describe('the Esplora backend', () => {
  test('reads the tip, summaries, history, transactions, statuses and fees as Esplora answers them', async () => {
    const esplora = createFakeEsplora()
    const backend = backendOver(esplora.fetch)
    const txid = esplora.fund([{address: STRANGER, value: 10_000}])
    esplora.mine()

    assert.deepEqual(await backend.tip(), {hash: esplora.blocks()[1]?.hash, height: 1})
    assert.equal(await backend.blockHash(5), undefined)

    const summary = await backend.addressSummary(STRANGER)
    assert.equal(summary.txCount, 1)
    assert.equal(summary.funded, 10_000n)
    assert.equal(summary.spent, 10_500n)

    const {next, transactions} = await backend.addressHistory(STRANGER)
    assert.equal(next, undefined)
    assert.equal(transactions[0]?.txid, txid)
    assert.equal(transactions[0]?.fee, 500n)
    assert.deepEqual(transactions[0]?.outputs, [{address: STRANGER, value: 10_000n}])
    assert.equal(transactions[0]?.status.confirmed, true)

    assert.equal((await backend.transaction(txid))?.txid, txid)
    assert.equal(await backend.transactionHex(txid), esplora.hex(txid))
    assert.deepEqual(await backend.transactionStatus(txid), {
      blockHash: esplora.blocks()[1]?.hash,
      blockTime: esplora.blocks()[1]?.time,
      confirmed: true,
      height: 1,
    })
    assert.equal(await backend.transaction('ab'.repeat(32)), undefined)
    assert.equal(await backend.transactionStatus('ab'.repeat(32)), undefined)
    await rejectsSync(backend.transaction('not a txid'), 'INVALID_ARGUMENT')
  })

  test('fees from mempool.space`s recommendation, or from the confirmation targets every Esplora has', async () => {
    const mempool = await backendOver(createFakeEsplora().fetch).feeEstimates()
    assert.deepEqual(
      [mempool.fastest, mempool.halfHour, mempool.hour, mempool.economy, mempool.minimum],
      [21, 11, 6, 2, 1]
    )
    assert.equal(mempool.byTarget[144], 1.4)

    const plain = await backendOver(createFakeEsplora({recommended: false}).fetch).feeEstimates()
    assert.deepEqual(
      [plain.fastest, plain.halfHour, plain.hour, plain.economy, plain.minimum],
      [20.5, 10.25, 5.1, 1.4, 1]
    )
  })

  test('history pages: the cursor is the last confirmed transaction of a full page', async () => {
    const esplora = createFakeEsplora()
    const backend = backendOver(esplora.fetch)

    for (let count = 0; count < 30; count++) {
      esplora.fund([{address: STRANGER, value: 1000 + count}])
      esplora.mine()
    }

    const first = await backend.addressHistory(STRANGER)
    assert.equal(first.transactions.length, 25)
    assert.equal(first.next, first.transactions[24]?.txid)

    const second = await backend.addressHistory(STRANGER, {after: first.next})
    assert.equal(second.transactions.length, 5)
    assert.equal(second.next, undefined)
  })

  test('429 and 5xx are retried with backoff (and Retry-After), and give up with their own codes', async () => {
    const esplora = createFakeEsplora()
    esplora.fail(/^\/blocks\/tip\/height$/, 429, 2, {'retry-after': '0'})
    esplora.fail(/^\/block-height\//, 503, 1)
    assert.equal((await backendOver(esplora.fetch).tip()).height, 0)
    assert.equal(esplora.requests.filter(request => request.includes('/blocks/tip/height')).length, 3)

    esplora.fail(/^\/blocks\/tip\/height$/, 429, 10)
    await rejectsSync(backendOver(esplora.fetch, {retries: 2}).tip(), 'RATE_LIMITED', /429/)

    const busy = scripted([new Response('down for maintenance', {status: 502})])
    await rejectsSync(backendOver(busy.fetch, {retries: 1}).tip(), 'BACKEND_ERROR', /502: down for maintenance/)
    assert.equal(busy.calls.length, 2)

    // A 4xx is an answer, not a hiccup: no retry.
    const refused = scripted([new Response('Invalid Bitcoin address', {status: 400})])
    await rejectsSync(backendOver(refused.fetch).addressSummary('x'), 'BACKEND_ERROR', /Invalid Bitcoin address/)
    assert.equal(refused.calls.length, 1)
  })

  test('a lost connection and a timeout are retried; the caller`s abort ends everything at once', async () => {
    const lost = scripted([new TypeError('Network request failed'), new Response('0011')])
    assert.equal(await backendOver(lost.fetch).transactionHex('ab'.repeat(32)), '0011')
    assert.equal(lost.calls.length, 2)
    await rejectsSync(
      backendOver(scripted([new TypeError('Network request failed')]).fetch, {retries: 1}).tip(),
      'NETWORK_ERROR'
    )

    const slow = scripted(['hang'])
    const started = Date.now()
    await rejectsSync(backendOver(slow.fetch, {retries: 1, timeoutMs: 20}).tip(), 'TIMEOUT')
    assert.equal(slow.calls.length, 2)
    assert.ok(Date.now() - started < 2000)

    const controller = new AbortController()
    const pending = backendOver(scripted(['hang']).fetch).tip({signal: controller.signal})
    setTimeout(() => controller.abort(), 10)
    await rejectsSync(pending, 'ABORTED')
    await rejectsSync(backendOver(scripted(['hang']).fetch).tip({signal: AbortSignal.abort()}), 'ABORTED')
  })

  test('at most `concurrency` requests in flight, across calls', async () => {
    let active = 0
    let peak = 0
    const fetch = (async () => {
      active++
      peak = Math.max(peak, active)
      await new Promise(resolve => setTimeout(resolve, 5))
      active--

      return new Response(JSON.stringify({chain_stats: STATS, mempool_stats: STATS}))
    }) as unknown as typeof globalThis.fetch
    const STATS = {funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0}
    const backend = esploraBackend({concurrency: 3, fetch, network: 'testnet', url: URL})

    await Promise.all(Array.from({length: 12}, () => backend.addressSummary(STRANGER)))
    assert.equal(peak, 3)

    const limit = createLimiter(1)
    const order: number[] = []
    await Promise.all([1, 2, 3].map(value => limit(async () => order.push(value))))
    assert.deepEqual(order, [1, 2, 3])
  })

  test('answers that are not Esplora`s are INVALID_RESPONSE; a node`s refusal is BROADCAST_REJECTED with its reason', async () => {
    await rejectsSync(
      backendOver(scripted([new Response('<html>')]).fetch).addressSummary(STRANGER),
      'INVALID_RESPONSE'
    )
    await rejectsSync(
      backendOver(scripted([new Response(JSON.stringify({chain_stats: {tx_count: -1}}))]).fetch).addressSummary(
        STRANGER
      ),
      'INVALID_RESPONSE'
    )
    await rejectsSync(backendOver(scripted([new Response('12x')]).fetch).tip(), 'INVALID_RESPONSE')

    const esplora = createFakeEsplora()
    await rejectsSync(backendOver(esplora.fetch).broadcast('0200000001'), 'BROADCAST_REJECTED')
    await rejectsSync(backendOver(esplora.fetch).broadcast('not hex'), 'INVALID_ARGUMENT')

    assert.equal(
      reasonOf('sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 110 < 141"}'),
      'min relay fee not met, 110 < 141'
    )
    assert.equal(reasonOf('Transaction not found'), 'Transaction not found')
  })
})
