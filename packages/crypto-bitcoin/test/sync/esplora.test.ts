import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {createBitcoinSync, esploraBackend, isPublicEsplora, PUBLIC_PACING} from '../../src/sync'
import {createLimiter, reasonOf} from '../../src/sync/http'
import {createFakeEsplora, STRANGER} from './fake-esplora'
import {chain, openWallet, rejectsSync, URL} from './helpers'

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

    const limiter = createLimiter(1)
    const order: number[] = []
    await Promise.all([1, 2, 3].map(value => limiter.run(async () => order.push(value))))
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

/** A `fetch` that answers every address summary after `latency` ms, recording when each request started. */
const timed = (latency = 0) => {
  const starts: number[] = []
  let active = 0
  let peak = 0
  const STATS = {funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0}
  const fetch = (async () => {
    starts.push(Date.now())
    active++
    peak = Math.max(peak, active)
    await new Promise(resolve => setTimeout(resolve, latency))
    active--

    return new Response(JSON.stringify({chain_stats: STATS, mempool_stats: STATS}))
  }) as unknown as typeof globalThis.fetch

  return {fetch, peak: () => peak, starts}
}

/** Whether request `i` started no earlier than its slot: `burst` at once, then one per `interval` ms. */
const paced = (starts: readonly number[], burst: number, interval: number) =>
  starts.every((start, index) => start - (starts[0] ?? 0) >= Math.max(0, index - burst + 1) * interval - 3)

describe('pacing', () => {
  test('request starts are spaced across every call of a backend: a burst, then the rate', async () => {
    const server = timed()
    const backend = esploraBackend({
      burst: 3,
      fetch: server.fetch,
      network: 'testnet',
      requestsPerSecond: 100,
      url: URL,
    })

    await Promise.all(Array.from({length: 13}, () => backend.addressSummary(STRANGER)))

    assert.equal(server.starts.length, 13)
    assert.ok(paced(server.starts, 3, 10), `starts: ${server.starts.map(start => start - (server.starts[0] ?? 0))}`)
    assert.ok((server.starts[12] ?? 0) - (server.starts[0] ?? 0) >= 97)
  })

  test('public servers get polite defaults, your own fast ones', async () => {
    assert.equal(isPublicEsplora('https://mempool.space/testnet4/api'), true)
    assert.equal(isPublicEsplora('https://blockstream.info/testnet/api'), true)
    assert.equal(isPublicEsplora('https://API.mempool.space/api'), true)
    assert.equal(isPublicEsplora('https://mempool.space.example.com/api'), false)
    assert.equal(isPublicEsplora('https://esplora.example.com/api'), false)
    assert.equal(isPublicEsplora('http://localhost:3002'), false)
    assert.deepEqual(PUBLIC_PACING, {burst: 5, concurrency: 2, requestsPerSecond: 2, retryDelayMs: 1000})

    // mempool.space, by default: five at once, then one every half second, never more than two in flight.
    const publicServer = timed(20)
    const polite = esploraBackend({fetch: publicServer.fetch, network: 'testnet'})
    await Promise.all(Array.from({length: 7}, () => polite.addressSummary(STRANGER)))
    assert.ok(paced(publicServer.starts, 5, 500))
    assert.ok((publicServer.starts[6] ?? 0) - (publicServer.starts[0] ?? 0) >= 997)
    assert.equal(publicServer.peak(), 2)

    // Your own server: twenty at once, eight in flight.
    const ownServer = timed(20)
    const own = esploraBackend({fetch: ownServer.fetch, network: 'testnet', url: 'https://esplora.example.com/api'})
    await Promise.all(Array.from({length: 7}, () => own.addressSummary(STRANGER)))
    assert.ok((ownServer.starts[6] ?? 0) - (ownServer.starts[0] ?? 0) < 100)
    assert.equal(ownServer.peak(), 7)
  })

  test('a long first sync stays under the pace, history reads included', async () => {
    const esplora = createFakeEsplora()
    const starts: number[] = []
    const fetch = ((input: string | URL | Request, init?: RequestInit) => {
      starts.push(Date.now())

      return esplora.fetch(input, init)
    }) as typeof globalThis.fetch
    const wallet = await openWallet()
    const backend = esploraBackend({burst: 4, fetch, network: 'testnet', requestsPerSecond: 400, url: URL})
    const sync = createBitcoinSync({backend, chain, extendedKey: wallet.extendedPublicKey("m/84'/1'/0'")})
    const account = (index: number) => sync.addressAt(0, index).address

    for (let count = 0; count < 30; count++) {
      esplora.fund([
        {address: account(count % 6), value: 1_000 + count},
        {address: account(20), value: 1_000},
      ])
      esplora.mine()
    }

    const view = await sync.sync()
    assert.equal(view.transactions.length, 30)
    assert.ok(starts.length >= 70, `${starts.length} requests`)
    assert.ok(
      starts.some(start => start - (starts[0] ?? 0) > 150),
      'the history reads waited their turn'
    )
    assert.ok(paced(starts, 4, 2.5))
    wallet.dispose()
  })
})

describe('an unreachable server', () => {
  test('is left alone after repeated connection failures: UNREACHABLE at once, nothing sent, until the pause passes', async () => {
    let calls = 0
    const refused = (() => {
      calls++

      return Promise.reject(new TypeError('fetch failed'))
    }) as unknown as typeof globalThis.fetch
    const backend = esploraBackend({
      fetch: refused,
      network: 'testnet',
      retries: 5,
      retryDelayMs: 1,
      unreachableAfter: 3,
      unreachablePauseMs: 60,
      url: URL,
    })

    // Three refusals, retries and all, and the backend stops trying.
    await rejectsSync(backend.addressSummary(STRANGER), 'UNREACHABLE', /3 times in a row/)
    assert.equal(calls, 3)
    await rejectsSync(backend.addressSummary(STRANGER), 'UNREACHABLE')
    await rejectsSync(backend.tip(), 'UNREACHABLE')
    assert.equal(calls, 3)

    // After the pause, one request tries; it fails, and the pause doubles.
    await new Promise(resolve => setTimeout(resolve, 70))
    await rejectsSync(backend.addressSummary(STRANGER), 'UNREACHABLE')
    assert.equal(calls, 4)
    await new Promise(resolve => setTimeout(resolve, 70))
    await rejectsSync(backend.addressSummary(STRANGER), 'UNREACHABLE')
    assert.equal(calls, 4)
  })

  test('a connection that times out counts; any answer, even an error, proves the server reachable', async () => {
    const slow = scripted(['hang'])
    const hanging = esploraBackend({
      fetch: slow.fetch,
      network: 'testnet',
      retries: 5,
      retryDelayMs: 1,
      timeoutMs: 10,
      unreachableAfter: 2,
      url: URL,
    })
    await rejectsSync(hanging.tip(), 'UNREACHABLE')
    assert.equal(slow.calls.length, 2)

    // Refused, refused, a 503, refused, refused: never three refusals in a row.
    const mixed = scripted([
      new TypeError('fetch failed'),
      new TypeError('fetch failed'),
      new Response('busy', {status: 503}),
      new TypeError('fetch failed'),
      new TypeError('fetch failed'),
      new Response('0011'),
    ])
    const flaky = esploraBackend({
      fetch: mixed.fetch,
      network: 'testnet',
      retries: 5,
      retryDelayMs: 1,
      unreachableAfter: 3,
      url: URL,
    })
    assert.equal(await flaky.transactionHex('ab'.repeat(32)), '0011')
    assert.equal(mixed.calls.length, 6)
  })
})
