import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {
  createBitcoinSync,
  esploraBackend,
  type SyncFetch,
  type SyncRequestInit,
  type SyncResponse,
} from '../../src/sync'
import {createFakeEsplora, STRANGER} from './fake-esplora'
import {ACCOUNT_PATH, chain, openWallet, rejectsSync, URL} from './helpers'

const STATS = {funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0}

/** The least a client can answer: a status, one header, the body. No `Response`, no `Headers`. */
const minimal = (status: number, body: string, header: Record<string, string> = {}): SyncResponse => ({
  headers: {get: name => header[name.toLowerCase()] ?? null},
  ok: status >= 200 && status < 300,
  status,
  text: async () => body,
})

const summary = () => minimal(200, JSON.stringify({chain_stats: STATS, mempool_stats: STATS}))

// The global fetch, and a hand-written function, are SyncFetches as they are (react-native-nitro-fetch's `fetch` is
// checked where it is installed: the example app's type check).
const global: SyncFetch = globalThis.fetch
const handWritten: SyncFetch = async (url, {method, signal}) => {
  signal.throwIfAborted()

  return minimal(200, `${method} ${url}`)
}

describe('your own HTTP client', () => {
  test('a minimal client runs a whole sync and a payment, and the global fetch is never touched', async () => {
    const esplora = createFakeEsplora()
    const calls: SyncRequestInit[] = []
    // A client that is no `fetch` at all: it answers from the fake chain with plain objects.
    const client: SyncFetch = async (url, init) => {
      calls.push(init)
      const answer = await esplora.fetch(url, init)

      return minimal(answer.status, await answer.text(), {
        'retry-after': answer.headers.get('retry-after') ?? '',
      })
    }
    const original = globalThis.fetch
    globalThis.fetch = (() => {
      throw new Error('the global fetch was used')
    }) as typeof globalThis.fetch

    try {
      const wallet = await openWallet()
      const sync = createBitcoinSync({
        backend: esploraBackend({
          fetch: client,
          network: 'testnet',
          requestsPerSecond: Number.POSITIVE_INFINITY,
          url: URL,
        }),
        chain,
        extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH),
        fingerprint: wallet.fingerprint,
      })
      esplora.fund([{address: sync.addressAt(0, 0).address, value: 50_000}])
      esplora.mine()

      const view = await sync.sync()
      assert.equal(view.balance.total, 50_000n)

      const psbt = await sync.createPsbt(sync.createPayment({amount: 10_000n, feeRate: 2, to: STRANGER}))
      const signed = await sync.signPsbt(psbt, path => wallet.deriveAccount({chain: 'bitcoin', path}))
      const txid = await sync.broadcast(chain.finalizePsbt(signed))
      assert.ok(esplora.inMempool(txid))
      wallet.dispose()
    } finally {
      globalThis.fetch = original
    }

    // Every request carries a method, headers and a signal; only the broadcast has a body.
    assert.ok(calls.length > 40)
    assert.ok(calls.every(init => init.signal instanceof AbortSignal && typeof init.headers === 'object'))
    assert.deepEqual(
      calls.filter(init => init.body !== undefined).map(init => [init.method, init.headers['content-type']]),
      [['POST', 'text/plain']]
    )
    assert.ok(calls.filter(init => init.body === undefined).every(init => init.method === 'GET'))
    assert.equal(typeof global, 'function')
    assert.equal(typeof handWritten, 'function')
  })

  test('a client that honours the signal is cancelled at the timeout, and its slot is free at once', async () => {
    const signals: AbortSignal[] = []
    let calls = 0
    const client: SyncFetch = (_url, {signal}) => {
      calls++
      signals.push(signal)

      if (calls > 1) {
        return Promise.resolve(summary())
      }

      return new Promise((_, reject) =>
        signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), {once: true})
      )
    }
    const backend = esploraBackend({
      concurrency: 1,
      fetch: client,
      network: 'testnet',
      retries: 0,
      timeoutMs: 30,
      url: URL,
    })

    const started = Date.now()
    const [hung, next] = await Promise.allSettled([backend.addressSummary(STRANGER), backend.addressSummary(STRANGER)])

    assert.equal(hung.status, 'rejected')
    assert.equal((hung as PromiseRejectedResult).reason.code, 'TIMEOUT')
    assert.equal(next.status, 'fulfilled')
    assert.equal(signals[0]?.aborted, true)
    assert.ok(Date.now() - started < 300)
  })

  test('a client that ignores the signal: TIMEOUT on time, and its slot held until it settles', async () => {
    const starts: number[] = []
    let running = 0
    let peak = 0
    // Ignores the signal and answers after 150 ms, whatever happened in between.
    const stubborn: SyncFetch = async () => {
      starts.push(Date.now())
      running++
      peak = Math.max(peak, running)
      await new Promise(resolve => setTimeout(resolve, 150))
      running--

      return summary()
    }
    const backend = esploraBackend({
      concurrency: 1,
      fetch: stubborn,
      network: 'testnet',
      retries: 0,
      timeoutMs: 30,
      url: URL,
    })

    const started = Date.now()
    const first = backend.addressSummary(STRANGER)
    const second = backend.addressSummary(STRANGER)

    await rejectsSync(first, 'TIMEOUT')
    const timedOutAfter = Date.now() - started
    assert.ok(timedOutAfter < 120, `TIMEOUT after ${timedOutAfter} ms`)

    // The second request starts only once the first one's client settles: never two at once.
    await rejectsSync(second, 'TIMEOUT')
    assert.equal(peak, 1)
    assert.ok((starts[1] ?? 0) - (starts[0] ?? 0) >= 145, `${(starts[1] ?? 0) - (starts[0] ?? 0)} ms apart`)

    // The caller's abort is just as prompt.
    const controller = new AbortController()
    const aborted = backend.addressSummary(STRANGER, {signal: controller.signal})
    setTimeout(() => controller.abort(), 10)
    const abortedAt = Date.now()
    await rejectsSync(aborted, 'ABORTED')
    // It waited for the previous request's slot (up to 150 ms), then for nothing.
    assert.ok(Date.now() - abortedAt < 200)
    await new Promise(resolve => setTimeout(resolve, 200))
    assert.equal(running, 0)
  })

  test('a waiter whose caller aborts leaves the queue: it never takes a slot', async () => {
    let calls = 0
    const slow: SyncFetch = async () => {
      calls++
      await new Promise(resolve => setTimeout(resolve, 40))

      return summary()
    }
    const backend = esploraBackend({concurrency: 1, fetch: slow, network: 'testnet', url: URL})
    const controller = new AbortController()

    const first = backend.addressSummary(STRANGER)
    const queued = backend.addressSummary(STRANGER, {signal: controller.signal})
    const third = backend.addressSummary(STRANGER)
    controller.abort()

    await rejectsSync(queued, 'ABORTED')
    await Promise.all([first, third])
    assert.equal(calls, 2)
  })

  test('a client that rejects (no connection) is a NETWORK_ERROR, retried with backoff, then UNREACHABLE', async () => {
    let calls = 0
    const offline: SyncFetch = async () => {
      calls++
      throw new Error('Network request failed')
    }
    const backend = esploraBackend({fetch: offline, network: 'testnet', retries: 1, retryDelayMs: 1, url: URL})

    await rejectsSync(backend.tip(), 'NETWORK_ERROR')
    assert.equal(calls, 2)
    await rejectsSync(backend.tip(), 'NETWORK_ERROR')
    await rejectsSync(backend.tip(), 'UNREACHABLE')
    assert.equal(calls, 5)
  })
})
