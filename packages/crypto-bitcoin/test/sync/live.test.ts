import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {createBitcoinSync, esploraBackend, parseExtendedKey} from '../../src/sync'
import {ACCOUNT_PATH, chain, crypto} from './helpers'

/**
 * Against mempool.space's testnet4, for real: off unless `BITCOIN_SYNC_LIVE=1`, so the suite never depends on the
 * network or on a public server's limits. By default it follows a fresh account (a new phrase from the engine: a
 * handful of requests); `BITCOIN_SYNC_LIVE_KEY` (a tpub or vpub) follows that account instead. Not the published test
 * phrase's: its testnet4 account has hundreds of transactions, and mempool.space drops connections long before a
 * sync of it is done.
 *
 * BITCOIN_SYNC_LIVE=1 node --conditions=source --import tsx --test test/sync/live.test.ts
 */
const live = process.env.BITCOIN_SYNC_LIVE === '1'
const key = process.env.BITCOIN_SYNC_LIVE_KEY

describe('mempool.space testnet4', {
  skip: live ? false : 'set BITCOIN_SYNC_LIVE=1 to run against the network',
}, async () => {
  const wallet = await crypto.createEphemeralWallet()
  after(() => wallet.dispose())

  test('an account syncs, adds up, and resyncs without reading history again', async () => {
    const requests: string[] = []
    const backend = esploraBackend({
      concurrency: 2,
      fetch: (input, init) => {
        requests.push(String(input))

        return globalThis.fetch(input, init)
      },
      network: 'testnet',
    })
    const sync = createBitcoinSync({
      backend,
      chain,
      ...(key
        ? {extendedKey: parseExtendedKey(key, crypto.hash.sha256).extendedKey}
        : {extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH), fingerprint: wallet.fingerprint}),
      gapLimit: 5,
    })

    const view = await sync.sync()
    assert.ok((view.tip?.height ?? 0) > 0)
    assert.equal(
      view.balance.total,
      view.utxos.reduce((sum, utxo) => sum + utxo.value, 0n)
    )
    assert.equal(view.balance.total, view.balance.confirmed + view.balance.unconfirmed)

    const fees = await sync.feeEstimates()
    assert.ok(fees.minimum > 0 && fees.fastest >= fees.minimum)

    const [latest] = view.transactions

    if (latest) {
      assert.notEqual((await sync.transactionStatus(latest.txid)).status, 'unknown')
    }

    // Only what can have changed: pending transactions' addresses, at most.
    requests.length = 0
    await sync.sync()
    const pending = view.transactions.filter(transaction => transaction.confirmations === 0).length
    assert.ok(requests.filter(url => /\/txs(\/chain\/|$)/.test(url)).length <= pending * 2)
  })
})
