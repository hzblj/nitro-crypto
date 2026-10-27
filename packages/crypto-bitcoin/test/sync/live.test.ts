import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {createBitcoinSync, esploraBackend, parseExtendedKey} from '../../src/sync'
import {ACCOUNT_PATH, chain, crypto} from './helpers'

/**
 * Against a real Esplora: off unless `BITCOIN_SYNC_LIVE=1`, so the suite never depends on the network or on a public
 * server's limits. mempool.space's testnet4 unless `BITCOIN_SYNC_LIVE_URL` names another (blockstream.info's
 * `https://blockstream.info/testnet/api` serves testnet3, whose addresses look the same: a fresh account works on
 * both). It follows a fresh account (a new phrase from the engine: a few dozen requests, paced as the backend's
 * defaults pace that server), or the tpub or vpub in `BITCOIN_SYNC_LIVE_KEY`. Not the published test phrase's: its
 * testnet4 account has hundreds of transactions, and syncing it unpaced got this machine's IP address blocked by
 * mempool.space.
 *
 * BITCOIN_SYNC_LIVE=1 BITCOIN_SYNC_LIVE_URL=https://blockstream.info/testnet/api \
 *   node --conditions=source --import tsx --test test/sync/live.test.ts
 */
const live = process.env.BITCOIN_SYNC_LIVE === '1'
const url = process.env.BITCOIN_SYNC_LIVE_URL || undefined
const key = process.env.BITCOIN_SYNC_LIVE_KEY

describe(`Esplora at ${url ?? 'mempool.space testnet4'}`, {
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
      url,
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
