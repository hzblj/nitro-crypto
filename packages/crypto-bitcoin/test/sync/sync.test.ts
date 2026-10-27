import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {type AccountView, createBitcoinSync, type SyncSnapshot} from '../../src/sync'
import {STRANGER} from './fake-esplora'
import {chain, historyReads, referenceAddress, setup, throwsSync} from './helpers'

const receive = (index: number) => referenceAddress(0, index)
const change = (index: number) => referenceAddress(1, index)

const indexes = (view: AccountView) => view.addresses.map(address => `${address.change}/${address.index}`)

describe('discovery', () => {
  test('finds every address up to the gap limit past the last used one, on both branches', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: receive(0), value: 10_000},
      {address: receive(5), value: 20_000},
      {address: receive(24), value: 30_000},
      {address: receive(50), value: 40_000},
      {address: change(2), value: 50_000},
    ])
    esplora.mine()

    const view = await sync.sync()

    // 50 is 26 past 24: beyond a gap of 20.
    assert.deepEqual(indexes(view), ['0/0', '0/5', '0/24', '1/2'])
    assert.equal(view.balance.total, 110_000n)
    assert.equal(view.balance.confirmed, 110_000n)
    assert.equal(view.receiveAddress.address, receive(25))
    assert.equal(view.receiveAddress.path, "m/84'/1'/0'/0/25")
    assert.equal(view.changeAddress.address, change(3))
    assert.equal(view.utxos.length, 4)
    assert.equal(view.tip?.height, 1)

    // Every summary up to 24 + 20 and 2 + 20, and nothing past them.
    const summaries = esplora.requests.filter(request => /^GET \/address\/[a-z0-9]+$/.test(request))
    assert.equal(summaries.length, 45 + 23)
    assert.equal(summaries.includes(`GET /address/${receive(45)}`), false)
    wallet.dispose()
  })

  test('a wider gap limit finds what a narrow one misses', async () => {
    const {esplora, sync, wallet} = await setup({sync: {gapLimit: 30}})
    esplora.fund([
      {address: receive(24), value: 30_000},
      {address: receive(50), value: 40_000},
    ])

    const view = await sync.sync()
    assert.deepEqual(indexes(view), ['0/24', '0/50'])
    assert.equal(view.balance.unconfirmed, 70_000n)
    assert.equal(view.receiveAddress.index, 51)
    wallet.dispose()
  })
})

describe('incremental sync', () => {
  test('reads history only for the addresses whose summary changed', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: receive(0), value: 10_000},
      {address: receive(3), value: 20_000},
      {address: change(1), value: 5_000},
    ])
    esplora.mine()
    await sync.sync()

    esplora.reset()
    await sync.sync()
    assert.deepEqual(historyReads(esplora.requests), [])
    assert.equal(esplora.requests.filter(request => request.startsWith('GET /tx/')).length, 0)
    // The tip is unchanged: no block is compared.
    assert.deepEqual(esplora.requests.slice(0, 2), ['GET /blocks/tip/height', 'GET /block-height/1'])

    esplora.reset()
    esplora.fund([{address: receive(3), value: 7_000}])
    const view = await sync.sync()
    assert.deepEqual(historyReads(esplora.requests), [receive(3)])
    assert.equal(view.balance.unconfirmed, 7_000n)
    assert.equal(view.balance.total, 42_000n)
    wallet.dispose()
  })

  test('a pending transaction confirms, and its confirmations follow the tip', async () => {
    const {esplora, sync, wallet} = await setup()
    const txid = esplora.fund([{address: receive(0), value: 10_000}])

    let view = await sync.sync()
    assert.equal(view.transactions[0]?.confirmations, 0)
    assert.equal(view.transactions[0]?.replaceable, true)
    assert.ok(view.transactions[0]?.firstSeen)
    assert.deepEqual([view.balance.confirmed, view.balance.unconfirmed], [0n, 10_000n])
    // A stranger's unconfirmed coin is not trusted: a payment does not spend it by default.
    assert.equal(view.balance.spendable, 0n)
    assert.equal(view.utxos[0]?.trusted, false)

    esplora.mine()
    view = await sync.sync()
    assert.equal(view.transactions[0]?.txid, txid)
    assert.equal(view.transactions[0]?.confirmations, 1)
    assert.equal(view.transactions[0]?.height, 1)
    assert.deepEqual([view.balance.confirmed, view.balance.unconfirmed, view.balance.spendable], [10_000n, 0n, 10_000n])

    esplora.mine()
    esplora.mine()
    view = await sync.sync()
    assert.equal(view.transactions[0]?.confirmations, 3)
    assert.equal(view.utxos[0]?.confirmations, 3)
    wallet.dispose()
  })

  test('a dropped transaction is forgotten, and a replaced one gives way to its replacement', async () => {
    const {esplora, sync, wallet} = await setup()
    const dropped = esplora.fund([{address: receive(0), value: 10_000}])
    // The sender bumps their fee from their own change: the account's address sees the same amount either way.
    const original = esplora.fund([
      {address: receive(1), value: 20_000},
      {address: STRANGER, value: 5_000},
    ])

    let view = await sync.sync()
    assert.equal(view.balance.unconfirmed, 30_000n)

    esplora.drop(dropped)
    const replacement = esplora.replace(original, [
      {address: receive(1), value: 20_000},
      {address: STRANGER, value: 4_000},
    ])
    view = await sync.sync()

    assert.deepEqual(
      view.transactions.map(transaction => transaction.txid),
      [replacement]
    )
    assert.equal(view.balance.unconfirmed, 20_000n)
    assert.equal(view.receiveAddress.index, 2)
    wallet.dispose()
  })

  test('reorganizations: a transaction moved to another block, back to the mempool, or gone', async () => {
    const {esplora, sync, wallet} = await setup()
    const moved = esplora.fund([{address: receive(0), value: 10_000}])
    esplora.mine()
    const before = (await sync.sync()).transactions[0]

    // The block is replaced by another with the same transaction, and one more on top.
    esplora.reorg(1, {mine: 2})
    let view = await sync.sync()
    assert.equal(view.transactions[0]?.txid, moved)
    assert.notEqual(view.transactions[0]?.blockHash, before?.blockHash)
    assert.equal(view.transactions[0]?.confirmations, 2)

    // Back to the mempool.
    const unmined = esplora.fund([{address: receive(1), value: 5_000}])
    esplora.mine()
    await sync.sync()
    esplora.reorg(1)
    view = await sync.sync()
    assert.equal(view.transactions.find(transaction => transaction.txid === unmined)?.confirmations, 0)
    assert.deepEqual([view.balance.confirmed, view.balance.unconfirmed], [10_000n, 5_000n])

    // Gone: reorganized away and never mined again.
    esplora.mine()
    await sync.sync()
    esplora.reorg(1, {drop: [unmined], mine: 2})
    view = await sync.sync()
    assert.equal(
      view.transactions.some(transaction => transaction.txid === unmined),
      false
    )
    assert.equal(view.balance.total, 10_000n)
    wallet.dispose()
  })

  test('concurrent calls share one run, and maxAgeMs skips the network', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([{address: receive(0), value: 10_000}])

    const [first, second] = await Promise.all([sync.sync(), sync.sync()])
    assert.equal(first, second)
    assert.equal(esplora.requests.filter(request => request === 'GET /blocks/tip/height').length, 1)

    esplora.reset()
    assert.equal(await sync.sync({maxAgeMs: 60_000}), first)
    assert.deepEqual(esplora.requests, [])

    const seen: AccountView[] = []
    const unsubscribe = sync.subscribe(view => seen.push(view))
    await sync.sync()
    unsubscribe()
    await sync.sync()
    assert.equal(seen.length, 1)
    wallet.dispose()
  })

  test('a failed sync leaves the state as it was', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([{address: receive(0), value: 10_000}])
    const view = await sync.sync()

    esplora.fund([{address: receive(1), value: 5_000}])
    esplora.fail(/\/txs$/, 500, 100)
    await assert.rejects(sync.sync())
    assert.equal(sync.view(), view)
    wallet.dispose()
  })
})

describe('snapshots', () => {
  test('survive JSON, restore the same view without the network, and resume with only what changed', async () => {
    const {backend, esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: receive(0), value: 10_000},
      {address: change(0), value: 3_000},
    ])
    esplora.mine()
    esplora.fund([{address: receive(2), value: 2_000}])
    const view = await sync.sync()

    const snapshot = JSON.parse(JSON.stringify(sync.snapshot())) as SyncSnapshot
    assert.equal(snapshot.version, 1)
    assert.equal(snapshot.addresses.length, 3)
    assert.equal(typeof snapshot.transactions[0]?.outputs[0]?.value, 'string')

    esplora.reset()
    const requests: readonly string[] = esplora.requests
    const restored = createBitcoinSync({
      backend,
      chain,
      extendedKey: wallet.extendedPublicKey("m/84'/1'/0'"),
      fingerprint: wallet.fingerprint,
      snapshot,
    })
    const offline = restored.view()
    assert.equal(requests.length, 0)
    assert.deepEqual(offline.balance, view.balance)
    assert.deepEqual(offline.utxos, view.utxos)
    assert.deepEqual(offline.transactions, view.transactions)
    assert.equal(offline.receiveAddress.address, view.receiveAddress.address)

    // Only the pending transaction is asked about.
    await restored.sync()
    assert.deepEqual(historyReads(requests), [])
    assert.equal(requests.filter(request => request.startsWith('GET /tx/')).length, 1)
    wallet.dispose()
  })

  test('long histories page, and a snapshot the backend disagrees with heals: what it no longer lists is forgotten', async () => {
    const {backend, esplora, sync, wallet} = await setup()

    for (let count = 0; count < 30; count++) {
      esplora.fund([{address: receive(0), value: 1_000 + count}])
      esplora.mine()
    }

    const view = await sync.sync()
    assert.equal(view.transactions.length, 30)
    assert.deepEqual(historyReads(esplora.requests), [receive(0), receive(0)])

    // A transaction the backend never had, and a summary that no longer matches the backend's.
    const snapshot = JSON.parse(JSON.stringify(sync.snapshot()))
    snapshot.transactions.push({...snapshot.transactions[0], txid: 'ee'.repeat(32)})
    snapshot.addresses[0].summary.txCount = 31
    const restored = createBitcoinSync({
      backend,
      chain,
      extendedKey: wallet.extendedPublicKey("m/84'/1'/0'"),
      fingerprint: wallet.fingerprint,
      snapshot,
    })
    assert.equal(restored.view().transactions.length, 31)

    const healed = await restored.sync()
    assert.equal(healed.transactions.length, 30)
    assert.deepEqual(healed.balance, view.balance)
    assert.equal(restored.snapshot().addresses[0]?.summary?.txCount, 30)
    wallet.dispose()
  })

  test('another account`s snapshot, or a damaged one, is refused', async () => {
    const {backend, esplora, sync, wallet} = await setup()
    esplora.fund([{address: receive(0), value: 10_000}])
    await sync.sync()
    const snapshot = sync.snapshot()
    const other = {backend, chain, extendedKey: wallet.extendedPublicKey("m/84'/1'/1'")}

    throwsSync(() => createBitcoinSync({...other, snapshot}), 'SNAPSHOT_MISMATCH')
    throwsSync(
      () =>
        createBitcoinSync({
          backend,
          chain,
          extendedKey: wallet.extendedPublicKey("m/84'/1'/0'"),
          snapshot: {...snapshot, version: 2 as 1},
        }),
      'INVALID_SNAPSHOT'
    )

    const damaged = JSON.parse(JSON.stringify(snapshot))
    damaged.transactions[0].outputs[0].value = '-1'
    throwsSync(
      () =>
        createBitcoinSync({backend, chain, extendedKey: wallet.extendedPublicKey("m/84'/1'/0'"), snapshot: damaged}),
      'INVALID_SNAPSHOT'
    )
    wallet.dispose()
  })
})

describe('history', () => {
  test('a payment in, from the account`s side', async () => {
    const {esplora, sync, wallet} = await setup()
    const txid = esplora.fund([
      {address: receive(0), value: 10_000},
      {address: STRANGER, value: 1_000},
    ])
    esplora.mine()

    const [transaction] = (await sync.sync()).transactions
    assert.deepEqual(
      {
        amount: transaction?.amount,
        counterparties: transaction?.counterparties,
        fee: transaction?.fee,
        kind: transaction?.kind,
        net: transaction?.net,
        received: transaction?.received,
        sent: transaction?.sent,
        transactionFee: transaction?.transactionFee,
        txid: transaction?.txid,
      },
      {
        amount: 10_000n,
        counterparties: [STRANGER],
        fee: 0n,
        kind: 'received',
        net: 10_000n,
        received: 10_000n,
        sent: 0n,
        transactionFee: 500n,
        txid,
      }
    )
    wallet.dispose()
  })

  test('sent, a consolidation, and a transaction that shares its inputs', async () => {
    const {esplora, sync, wallet} = await setup()
    const funding = esplora.fund([
      {address: receive(0), value: 50_000},
      {address: receive(1), value: 30_000},
      {address: STRANGER, value: 9_000},
    ])
    esplora.mine()

    // Sent: 20 000 to a stranger, change back to the account, 1 000 to the miners.
    const sent = esplora.add(
      [{txid: funding, vout: 0}],
      [
        {address: STRANGER, value: 20_000},
        {address: change(0), value: 29_000},
      ]
    )
    // A consolidation: the account's coin to the account, 500 to the miners.
    const self = esplora.add([{txid: funding, vout: 1}], [{address: receive(2), value: 29_500}])
    esplora.mine()
    // A stranger's coin and the account's change in one transaction.
    const shared = esplora.add(
      [
        {txid: sent, vout: 1},
        {txid: funding, vout: 2},
      ],
      [
        {address: STRANGER, value: 30_000},
        {address: receive(3), value: 7_000},
      ]
    )

    const view = await sync.sync()
    const byId = new Map(view.transactions.map(transaction => [transaction.txid, transaction]))

    assert.deepEqual(
      [
        byId.get(sent)?.kind,
        byId.get(sent)?.amount,
        byId.get(sent)?.fee,
        byId.get(sent)?.net,
        byId.get(sent)?.counterparties,
      ],
      ['sent', 20_000n, 1_000n, -21_000n, [STRANGER]]
    )
    assert.deepEqual(
      [
        byId.get(self)?.kind,
        byId.get(self)?.amount,
        byId.get(self)?.fee,
        byId.get(self)?.net,
        byId.get(self)?.counterparties,
      ],
      ['self', 29_500n, 500n, -500n, []]
    )
    // Who paid the 1 000-sat fee is not written anywhere: `fee` is undefined, `net` is what is certain.
    assert.deepEqual(
      [byId.get(shared)?.kind, byId.get(shared)?.fee, byId.get(shared)?.transactionFee, byId.get(shared)?.net],
      ['sent', undefined, 1_000n, -22_000n]
    )
    assert.equal(view.transactions[0]?.txid, shared)

    // A confirmed coin spent in the mempool: still confirmed, taken back by the mempool's delta.
    assert.deepEqual(
      [view.balance.confirmed, view.balance.unconfirmed, view.balance.total],
      [29_000n + 29_500n, 7_000n - 29_000n, 29_500n + 7_000n]
    )
    assert.equal(
      view.balance.total,
      view.utxos.reduce((sum, utxo) => sum + utxo.value, 0n)
    )
    assert.deepEqual(
      view.addresses.map(address => [address.change, address.index, address.transactions, address.balance]),
      [
        [0, 0, 2, 0n],
        [0, 1, 2, 0n],
        [0, 2, 1, 29_500n],
        [0, 3, 1, 7_000n],
        [1, 0, 2, 0n],
      ]
    )
    wallet.dispose()
  })
})
