import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {hex} from '@hzblj/nitro-crypto/adapter'
import {Transaction} from '@scure/btc-signer'

import type {BitcoinAccount} from '../../src'
import {type BitcoinSync, createBitcoinSync, esploraBackend, type Payment, type SignerRequest} from '../../src/sync'
import {STRANGER} from './fake-esplora'
import {
  ACCOUNT_PATH,
  chain,
  reference,
  referenceAddress,
  referenceKey,
  rejectsSync,
  setup,
  throwsSync,
  URL,
} from './helpers'

const receive = (index: number) => referenceAddress(0, index)
const change = (index: number) => referenceAddress(1, index)

const HARDENED = 0x80000000

/** `m/84'/1'/0'/1/2` as BIP-32 indexes, the way btc-signer writes a derivation. */
const indexesOf = (path: string) =>
  path
    .split('/')
    .slice(1)
    .map(step => (step.endsWith("'") ? Number.parseInt(step, 10) + HARDENED : Number(step)))

/** Signs every input with @scure/bip32's keys and finalizes: the same transaction, signed elsewhere. */
const signedByScure = (psbt: Uint8Array, payment: Payment) => {
  const transaction = Transaction.fromPSBT(psbt)

  payment.inputs.forEach((coin, index) => {
    transaction.signIdx(referenceKey(coin.change, coin.index).privateKey ?? new Uint8Array(), index)
  })
  transaction.finalize()

  return hex.encode(transaction.extract())
}

const engineSigner = (wallet: Awaited<ReturnType<typeof setup>>['wallet']) => (request: SignerRequest) =>
  wallet.deriveAccount({chain: 'bitcoin', ...request}) as Promise<BitcoinAccount<string>>

/** Plans, writes, signs in the engine, finalizes and broadcasts: a hot wallet's send. */
const send = async (sync: BitcoinSync, wallet: Awaited<ReturnType<typeof setup>>['wallet'], payment: Payment) => {
  const psbt = await sync.createPsbt(payment)
  const final = chain.finalizePsbt(await sync.signPsbt(psbt, engineSigner(wallet)))
  await sync.broadcast(final)

  return final
}

describe('payments', () => {
  test('coin selection: largest first over trusted coins, change to the next change address', async () => {
    const {esplora, sync, wallet} = await setup()
    const funding = esplora.fund([
      {address: receive(0), value: 50_000},
      {address: receive(1), value: 30_000},
      {address: receive(2), value: 20_000},
    ])
    esplora.mine()
    esplora.fund([{address: receive(3), value: 100_000}])
    await sync.sync()

    const payment = sync.createPayment({amount: 60_000n, feeRate: 2, to: STRANGER})
    assert.deepEqual(
      payment.inputs.map(coin => [coin.address, coin.value, coin.path]),
      [
        [receive(0), 50_000n, `${ACCOUNT_PATH}/0/0`],
        [receive(1), 30_000n, `${ACCOUNT_PATH}/0/1`],
      ]
    )
    assert.equal(payment.plan.outputs[1]?.address, change(0))
    assert.equal(payment.change?.path, `${ACCOUNT_PATH}/1/0`)
    assert.equal(payment.plan.fee, BigInt(Math.ceil(payment.plan.vsize * 2)))
    assert.equal(payment.replaces, undefined)

    // A stranger's unconfirmed coin only when asked for; none at all with `none`.
    assert.deepEqual(
      sync
        .createPayment({amount: 60_000n, feeRate: 2, to: STRANGER, unconfirmed: 'all'})
        .inputs.map(coin => coin.value),
      [100_000n]
    )

    const max = sync.createPayment({amount: 'max', feeRate: 1, to: STRANGER})
    assert.equal(max.plan.amount + max.plan.fee, 100_000n)
    assert.equal(max.change, undefined)

    const controlled = sync.createPayment({amount: 5_000n, coins: [{txid: funding, vout: 2}], feeRate: 1, to: STRANGER})
    assert.deepEqual(
      controlled.inputs.map(coin => coin.vout),
      [2]
    )

    throwsSync(
      () => sync.createPayment({amount: 100_000_000n, feeRate: 2, to: STRANGER}),
      'INSUFFICIENT_FUNDS',
      /short/
    )
    throwsSync(
      () => sync.createPayment({amount: 1_000n, coins: [{txid: 'ab'.repeat(32), vout: 0}], feeRate: 1, to: STRANGER}),
      'UNKNOWN_COIN'
    )
    throwsSync(
      () => sync.createPayment({amount: 1_000n, feeRate: 1, to: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'}),
      'INVALID_ADDRESS'
    )
    throwsSync(() => sync.createPayment({amount: 1_000n, feeRate: 0, to: STRANGER}), 'INVALID_ARGUMENT')
    throwsSync(() => sync.createPayment({amount: 100n, feeRate: 1, to: STRANGER}), 'INVALID_ARGUMENT', /dust/)
    wallet.dispose()
  })

  test('one PSBT for coins of several addresses: every key`s origin, read by btc-signer, signed by the engine', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: receive(0), value: 20_000},
      {address: receive(3), value: 15_000},
      {address: change(1), value: 10_000},
    ])
    esplora.mine()
    await sync.sync()

    const payment = sync.createPayment({amount: 40_000n, feeRate: 3, to: STRANGER})
    assert.equal(payment.inputs.length, 3)

    const psbt = await sync.createPsbt(payment)
    const theirs = Transaction.fromPSBT(psbt)

    payment.inputs.forEach((coin, index) => {
      const input = theirs.getInput(index)
      const [origin] = input.bip32Derivation ?? []

      assert.deepEqual(origin?.[0], referenceKey(coin.change, coin.index).publicKey)
      assert.equal(origin?.[1].fingerprint, reference.fingerprint)
      assert.deepEqual(origin?.[1].path, indexesOf(coin.path ?? ''))
      assert.deepEqual(input.witnessUtxo?.script, coin.scriptPubKey)
      assert.equal(input.witnessUtxo?.amount, coin.value)
      assert.ok(input.nonWitnessUtxo, 'each coin`s previous transaction')
      assert.equal(input.sequence, 0xfffffffd)
    })

    // Change goes to the first unused change address, 1/2, and says so; the payment does not.
    assert.equal(payment.change?.address, change(2))
    assert.equal(theirs.getOutput(0).bip32Derivation, undefined)
    assert.deepEqual(theirs.getOutput(1).bip32Derivation?.[0]?.[1].path, indexesOf(`${ACCOUNT_PATH}/1/2`))

    const decoded = chain.decodePsbt(psbt)
    assert.equal(decoded.fee, payment.plan.fee)
    assert.ok(decoded.inputs.every(input => input.verifiedValue))

    // The engine signs each key's inputs; btc-signer, with @scure/bip32's keys, makes the same transaction.
    const signed = await sync.signPsbt(psbt, engineSigner(wallet))
    const final = chain.finalizePsbt(signed)
    assert.equal(final.hex, signedByScure(psbt, payment))
    assert.equal(final.txid, decoded.txid)

    // Without previous transactions: witness UTXOs only, and nothing asked of the backend.
    esplora.reset()
    const light = Transaction.fromPSBT(await sync.createPsbt(payment, {previousTransactions: false}))
    assert.equal(light.getInput(0).nonWitnessUtxo, undefined)
    assert.deepEqual(esplora.requests, [])

    // A key that is not the one the PSBT names is refused before it signs anything.
    await rejectsSync(
      sync.signPsbt(psbt, () => wallet.deriveAccount({chain: 'bitcoin', index: 7}) as Promise<BitcoinAccount<string>>),
      'KEY_MISMATCH'
    )
    wallet.dispose()
  })

  test('a broadcast is recorded at once: its coins spent, its change trusted, and the next sync agrees', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([{address: receive(0), value: 50_000}])
    esplora.mine()
    await sync.sync()

    const payment = sync.createPayment({amount: 20_000n, feeRate: 2, to: STRANGER})
    // The same coin, another payment: signed now, broadcast once the first is in a block.
    const alternative = chain.finalizePsbt(
      await sync.signPsbt(
        await sync.createPsbt(sync.createPayment({amount: 21_000n, feeRate: 2, to: STRANGER})),
        engineSigner(wallet)
      )
    )
    const final = await send(sync, wallet, payment)
    assert.ok(esplora.inMempool(final.txid))

    const view = sync.view()
    assert.equal(view.transactions[0]?.txid, final.txid)
    assert.equal(view.transactions[0]?.kind, 'sent')
    assert.equal(view.transactions[0]?.amount, 20_000n)
    assert.equal(view.transactions[0]?.fee, payment.plan.fee)
    assert.equal(view.balance.total, 50_000n - 20_000n - payment.plan.fee)
    assert.deepEqual(
      view.utxos.map(utxo => [utxo.address, utxo.trusted, utxo.confirmations]),
      [[change(0), true, 0]]
    )
    assert.equal(view.balance.spendable, payment.plan.change)
    assert.equal(view.changeAddress.address, change(1))

    // Its change can pay before it confirms.
    const next = sync.createPayment({amount: 5_000n, feeRate: 2, to: STRANGER})
    assert.equal(next.inputs[0]?.txid, final.txid)

    const synced = await sync.sync()
    assert.deepEqual(synced.balance, view.balance)
    assert.deepEqual(
      synced.transactions.map(transaction => transaction.txid),
      view.transactions.map(transaction => transaction.txid)
    )

    // Again: the node has it, which is a success. Spending spent coins is the node's refusal, with its reason.
    assert.equal(await sync.broadcast(final), final.txid)
    esplora.mine()
    await rejectsSync(sync.broadcast(alternative), 'BROADCAST_REJECTED', /missingorspent/)

    // A backend that accepts it under another id is not believed.
    const other = chain.finalizePsbt(await sync.signPsbt(await sync.createPsbt(next), engineSigner(wallet)))
    await rejectsSync(sync.broadcast({hex: other.hex, txid: 'ab'.repeat(32)}), 'INVALID_RESPONSE')
    wallet.dispose()
  })

  test('fee bumps: the same payment at a higher rate replaces the original (BIP-125)', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: receive(0), value: 50_000},
      {address: receive(1), value: 8_000},
    ])
    esplora.mine()
    const received = esplora.fund([{address: receive(2), value: 1_000}])
    await sync.sync()

    const payment = sync.createPayment({amount: 30_000n, feeRate: 2, to: STRANGER})
    const original = await send(sync, wallet, payment)

    throwsSync(() => sync.createFeeBump(original.txid, {feeRate: 2}), 'FEE_TOO_LOW', /at least/)
    throwsSync(() => sync.createFeeBump(received, {feeRate: 10}), 'FEE_BUMP_UNAVAILABLE')

    const bump = sync.createFeeBump(original.txid, {feeRate: 6})
    assert.equal(bump.replaces, original.txid)
    assert.deepEqual(bump.plan.outputs[0], payment.plan.outputs[0])
    assert.equal(bump.plan.outputs[1]?.address, payment.plan.outputs[1]?.address)
    assert.ok(bump.plan.fee >= payment.plan.fee + BigInt(bump.plan.vsize))
    assert.equal(bump.plan.change, payment.plan.change - (bump.plan.fee - payment.plan.fee))

    const replacement = await send(sync, wallet, bump)
    assert.equal(esplora.inMempool(original.txid), false)
    assert.deepEqual(
      sync
        .view()
        .transactions.slice(0, 2)
        .map(transaction => transaction.txid),
      [replacement.txid, received]
    )
    assert.equal(
      sync.view().transactions.some(transaction => transaction.txid === original.txid),
      false
    )

    const synced = await sync.sync()
    assert.equal(
      synced.transactions.some(transaction => transaction.txid === original.txid),
      false
    )
    assert.equal(synced.balance.total, 58_000n + 1_000n - 30_000n - bump.plan.fee)

    // Once something spends its change, replacing it would drop that too.
    await send(sync, wallet, sync.createPayment({amount: 5_000n, feeRate: 6, to: STRANGER}))
    throwsSync(() => sync.createFeeBump(replacement.txid, {feeRate: 20}), 'FEE_BUMP_UNAVAILABLE', /spends its outputs/)

    esplora.mine()
    await sync.sync()
    throwsSync(() => sync.createFeeBump(replacement.txid, {feeRate: 20}), 'FEE_BUMP_UNAVAILABLE', /confirmed/)
    wallet.dispose()
  })

  test('previous transactions the backend lies about are caught before a signer sees them', async () => {
    const {backend, esplora, sync, wallet} = await setup()
    esplora.fund([{address: receive(0), value: 50_000}])
    const other = esplora.fund([{address: STRANGER, value: 50_000}])
    esplora.mine()
    await sync.sync()

    const lying = createBitcoinSync({
      backend: {...backend, transactionHex: async () => esplora.hex(other)},
      chain,
      extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH),
      fingerprint: wallet.fingerprint,
      snapshot: sync.snapshot(),
    })
    await rejectsSync(
      lying.createPsbt(lying.createPayment({amount: 10_000n, feeRate: 1, to: STRANGER})),
      'INVALID_RESPONSE'
    )

    const anonymous = createBitcoinSync({
      backend,
      chain,
      extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH),
      snapshot: sync.snapshot(),
    })
    await rejectsSync(
      anonymous.createPsbt(anonymous.createPayment({amount: 10_000n, feeRate: 1, to: STRANGER})),
      'MISSING_FINGERPRINT'
    )
    wallet.dispose()
  })
})

describe('one address', () => {
  test('an account of the engine: its address receives, pays and takes its change back', async () => {
    const base = await setup()
    const account = await base.wallet.deriveAccount({chain: 'bitcoin', index: 4})
    const {esplora, sync, wallet} = await setup({sync: {account}})
    esplora.fund([{address: account.address, value: 30_000}])
    esplora.mine()
    esplora.fund([{address: account.address, value: 20_000}])

    const view = await sync.sync()
    assert.equal(view.balance.total, 50_000n)
    assert.equal(view.receiveAddress.address, account.address)
    assert.equal(view.changeAddress.address, account.address)
    assert.equal(sync.path, `${ACCOUNT_PATH}/0/4`)
    // One summary and one history: no discovery.
    assert.equal(esplora.requests.filter(request => request.startsWith('GET /address/')).length, 2)

    const payment = sync.createPayment({amount: 10_000n, feeRate: 2, to: STRANGER})
    assert.equal(payment.plan.outputs[1]?.address, account.address)
    const psbt = await sync.createPsbt(payment)
    assert.deepEqual(Transaction.fromPSBT(psbt).getInput(0).bip32Derivation?.[0]?.[1].path, indexesOf(account.path))

    // Signed by the account itself, as a single-address wallet does.
    const final = chain.finalizePsbt((await account.signPsbt(psbt)).psbt)
    assert.equal(await sync.broadcast(final), final.txid)
    assert.equal(sync.view().balance.total, 50_000n - 10_000n - payment.plan.fee)
    wallet.dispose()
    base.wallet.dispose()
  })

  test('an address alone: balance and history, no payments, and a snapshot an account of it can take over', async () => {
    const base = await setup()
    const account = await base.wallet.deriveAccount({chain: 'bitcoin', index: 9})
    const watched = await setup({sync: {address: account.address}})
    watched.esplora.fund([{address: account.address, value: 12_000}])

    const view = await watched.sync.sync()
    assert.equal(view.balance.unconfirmed, 12_000n)
    assert.equal(view.receiveAddress.publicKey, undefined)
    assert.equal(watched.sync.scriptType, undefined)
    throwsSync(() => watched.sync.createPayment({amount: 1_000n, feeRate: 1, to: STRANGER}), 'MISSING_KEY')
    throwsSync(() => watched.sync.addressAt(0, 1), 'INVALID_ARGUMENT')

    const upgraded = createBitcoinSync({
      account,
      backend: watched.backend,
      chain,
      snapshot: watched.sync.snapshot(),
    })
    assert.equal(upgraded.view().balance.unconfirmed, 12_000n)
    assert.equal(upgraded.id, watched.sync.id)

    // Any address type reads: a stranger's P2TR, say.
    const taproot = 'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c'
    const stranger = createBitcoinSync({
      address: taproot,
      backend: esploraBackend({fetch: watched.esplora.fetch, network: 'testnet', url: URL}),
      chain,
    })
    assert.equal(stranger.view().receiveAddress.address, taproot)
    throwsSync(
      () => createBitcoinSync({address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', backend: watched.backend, chain}),
      'INVALID_ADDRESS'
    )
    base.wallet.dispose()
    watched.wallet.dispose()
  })
})
