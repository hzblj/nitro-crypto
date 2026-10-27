import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import {hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {schnorr} from '@noble/curves/secp256k1.js'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {p2tr, SigHash, TEST_NETWORK, Transaction} from '@scure/btc-signer'

import {type BitcoinAccount, bitcoinAdapter} from '../../src'
import {createBitcoinSync, esploraBackend, type Payment, parseExtendedKey, type SignerRequest} from '../../src/sync'
import {createFakeEsplora, STRANGER} from './fake-esplora'
import {chain, crypto, MNEMONIC, openWallet, throwsSync, URL} from './helpers'

const TAPROOT_PATH = "m/86'/1'/0'"
const HARDENED = 0x80000000

type Bip86 = {
  readonly account: {readonly path: string; readonly xpub: string}
  readonly addresses: readonly {
    readonly path: string
    readonly request: {readonly change: 0 | 1; readonly index: number}
    readonly internalKey: string
    readonly scriptPubKey: string
    readonly address: string
  }[]
}

const bip86 = JSON.parse(readFileSync(path.join(import.meta.dirname, '../vectors/bip86.json'), 'utf8')) as Bip86

/** The same Taproot account by @scure/bip32 and btc-signer. */
const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC))
const referenceKey = (change: 0 | 1, index: number) =>
  reference.derive(TAPROOT_PATH).deriveChild(change).deriveChild(index)
const internalKey = (change: 0 | 1, index: number) =>
  (referenceKey(change, index).publicKey ?? new Uint8Array()).subarray(1)
const referenceAddress = (change: 0 | 1, index: number) =>
  p2tr(internalKey(change, index), undefined, TEST_NETWORK).address ?? ''

const indexesOf = (text: string) =>
  text
    .split('/')
    .slice(1)
    .map(step => (step.endsWith("'") ? Number.parseInt(step, 10) + HARDENED : Number(step)))

const engineSigner = (wallet: Awaited<ReturnType<typeof openWallet>>) => (request: SignerRequest) =>
  wallet.deriveAccount({chain: 'bitcoin', ...request}) as Promise<BitcoinAccount<string>>

const setup = async () => {
  const wallet = await openWallet()
  const esplora = createFakeEsplora()
  const backend = esploraBackend({
    fetch: esplora.fetch,
    network: 'testnet',
    requestsPerSecond: Number.POSITIVE_INFINITY,
    retryDelayMs: 1,
    url: URL,
  })
  const sync = createBitcoinSync({
    backend,
    chain,
    extendedKey: wallet.extendedPublicKey(TAPROOT_PATH),
    fingerprint: wallet.fingerprint,
    scriptType: 'p2tr',
  })

  return {backend, esplora, sync, wallet}
}

/** Each input's BIP-341 key path signature, checked with @noble/curves over btc-signer's signature hash. */
const verifyTaproot = (raw: string, payment: Payment) => {
  const transaction = Transaction.fromRaw(hex.decode(raw), {allowUnknownOutputs: true})
  const scripts = payment.inputs.map(coin => coin.scriptPubKey)
  const amounts = payment.inputs.map(coin => coin.value)

  payment.inputs.forEach((coin, index) => {
    const [signature] = transaction.getInput(index).finalScriptWitness ?? []
    const sighash = transaction.preimageWitnessV1(index, scripts, SigHash.DEFAULT, amounts)

    assert.equal(signature?.length, 64, 'SIGHASH_DEFAULT: a bare 64-byte signature')
    assert.equal(schnorr.verify(signature ?? new Uint8Array(), sighash, coin.scriptPubKey.subarray(2)), true)
  })
}

describe('Taproot accounts (BIP-86)', () => {
  test('BIP-86`s account xpub, with scriptType p2tr, gives BIP-86`s addresses', () => {
    const mainnet = createTestCryptoEngine({adapters: [bitcoinAdapter()]})
    const {extendedKey, scriptType} = parseExtendedKey(bip86.account.xpub, crypto.hash.sha256)
    // An xpub says nothing of its script: Taproot has no SLIP-132 prefix, so the caller does.
    assert.equal(scriptType, undefined)

    const sync = createBitcoinSync({
      backend: esploraBackend({fetch: () => Promise.reject(new Error('offline')), network: 'mainnet'}),
      chain: mainnet.chains.bitcoin,
      extendedKey,
      scriptType: 'p2tr',
    })
    assert.equal(sync.path, bip86.account.path)
    assert.equal(sync.scriptType, 'p2tr')

    for (const vector of bip86.addresses) {
      const address = sync.addressAt(vector.request.change, vector.request.index)

      assert.equal(address.address, vector.address)
      assert.equal(address.path, vector.path)
      assert.equal(hex.encode(address.scriptPubKey), vector.scriptPubKey)
      assert.equal(hex.encode(address.publicKey?.subarray(1) ?? new Uint8Array()), vector.internalKey)
    }
  })

  test('every address of both branches, as @scure/bip32 and btc-signer derive them', async () => {
    const {sync, wallet} = await setup()

    for (const change of [0, 1] as const) {
      for (let index = 0; index < 25; index++) {
        assert.equal(sync.addressAt(change, index).address, referenceAddress(change, index))
      }
    }

    assert.equal(sync.view().receiveAddress.address, referenceAddress(0, 0))
    wallet.dispose()
  })

  test('discovery finds Taproot coins up to the gap limit, and a snapshot is tied to the type', async () => {
    const {backend, esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: referenceAddress(0, 0), value: 10_000},
      {address: referenceAddress(0, 7), value: 20_000},
      {address: referenceAddress(1, 2), value: 5_000},
    ])
    esplora.mine()

    const view = await sync.sync()
    assert.deepEqual(
      view.addresses.map(address => `${address.change}/${address.index}`),
      ['0/0', '0/7', '1/2']
    )
    assert.equal(view.balance.confirmed, 35_000n)
    assert.equal(view.receiveAddress.path, `${TAPROOT_PATH}/0/8`)
    assert.equal(view.changeAddress.address, referenceAddress(1, 3))

    const snapshot = sync.snapshot()
    assert.ok(snapshot.account.startsWith('p2tr:testnet:'))
    // The same key followed as P2WPKH is another account: other addresses, another history.
    throwsSync(
      () =>
        createBitcoinSync({
          backend,
          chain,
          extendedKey: wallet.extendedPublicKey(TAPROOT_PATH),
          path: TAPROOT_PATH,
          scriptType: 'p2wpkh',
          snapshot,
        }),
      'SNAPSHOT_MISMATCH'
    )
    wallet.dispose()
  })

  test('a payment from several Taproot addresses: BIP-371 fields, Taproot sizes, signed by the engine', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([
      {address: referenceAddress(0, 0), value: 20_000},
      {address: referenceAddress(0, 3), value: 15_000},
      {address: referenceAddress(1, 1), value: 10_000},
    ])
    esplora.mine()
    await sync.sync()

    const payment = sync.createPayment({amount: 40_000n, feeRate: 2, to: STRANGER})
    assert.equal(payment.inputs.length, 3)
    // 57.5 vB per Taproot key path input, a P2WPKH payment (31 bytes) and Taproot change (43).
    assert.equal(payment.plan.vsize, Math.ceil(10.5 + 3 * 57.5 + 31 + 43))
    assert.equal(payment.change?.address, referenceAddress(1, 2))

    const psbt = await sync.createPsbt(payment)
    const theirs = Transaction.fromPSBT(psbt)

    payment.inputs.forEach((coin, index) => {
      const input = theirs.getInput(index)
      const [[key, origin] = []] = input.tapBip32Derivation ?? []

      assert.deepEqual(input.tapInternalKey, internalKey(coin.change, coin.index))
      assert.deepEqual(key, internalKey(coin.change, coin.index))
      assert.deepEqual(origin?.hashes, [])
      assert.equal(origin?.der.fingerprint, reference.fingerprint)
      assert.deepEqual(origin?.der.path, indexesOf(coin.path ?? ''))
      assert.deepEqual(input.witnessUtxo?.script, coin.scriptPubKey)
      assert.equal(input.bip32Derivation, undefined)
    })
    assert.equal(theirs.getOutput(0).tapInternalKey, undefined)
    assert.deepEqual(theirs.getOutput(1).tapInternalKey, internalKey(1, 2))
    assert.deepEqual(theirs.getOutput(1).tapBip32Derivation?.[0]?.[1].der.path, indexesOf(`${TAPROOT_PATH}/1/2`))

    // The engine signs each key's input; the signatures verify under @noble/curves over btc-signer's signature
    // hashes, and btc-signer, signing the same PSBT with @scure/bip32's keys, makes the same transaction.
    const final = chain.finalizePsbt(await sync.signPsbt(psbt, engineSigner(wallet)))
    verifyTaproot(final.hex, payment)

    const scure = Transaction.fromPSBT(psbt)
    payment.inputs.forEach((coin, index) => {
      scure.signIdx(referenceKey(coin.change, coin.index).privateKey ?? new Uint8Array(), index)
    })
    scure.finalize()
    assert.equal(scure.id, final.txid)
    assert.equal(scure.vsize, final.vsize)

    await sync.broadcast(final)
    assert.ok(esplora.inMempool(final.txid))
    assert.deepEqual(
      sync.view().utxos.map(utxo => [utxo.address, utxo.trusted]),
      [[referenceAddress(1, 2), true]]
    )
    wallet.dispose()
  })

  test('a fee bump replaces a Taproot payment, and a key of the wrong type is refused', async () => {
    const {esplora, sync, wallet} = await setup()
    esplora.fund([{address: referenceAddress(0, 0), value: 50_000}])
    esplora.mine()
    await sync.sync()

    const payment = sync.createPayment({amount: 20_000n, feeRate: 2, to: STRANGER})
    const psbt = await sync.createPsbt(payment)

    // The P2WPKH account at the Taproot path is another key, as the PSBT names it: refused before anything is signed.
    await assert.rejects(
      sync.signPsbt(
        psbt,
        request => wallet.deriveAccount({chain: 'bitcoin', path: request.path}) as Promise<BitcoinAccount<string>>
      ),
      (error: {code?: string}) => error.code === 'KEY_MISMATCH'
    )

    const original = chain.finalizePsbt(await sync.signPsbt(psbt, engineSigner(wallet)))
    await sync.broadcast(original)

    const bump = sync.createFeeBump(original.txid, {feeRate: 5})
    assert.equal(bump.plan.vsize, payment.plan.vsize)
    const replacement = chain.finalizePsbt(await sync.signPsbt(await sync.createPsbt(bump), engineSigner(wallet)))
    verifyTaproot(replacement.hex, bump)
    await sync.broadcast(replacement)

    assert.equal(esplora.inMempool(original.txid), false)
    assert.equal(esplora.inMempool(replacement.txid), true)
    assert.equal((await sync.sync()).balance.total, 50_000n - 20_000n - bump.plan.fee)
    wallet.dispose()
  })
})
