import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {bytes, hex, isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {p2tr, p2wpkh, TEST_NETWORK, Transaction} from '@scure/btc-signer'

import {type BitcoinUtxo, bitcoinAdapter} from '../src'
import {parseMaps, serializeMaps} from '../src/psbt'
import {serializeTransaction, u64} from '../src/transaction'

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const crypto = createTestCryptoEngine({adapters: [bitcoinAdapter({network: 'testnet'})]})
const chain = crypto.chains.bitcoin
const sha256 = crypto.hash.sha256

const throwsWith = (run: () => unknown, code: Parameters<typeof isCryptoError>[1], message?: RegExp) =>
  assert.throws(run, error => isCryptoError(error, code) && (!message || message.test(error.message)))

const rejectsWith = async (promise: Promise<unknown>, code: Parameters<typeof isCryptoError>[1]) =>
  assert.rejects(promise, error => isCryptoError(error, code))

/** mulberry32: the same "random" cases on every run, so a failure can be replayed. */
const seeded = (seed: number) => {
  let state = seed

  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t

    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const utxo = (txid: string, value: number, vout = 0): BitcoinUtxo => ({
  txid: txid.repeat(64 / txid.length),
  value: BigInt(value),
  vout,
})

/** The PSBT with input `index`'s entry of key type `type` given `value`: tampering btc-signer would refuse to do. */
const withInputValue = (psbt: Uint8Array, index: number, type: number, value: (old: Uint8Array) => Uint8Array) => {
  const maps = parseMaps(psbt)

  return serializeMaps({
    ...maps,
    inputs: maps.inputs.map((entries, position) =>
      position === index
        ? entries.map(entry => (entry.key[0] === type ? {key: entry.key, value: value(entry.value)} : entry))
        : entries
    ),
  })
}

/** A previous transaction paying `script` `value` at output `vout`, and the coin it makes. */
const previousTransaction = (script: Uint8Array, value: bigint, vout: number, salt: number) => {
  const raw = serializeTransaction({
    inputs: [{sequence: 0xffffffff, txid: new Uint8Array(32).fill(salt), value: 0n, vout: 0}],
    locktime: 0,
    outputs: Array.from({length: vout + 1}, (_, index) => ({
      scriptPubKey: index === vout ? script : Uint8Array.of(0x6a),
      value: index === vout ? value : 0n,
    })),
    version: 2,
  })

  return {coin: {txid: hex.encode(sha256(sha256(raw)).reverse()), value, vout}, raw}
}

describe('PSBT', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const account = await wallet.deriveAccount({chain: 'bitcoin'})
  const recipient = (await wallet.deriveAccount({chain: 'bitcoin', index: 1})).address
  const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC))
  const privateKey = reference.derive(account.path).privateKey ?? new Uint8Array()
  after(() => wallet.dispose())

  test('the account names its origin: the master fingerprint and its path', () => {
    assert.equal(account.fingerprint, 0x73c5da0a)
    assert.equal(account.fingerprint, reference.fingerprint)
    assert.equal(account.path, "m/84'/1'/0'/0/0")
  })

  test('a watch-only account from the public key is the same account, without the key', () => {
    const watch = chain.watchAccount({
      fingerprint: account.fingerprint,
      path: account.path,
      publicKey: account.publicKey,
    })
    assert.equal(watch.address, account.address)
    assert.deepEqual(watch.scriptPubKey, account.scriptPubKey)
    assert.equal('signPsbt' in watch, false)

    const plan = watch.createTransaction({amount: 10_000n, feeRate: 2, to: recipient, utxos: [utxo('aa', 50_000)]})
    assert.deepEqual(watch.createPsbt(plan), account.createPsbt(plan))

    throwsWith(
      () => chain.watchAccount({fingerprint: 1, path: account.path, publicKey: new Uint8Array(33)}),
      'INVALID_PUBLIC_KEY'
    )
    throwsWith(() => chain.watchAccount({fingerprint: 1, path: 'm/x', publicKey: account.publicKey}), 'INVALID_PATH')
    throwsWith(
      () => chain.watchAccount({fingerprint: -1, path: account.path, publicKey: account.publicKey}),
      'INVALID_ARGUMENT'
    )
  })

  test('a watch-only account from the account`s extended key: every address, derived publicly by the engine', async () => {
    const extendedKey = wallet.extendedPublicKey("m/84'/1'/0'")

    for (const [change, index] of [
      [0, 0],
      [0, 1],
      [1, 0],
      [0, 19],
    ] as const) {
      const watch = chain.watchAccount({
        change,
        extendedKey,
        fingerprint: account.fingerprint,
        index,
        path: "m/84'/1'/0'",
      })
      const derived = await wallet.deriveAccount({chain: 'bitcoin', change, index})
      assert.equal(watch.address, derived.address)
      assert.equal(watch.path, derived.path)
      assert.deepEqual(watch.publicKey, derived.publicKey)
    }

    throwsWith(
      () => chain.watchAccount({extendedKey, fingerprint: account.fingerprint, path: "m/84'/1'"}),
      'INVALID_ARGUMENT'
    )
    throwsWith(() => chain.derivePublic(extendedKey, "m/0'"), 'INVALID_PATH')
  })

  test('@scure/btc-signer reads what createPsbt writes: the transaction, coins, origins and change', () => {
    const plan = account.createTransaction({
      amount: 25_000n,
      feeRate: 3,
      to: recipient,
      utxos: [utxo('aa', 20_000), utxo('bb', 30_000, 1)],
    })
    const psbt = account.createPsbt(plan)
    const theirs = Transaction.fromPSBT(psbt)

    assert.equal(theirs.inputsLength, plan.inputs.length)
    assert.equal(theirs.outputsLength, 2)
    assert.equal(theirs.fee, plan.fee)

    for (let index = 0; index < theirs.inputsLength; index++) {
      const input = theirs.getInput(index)
      assert.deepEqual(input.witnessUtxo?.script, account.scriptPubKey)
      assert.equal(input.witnessUtxo?.amount, plan.inputs[index]?.value)
      assert.deepEqual(input.bip32Derivation?.[0]?.[0], account.publicKey)
      assert.equal(input.bip32Derivation?.[0]?.[1].fingerprint, 0x73c5da0a)
      assert.deepEqual(input.bip32Derivation?.[0]?.[1].path, [0x80000054, 0x80000001, 0x80000000, 0, 0])
    }

    // Change back to the account carries its origin; the payment does not.
    assert.equal(theirs.getOutput(0).bip32Derivation, undefined)
    assert.deepEqual(theirs.getOutput(1).bip32Derivation?.[0]?.[0], account.publicKey)

    const decoded = chain.decodePsbt(psbt)
    assert.equal(decoded.fee, plan.fee)
    assert.equal(decoded.txid, theirs.id)
    assert.deepEqual(
      decoded.outputs.map(output => [output.address, output.value]),
      plan.outputs.map(output => [output.address, output.value])
    )
    assert.equal(decoded.inputs[0]?.address, account.address)
    assert.equal(decoded.inputs[0]?.verifiedValue, false)
  })

  test('signed here, finalized there, and the other way round: the same transaction as signTransaction', async () => {
    const random = seeded(174)

    for (let round = 0; round < 12; round++) {
      const utxos = Array.from({length: 1 + Math.floor(random() * 3)}, (_, index) =>
        utxo((round * 16 + index + 1).toString(16).padStart(2, '0'), 10_000 + Math.floor(random() * 500_000), index)
      )
      const to =
        round % 2 === 0 ? recipient : (p2tr(account.publicKey.subarray(1), undefined, TEST_NETWORK).address ?? '')
      const plan = account.createTransaction({amount: round % 4 === 3 ? 'max' : 5_000n, feeRate: 1 + round, to, utxos})
      const direct = await account.signTransaction(plan)
      const psbt = account.createPsbt(plan)

      // Signed by this package, finalized by btc-signer.
      const {psbt: signed, signedInputs} = await account.signPsbt(psbt)
      assert.deepEqual(
        signedInputs,
        plan.inputs.map((_, index) => index)
      )
      const theirs = Transaction.fromPSBT(signed)
      theirs.finalize()
      assert.equal(hex.encode(theirs.extract()), direct.hex, `round ${round}`)

      // Finalized by this package, with every signature verified by the engine.
      assert.deepEqual(chain.finalizePsbt(signed), direct)

      // Signed by btc-signer, finalized here.
      const external = Transaction.fromPSBT(psbt)
      external.sign(privateKey)
      assert.deepEqual(chain.finalizePsbt(external.toPSBT()), direct)
    }
  })

  test('PSBTs made by btc-signer sign here', async () => {
    const theirs = new Transaction({lockTime: 0, version: 2})
    theirs.addInput({
      index: 3,
      sequence: 0xfffffffd,
      txid: 'cd'.repeat(32),
      witnessUtxo: {amount: 80_000n, script: account.scriptPubKey},
    })
    theirs.addOutputAddress(recipient, 70_000n, TEST_NETWORK)
    const {psbt} = await account.signPsbt(theirs.toPSBT())
    const back = Transaction.fromPSBT(psbt)
    back.finalize()
    assert.equal(chain.finalizePsbt(psbt).hex, hex.encode(back.extract()))
    assert.equal(chain.finalizePsbt(psbt).fee, 10_000n)
  })

  test('previous transactions make values checkable, and must be the coins they claim', async () => {
    const first = previousTransaction(account.scriptPubKey, 60_000n, 1, 1)
    const second = previousTransaction(account.scriptPubKey, 40_000n, 0, 2)
    const plan = account.createTransaction({
      amount: 70_000n,
      feeRate: 2,
      to: recipient,
      utxos: [first.coin, second.coin],
    })
    const psbt = account.createPsbt(plan, {
      previousTransactions: {[first.coin.txid]: first.raw, [second.coin.txid]: hex.encode(second.raw)},
    })

    assert.deepEqual(
      chain.decodePsbt(psbt).inputs.map(input => input.verifiedValue),
      [true, true]
    )
    assert.equal(Transaction.fromPSBT(psbt).getInput(0).nonWitnessUtxo !== undefined, true)
    assert.equal(chain.finalizePsbt((await account.signPsbt(psbt)).psbt).fee, plan.fee)

    // A previous transaction that is not the coin's.
    throwsWith(
      () => account.createPsbt(plan, {previousTransactions: {[first.coin.txid]: second.raw}}),
      'INVALID_ARGUMENT',
      /not the coin/
    )

    // A witness UTXO that lies about the value its previous transaction states.
    const lying = withInputValue(psbt, 0, 0x01, old => bytes.concat(u64(1n), old.subarray(8)))
    throwsWith(() => chain.decodePsbt(lying), 'INVALID_ARGUMENT', /disagrees/)
  })

  test('only SIGHASH_ALL is signed', async () => {
    const theirs = Transaction.fromPSBT(
      account.createPsbt(
        account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
      ),
      {allowUnknownInputs: true}
    )
    theirs.updateInput(0, {sighashType: 0x83}, true)
    await rejectsWith(account.signPsbt(theirs.toPSBT()), 'INVALID_ARGUMENT')
  })

  test('a PSBT with nothing for the account is refused', async () => {
    const other = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC, 'other')).derive("m/84'/1'/0'/0/0")
    const theirs = new Transaction({lockTime: 0, version: 2})
    theirs.addInput({
      index: 0,
      txid: 'ee'.repeat(32),
      witnessUtxo: {amount: 50_000n, script: p2wpkh(other.publicKey ?? new Uint8Array(), TEST_NETWORK).script},
    })
    theirs.addOutputAddress(recipient, 40_000n, TEST_NETWORK)
    await rejectsWith(account.signPsbt(theirs.toPSBT()), 'INVALID_ARGUMENT')
  })

  test('a forged or misplaced signature never finalizes', async () => {
    const plan = account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    const {psbt} = await account.signPsbt(account.createPsbt(plan))
    // One bit of s flipped.
    const forged = withInputValue(psbt, 0, 0x02, old => {
      const flipped = old.slice()
      flipped[flipped.length - 3] = (flipped[flipped.length - 3] ?? 0) ^ 1

      return flipped
    })
    throwsWith(() => chain.finalizePsbt(forged), 'INVALID_SIGNATURE')

    // A valid signature of another transaction (another fee).
    const otherPlan = account.createTransaction({
      amount: 10_000n,
      feeRate: 2,
      to: recipient,
      utxos: [utxo('aa', 50_000)],
    })
    const otherSigned = (await account.signPsbt(account.createPsbt(otherPlan))).psbt
    const otherSignature =
      parseMaps(otherSigned).inputs[0]?.find(entry => entry.key[0] === 0x02)?.value ?? new Uint8Array()
    const replayed = withInputValue(psbt, 0, 0x02, () => otherSignature)
    throwsWith(() => chain.finalizePsbt(replayed), 'INVALID_SIGNATURE')

    // No signature at all.
    throwsWith(() => chain.finalizePsbt(account.createPsbt(plan)), 'INVALID_ARGUMENT')
  })

  test('malformed PSBTs are refused, whatever is wrong with them', () => {
    const psbt = account.createPsbt(
      account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    const cases: Uint8Array[] = [
      new Uint8Array(0),
      hex.decode('70736274'),
      bytes.concat(hex.decode('70736274fe'), psbt.subarray(5)),
      bytes.concat(psbt, Uint8Array.of(0)),
      psbt.subarray(0, psbt.length - 1),
      // The global map's unsigned transaction key, repeated.
      bytes.concat(psbt.subarray(0, 5), Uint8Array.of(0x01, 0x00, 0x00), psbt.subarray(5)),
      // A non-canonical size: 0xfd before a length under 253.
      bytes.concat(psbt.subarray(0, 5), Uint8Array.of(0x01, 0x00, 0xfd, 0x05, 0x00), psbt.subarray(8)),
      // Version 2 PSBTs have no unsigned transaction.
      hex.decode('70736274ff01fb040200000000'),
    ]

    for (const [index, data] of cases.entries()) {
      throwsWith(() => chain.decodePsbt(data), 'INVALID_ARGUMENT', undefined)
      assert.ok(true, `case ${index}`)
    }

    const random = seeded(9)

    for (let run = 0; run < 2000; run++) {
      const mutated = psbt.slice()
      mutated[Math.floor(random() * mutated.length)] = Math.floor(random() * 256)

      try {
        chain.decodePsbt(mutated)
      } catch (error) {
        assert.ok(isCryptoError(error), String(error))
      }
    }
  })

  test('a disposed wallet signs nothing', async () => {
    const own = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
    const spender = await own.deriveAccount({chain: 'bitcoin'})
    const psbt = spender.createPsbt(
      spender.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    )
    own.dispose()
    await rejectsWith(spender.signPsbt(psbt), 'DISPOSED')
  })
})
