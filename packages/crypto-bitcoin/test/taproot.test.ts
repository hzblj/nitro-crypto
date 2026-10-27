import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {type AdapterContext, bytes, type Capability, hex} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {NETWORK, p2tr, p2wpkh, SigHash, TEST_NETWORK, Transaction} from '@scure/btc-signer'

import {type BitcoinTransactionPlan, type BitcoinUtxo, bitcoinAdapter} from '../src'
import {p2trOutput} from '../src/address'
import {parseMaps, parseTransaction, serializeMaps, signPsbt} from '../src/psbt'
import {
  type AccountSigner,
  estimateVsize,
  type RawTransaction,
  signTransaction,
  TAPROOT_SIGHASH_TYPES,
  taprootSighash,
  taprootSigMsg,
} from '../src/transaction'
import {engineVectors, MNEMONIC, rejectsWith, seeded, signWithAux, throwsWith, vectors, withAux} from './support'

type Bip86 = {
  mnemonic: string
  account: {path: string; xpub: string}
  addresses: {
    path: string
    request: {account: number; change: 0 | 1; index: number}
    internalKey: string
    outputKey: string
    scriptPubKey: string
    address: string
  }[]
}

type Bip341 = {
  scriptPubKey: {
    given: {internalPubkey: string}
    intermediary: {merkleRoot: string | null; tweakedPubkey: string}
    expected: {scriptPubKey: string; bip350Address: string}
  }[]
  keyPathSpending: {
    given: {rawUnsignedTx: string; utxosSpent: {scriptPubKey: string; amountSats: number}[]}
    inputSpending: {
      given: {txinIndex: number; internalPrivkey: string; merkleRoot: string | null; hashType: number}
      intermediary: {internalPubkey: string; sigMsg: string; sigHash: string}
      expected: {witness: string[]}
    }[]
  }[]
}

const crypto = createTestCryptoEngine({
  adapters: [
    bitcoinAdapter(),
    bitcoinAdapter({id: 'bitcoin-testnet', network: 'testnet'}),
    bitcoinAdapter({id: 'bitcoin-regtest', network: 'regtest'}),
  ],
})
const mainnet = crypto.chains.bitcoin
const testnet = crypto.chains['bitcoin-testnet']
const sha256 = crypto.hash.sha256
const transactions = {network: testnet.network, sha256, tweak: crypto.schnorr.taprootTweak}
const REGTEST_NETWORK = {...TEST_NETWORK, bech32: 'bcrt'}
const root = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC))
const secretAt = (path: string) => root.derive(path).privateKey ?? new Uint8Array()

const utxo = (txid: string, value: number, vout = 0): BitcoinUtxo => ({
  txid: txid.repeat(64 / txid.length),
  value: BigInt(value),
  vout,
})

/** The PSBT with input `index`'s entries of key type `type` changed by `change` (`undefined` drops them). */
const editInput = (
  psbt: Uint8Array,
  index: number,
  type: number,
  change: (value: Uint8Array) => Uint8Array | undefined
) => {
  const maps = parseMaps(psbt)

  return serializeMaps({
    ...maps,
    inputs: maps.inputs.map((entries, position) =>
      position === index
        ? entries.flatMap(entry => {
            if (entry.key[0] !== type) {
              return [entry]
            }

            const value = change(entry.value)

            return value ? [{key: entry.key, value}] : []
          })
        : entries
    ),
  })
}

/** Adds an entry to input `index`. */
const addToInput = (psbt: Uint8Array, index: number, key: Uint8Array, value: Uint8Array) => {
  const maps = parseMaps(psbt)

  return serializeMaps({
    ...maps,
    inputs: maps.inputs.map((entries, position) => (position === index ? [...entries, {key, value}] : entries)),
  })
}

/** btc-signer's transaction of a plan: the inputs as this package writes them, version 2, replaceable. */
const btcSignerTransaction = (plan: BitcoinTransactionPlan, script: Uint8Array, extra: object = {}) => {
  const tx = new Transaction({lockTime: 0, version: 2})

  for (const input of plan.inputs) {
    tx.addInput({
      index: input.vout,
      sequence: 0xfffffffd,
      txid: input.txid,
      witnessUtxo: {amount: input.value, script},
      ...extra,
    })
  }

  for (const output of plan.outputs) {
    tx.addOutput({amount: output.value, script: output.scriptPubKey})
  }

  return tx
}

describe('Taproot accounts (BIP-86)', () => {
  test('BIP-86 test vectors: paths, internal keys, output keys, scripts and addresses', async () => {
    const {account, addresses, mnemonic} = vectors<Bip86>('bip86.json')
    const wallet = await crypto.createEphemeralWallet({mnemonic})

    for (const expected of addresses) {
      const derived = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin', ...expected.request})
      assert.equal(derived.addressType, 'p2tr')
      assert.equal(derived.path, expected.path)
      assert.equal(hex.encode(derived.publicKey.subarray(1)), expected.internalKey)
      assert.equal(hex.encode(derived.scriptPubKey), expected.scriptPubKey)
      assert.equal(derived.address, expected.address)

      // From the internal key alone, x-only or compressed, as a watch-only wallet has it.
      assert.equal(mainnet.addressFromPublicKey(hex.decode(expected.internalKey), 'p2tr'), expected.address)
      assert.equal(mainnet.addressFromPublicKey(derived.publicKey, 'p2tr'), expected.address)

      // From the account's extended public key, derived publicly by the engine.
      const watch = mainnet.watchAccount({
        addressType: 'p2tr',
        change: expected.request.change,
        extendedKey: wallet.extendedPublicKey(account.path),
        fingerprint: wallet.fingerprint,
        index: expected.request.index,
        path: account.path,
      })
      assert.equal(watch.address, expected.address)
      assert.equal(watch.path, expected.path)

      const validation = mainnet.validateAddress(expected.address)
      assert.ok(validation.valid)
      assert.equal(validation.type, 'p2tr')
      assert.equal(hex.encode(validation.scriptPubKey), expected.scriptPubKey)
    }

    wallet.dispose()
  })

  test('addresses and scripts equal @scure/btc-signer on every network, at many paths', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC, passphrase: 'taproot'})
    const other = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC, 'taproot'))

    for (const [chain, network, coin] of [
      ['bitcoin', NETWORK, 0],
      ['bitcoin-testnet', TEST_NETWORK, 1],
      ['bitcoin-regtest', REGTEST_NETWORK, 1],
    ] as const) {
      for (const [account, change, index] of [
        [0, 0, 0],
        [0, 1, 7],
        [3, 0, 42],
      ] as const) {
        const ours = await wallet.deriveAccount({account, addressType: 'p2tr', chain, change, index})
        const path = `m/86'/${coin}'/${account}'/${change}/${index}`
        const theirs = p2tr((other.derive(path).publicKey ?? new Uint8Array()).subarray(1), undefined, network)
        assert.equal(ours.path, path)
        assert.equal(ours.address, theirs.address)
        assert.deepEqual(ours.scriptPubKey, theirs.script)
      }
    }

    wallet.dispose()
  })

  test('the request: P2WPKH stays the default, any path takes either type, and nothing else is a type', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
    const atPath = await wallet.deriveAccount({chain: 'bitcoin', path: "m/86'/0'/0'/0/0"})
    assert.equal(atPath.addressType, 'p2wpkh')
    const taprootAtPath = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin', path: "m/84'/0'/0'/0/0"})
    assert.equal(taprootAtPath.addressType, 'p2tr')
    assert.equal(taprootAtPath.path, "m/84'/0'/0'/0/0")
    await rejectsWith(wallet.deriveAccount({addressType: 'p2sh' as 'p2tr', chain: 'bitcoin'}), 'INVALID_ARGUMENT')
    throwsWith(() => mainnet.addressFromPublicKey(new Uint8Array(33), 'p2tr'), 'INVALID_PUBLIC_KEY')
    throwsWith(() => mainnet.addressFromPublicKey(atPath.publicKey, 'p2sh' as 'p2tr'), 'INVALID_ARGUMENT')
    wallet.dispose()
  })

  test('BIP-341`s scriptPubKey vectors: every output key encodes to its Bech32m address', () => {
    const {scriptPubKey} = engineVectors<Bip341>('bip341.json')

    for (const {expected, given, intermediary} of scriptPubKey) {
      const output = p2trOutput(hex.decode(intermediary.tweakedPubkey), mainnet.network)
      assert.equal(output.address, expected.bip350Address)
      assert.equal(hex.encode(output.scriptPubKey), expected.scriptPubKey)

      if (intermediary.merkleRoot === null) {
        assert.equal(mainnet.addressFromPublicKey(hex.decode(given.internalPubkey), 'p2tr'), expected.bip350Address)
      }
    }
  })
})

describe('BIP-341 signature hashes', () => {
  test('BIP-341`s wallet vectors: every key path input`s signature message and hash, and its published signature', () => {
    const {keyPathSpending} = engineVectors<Bip341>('bip341.json')
    let inputs = 0

    for (const spending of keyPathSpending) {
      const parsed = parseTransaction(hex.decode(spending.given.rawUnsignedTx))
      const tx: RawTransaction = {
        ...parsed,
        inputs: parsed.inputs.map((input, index) => ({
          ...input,
          value: BigInt(spending.given.utxosSpent[index]?.amountSats ?? 0),
        })),
      }
      const scripts = spending.given.utxosSpent.map(spent => hex.decode(spent.scriptPubKey))

      for (const {expected, given, intermediary} of spending.inputSpending) {
        const {hashType, txinIndex} = given
        assert.equal(hex.encode(taprootSigMsg(tx, txinIndex, scripts, hashType, sha256)), intermediary.sigMsg)
        const sighash = taprootSighash(tx, txinIndex, scripts, hashType, sha256)
        assert.equal(hex.encode(sighash), intermediary.sigHash)

        // The engine signs this hash with the vectors' zero aux randomness to the published witness, which verifies
        // under the coin's output key.
        const merkleRoot = given.merkleRoot === null ? undefined : hex.decode(given.merkleRoot)
        const signature = signWithAux(hex.decode(given.internalPrivkey), sighash, new Uint8Array(32), {merkleRoot})
        const witness = hashType === 0 ? signature : bytes.concat(signature, Uint8Array.of(hashType))
        assert.equal(hex.encode(witness), expected.witness[0])
        const outputKey = scripts[txinIndex]?.subarray(2) ?? new Uint8Array()
        assert.equal(crypto.schnorr.verify(outputKey, sighash, signature), true)
        inputs++
      }
    }

    assert.equal(inputs, 7)
  })

  test('every hash type agrees with @scure/btc-signer on random transactions', () => {
    const random = seeded(341)
    const scriptOf = () => bytes.concat(Uint8Array.of(0x51, 32), random.bytes(32))

    for (let round = 0; round < 16; round++) {
      const count = 1 + random.integer(4)
      const tx: RawTransaction = {
        inputs: Array.from({length: count}, () => ({
          sequence: random.integer(2) === 0 ? 0xfffffffd : random.integer(0xffffffff),
          txid: random.bytes(32),
          value: BigInt(1 + random.integer(1e9)),
          vout: random.integer(8),
        })),
        locktime: random.integer(2) === 0 ? 0 : random.integer(800_000),
        outputs: Array.from({length: 1 + random.integer(4)}, () => ({
          scriptPubKey: random.integer(2) === 0 ? scriptOf() : random.bytes(22),
          value: BigInt(random.integer(1e9)),
        })),
        version: 1 + random.integer(2),
      }
      const scripts = tx.inputs.map(() => (random.integer(3) === 0 ? random.bytes(22) : scriptOf()))
      const theirs = new Transaction({
        allowUnknownInputs: true,
        allowUnknownOutputs: true,
        disableScriptCheck: true,
        lockTime: tx.locktime,
        version: tx.version,
      })

      for (const [index, input] of tx.inputs.entries()) {
        theirs.addInput({
          index: input.vout,
          sequence: input.sequence,
          txid: input.txid.slice().reverse(),
          witnessUtxo: {amount: input.value, script: scripts[index] ?? new Uint8Array()},
        })
      }

      for (const output of tx.outputs) {
        theirs.addOutput({amount: output.value, script: output.scriptPubKey})
      }

      const amounts = tx.inputs.map(input => input.value)

      for (const hashType of TAPROOT_SIGHASH_TYPES) {
        for (let index = 0; index < count; index++) {
          if ((hashType & 3) === 3 && index >= tx.outputs.length) {
            throwsWith(() => taprootSighash(tx, index, scripts, hashType, sha256), 'INVALID_ARGUMENT', /SINGLE/)
            continue
          }

          assert.deepEqual(
            taprootSighash(tx, index, scripts, hashType, sha256),
            theirs.preimageWitnessV1(index, scripts, hashType, amounts),
            `round ${round}, input ${index}, type ${hashType}`
          )
        }
      }
    }

    const tx: RawTransaction = {
      inputs: [{sequence: 0, txid: new Uint8Array(32), value: 1n, vout: 0}],
      locktime: 0,
      outputs: [{scriptPubKey: Uint8Array.of(0x6a), value: 0n}],
      version: 2,
    }
    const scripts = [scriptOf()]
    throwsWith(() => taprootSighash(tx, 0, scripts, 4, sha256), 'INVALID_ARGUMENT')
    throwsWith(() => taprootSighash(tx, 1, scripts, 0, sha256), 'INVALID_ARGUMENT')
    throwsWith(() => taprootSighash(tx, 0, [], 0, sha256), 'INVALID_ARGUMENT')
  })
})

describe('Taproot payments', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const account = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin-testnet'})
  const segwit = await wallet.deriveAccount({chain: 'bitcoin-testnet'})
  const secret = secretAt(account.path)
  const otherKey = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC, 'other')).derive("m/86'/1'/0'/0/0").publicKey
  const recipients = [
    p2tr((otherKey ?? new Uint8Array()).subarray(1), undefined, TEST_NETWORK).address ?? '',
    p2wpkh(otherKey ?? new Uint8Array(), TEST_NETWORK).address ?? '',
    segwit.address,
    account.address,
  ]
  after(() => wallet.dispose())

  test('the fee counts 57.5 vB a Taproot input, and P2TR change costs its 43 bytes', () => {
    const plan = account.createTransaction({
      amount: 40_000n,
      feeRate: 1,
      to: recipients[1] ?? '',
      utxos: [utxo('aa', 50_000)],
    })
    // 10.5 overhead, 57.5 for the input, 31 for P2WPKH and 43 for the P2TR change.
    assert.equal(plan.vsize, 142)
    assert.equal(
      plan.vsize,
      estimateVsize(
        1,
        plan.outputs.map(output => output.scriptPubKey),
        'p2tr'
      )
    )
    assert.equal(plan.outputs[1]?.address, account.address)
    assert.equal(testnet.dustThreshold(account.address), 330n)
  })

  test('random payments: the same bytes as @scure/btc-signer with the same aux randomness, and exact sizes', async () => {
    const random = seeded(86)
    const signer: AccountSigner = {
      key: wallet.deriveKey('bip32', account.path),
      publicKey: account.publicKey,
      scriptPubKey: account.scriptPubKey,
      type: 'p2tr',
    }

    for (let round = 0; round < 16; round++) {
      const utxos = Array.from({length: 1 + random.integer(4)}, () => ({
        txid: hex.encode(random.bytes(32)),
        value: BigInt(5_000 + random.integer(2_000_000)),
        vout: random.integer(4),
      }))
      const total = utxos.reduce((sum, coin) => sum + coin.value, 0n)
      const to = recipients[round % recipients.length] ?? ''
      const amount = round % 5 === 4 ? 'max' : 1_000n + BigInt(random.integer(Number(total / 2n)))
      const feeRate = [1, 1.5, 2, 5, 12.3][round % 5] ?? 1
      const plan = account.createTransaction({amount, feeRate, to, utxos})
      const aux = random.bytes(32)
      const ours = signTransaction(plan, {...signer, key: withAux(signer.key, secret, aux)}, transactions)

      const theirs = btcSignerTransaction(plan, account.scriptPubKey, {tapInternalKey: account.publicKey.subarray(1)})
      theirs.sign(secret, undefined, aux)
      theirs.finalize()

      assert.equal(ours.hex, theirs.hex, `round ${round}`)
      assert.equal(ours.txid, theirs.id)
      assert.equal(ours.vsize, theirs.vsize)
      assert.equal(ours.fee, theirs.fee)
      // A key path witness is always 64 bytes: the estimate is exact.
      assert.equal(ours.vsize, plan.vsize, `round ${round}`)

      // With the engine's own randomness: another signature, the same transaction id, and it verifies.
      const signed = await account.signTransaction(plan)
      assert.equal(signed.txid, ours.txid)
      assert.equal(signed.weight, ours.weight)
      assert.notEqual(signed.hex, ours.hex)
      const broadcast = Transaction.fromRaw(hex.decode(signed.hex))
      const amounts = plan.inputs.map(input => input.value)
      const scripts = plan.inputs.map(() => account.scriptPubKey)

      for (let index = 0; index < plan.inputs.length; index++) {
        const signature = broadcast.getInput(index).finalScriptWitness?.[0]
        const sighash = theirs.preimageWitnessV1(index, scripts, SigHash.DEFAULT, amounts)
        assert.equal(signature?.length, 64)
        assert.equal(
          crypto.schnorr.verify(account.scriptPubKey.subarray(2), sighash, signature ?? new Uint8Array()),
          true
        )
      }
    }
  })
})

describe('Taproot PSBTs (BIP-371)', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const account = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin-testnet'})
  const segwit = await wallet.deriveAccount({chain: 'bitcoin-testnet'})
  const recipient = (await wallet.deriveAccount({chain: 'bitcoin-testnet', index: 9})).address
  const secret = secretAt(account.path)
  const segwitSecret = secretAt(segwit.path)
  const internalKey = account.publicKey.subarray(1)
  after(() => wallet.dispose())

  test('createPsbt writes the internal key and Taproot derivations, and @scure/btc-signer reads them', () => {
    const plan = account.createTransaction({
      amount: 25_000n,
      feeRate: 2,
      to: recipient,
      utxos: [utxo('aa', 20_000), utxo('bb', 30_000, 1)],
    })
    const psbt = account.createPsbt(plan)
    const theirs = Transaction.fromPSBT(psbt)
    assert.equal(theirs.fee, plan.fee)

    for (let index = 0; index < theirs.inputsLength; index++) {
      const input = theirs.getInput(index)
      assert.deepEqual(input.witnessUtxo?.script, account.scriptPubKey)
      assert.deepEqual(input.tapInternalKey, internalKey)
      const [[key, origin] = []] = input.tapBip32Derivation ?? []
      assert.deepEqual(key, internalKey)
      assert.deepEqual(origin?.hashes, [])
      assert.equal(origin?.der.fingerprint, 0x73c5da0a)
      assert.deepEqual(origin?.der.path, [0x80000056, 0x80000001, 0x80000000, 0, 0])
      assert.equal(input.bip32Derivation, undefined)
    }

    // Change back to the account carries its internal key and origin; the payment does not.
    assert.equal(theirs.getOutput(0).tapInternalKey, undefined)
    assert.deepEqual(theirs.getOutput(1).tapInternalKey, internalKey)
    assert.deepEqual(theirs.getOutput(1).tapBip32Derivation?.[0]?.[0], internalKey)

    // btc-signer writes the same PSBT for the same fields.
    const written = btcSignerTransaction(plan, account.scriptPubKey, {
      tapBip32Derivation: [
        [internalKey, {der: {fingerprint: 0x73c5da0a, path: [0x80000056, 0x80000001, 0x80000000, 0, 0]}, hashes: []}],
      ],
      tapInternalKey: internalKey,
    })
    written.updateOutput(1, {
      tapBip32Derivation: [
        [internalKey, {der: {fingerprint: 0x73c5da0a, path: [0x80000056, 0x80000001, 0x80000000, 0, 0]}, hashes: []}],
      ],
      tapInternalKey: internalKey,
    })
    assert.equal(hex.encode(written.toPSBT(0)), hex.encode(psbt))

    const decoded = testnet.decodePsbt(psbt)
    assert.deepEqual(decoded.inputs[0]?.taprootInternalKey, internalKey)
    assert.equal(decoded.inputs[0]?.taprootDerivations[0]?.path, account.path)
    assert.equal(decoded.inputs[0]?.address, account.address)
    assert.deepEqual(decoded.outputs[1]?.taprootDerivations[0]?.publicKey, internalKey)
    assert.equal(decoded.outputs[1]?.taprootDerivations[0]?.fingerprint, account.fingerprint)
  })

  test('signed here, finalized there, and the other way round', async () => {
    const random = seeded(371)

    for (let round = 0; round < 8; round++) {
      const utxos = Array.from({length: 1 + random.integer(3)}, (_, index) =>
        utxo((round * 16 + index + 1).toString(16).padStart(2, '0'), 10_000 + random.integer(500_000), index)
      )
      const plan = account.createTransaction({
        amount: round % 4 === 3 ? 'max' : 5_000n,
        feeRate: 1 + round,
        to: recipient,
        utxos,
      })
      const psbt = account.createPsbt(plan)

      // Signed by this package, finalized by btc-signer and by this package alike.
      const {psbt: signed, signedInputs} = await account.signPsbt(psbt)
      assert.deepEqual(
        signedInputs,
        plan.inputs.map((_, index) => index)
      )
      assert.equal(testnet.decodePsbt(signed).inputs[0]?.taprootKeySignature?.length, 64)
      const theirs = Transaction.fromPSBT(signed)
      theirs.finalize()
      const ours = testnet.finalizePsbt(signed)
      assert.equal(ours.hex, hex.encode(theirs.extract()), `round ${round}`)
      assert.equal(ours.vsize, plan.vsize)

      // Signed by btc-signer, finalized here: the same as btc-signer finalizes it.
      const external = Transaction.fromPSBT(psbt)
      external.sign(secret, undefined, random.bytes(32))
      const externalPsbt = external.toPSBT()
      external.finalize()
      assert.equal(testnet.finalizePsbt(externalPsbt).hex, hex.encode(external.extract()))

      // Finalized by btc-signer already: verified, not trusted.
      assert.equal(testnet.finalizePsbt(external.toPSBT()).hex, hex.encode(external.extract()))
    }
  })

  test('with the same aux randomness, signPsbt signs what btc-signer signs, byte for byte', () => {
    const plan = account.createTransaction({
      amount: 12_345n,
      feeRate: 3,
      to: recipient,
      utxos: [utxo('ab', 90_000), utxo('cd', 10_000, 2)],
    })
    const aux = new Uint8Array(32).fill(7)
    const key = withAux(wallet.deriveKey('bip32', account.path), secret, aux)
    const signer: AccountSigner = {key, publicKey: account.publicKey, scriptPubKey: account.scriptPubKey, type: 'p2tr'}
    const {psbt} = signPsbt(account.createPsbt(plan), signer, transactions)
    const theirs = Transaction.fromPSBT(account.createPsbt(plan))
    theirs.sign(secret, undefined, aux)

    for (let index = 0; index < plan.inputs.length; index++) {
      assert.deepEqual(Transaction.fromPSBT(psbt).getInput(index).tapKeySig, theirs.getInput(index).tapKeySig)
    }
  })

  test('mixed inputs: a P2WPKH coin, a BIP-86 coin and a coin of the Taproot key under a script tree, signed by each account', async () => {
    const leaf = p2tr(internalKey, {script: Uint8Array.of(0x51)}, TEST_NETWORK, true)
    const tx = new Transaction({lockTime: 0, version: 2})
    tx.addInput({
      bip32Derivation: [
        [segwit.publicKey, {fingerprint: segwit.fingerprint, path: [0x80000054, 0x80000001, 0x80000000, 0, 0]}],
      ],
      index: 0,
      sequence: 0xfffffffd,
      txid: '11'.repeat(32),
      witnessUtxo: {amount: 40_000n, script: segwit.scriptPubKey},
    })
    tx.addInput({
      index: 1,
      sequence: 0xfffffffd,
      tapInternalKey: internalKey,
      txid: '22'.repeat(32),
      witnessUtxo: {amount: 50_000n, script: account.scriptPubKey},
    })
    tx.addInput({
      index: 2,
      sequence: 0xfffffffd,
      tapInternalKey: internalKey,
      tapMerkleRoot: leaf.tapMerkleRoot,
      txid: '33'.repeat(32),
      witnessUtxo: {amount: 60_000n, script: leaf.script},
    })
    tx.addOutputAddress(recipient, 140_000n, TEST_NETWORK)
    const psbt = tx.toPSBT()

    const decoded = testnet.decodePsbt(psbt)
    assert.deepEqual(decoded.inputs[2]?.taprootMerkleRoot, leaf.tapMerkleRoot)
    assert.equal(decoded.fee, 10_000n)

    // Each account signs its own inputs and leaves the others.
    const first = await segwit.signPsbt(psbt)
    assert.deepEqual(first.signedInputs, [0])
    const second = await account.signPsbt(first.psbt)
    assert.deepEqual(second.signedInputs, [1, 2])
    const ours = testnet.finalizePsbt(second.psbt)
    const theirs = Transaction.fromPSBT(second.psbt)
    theirs.finalize()
    assert.equal(ours.hex, hex.encode(theirs.extract()))
    assert.equal(ours.fee, 10_000n)

    // Signed by btc-signer with both keys, finalized here.
    const external = Transaction.fromPSBT(psbt)
    external.sign(segwitSecret)
    external.sign(secret)
    const externalPsbt = external.toPSBT()
    external.finalize()
    assert.equal(testnet.finalizePsbt(externalPsbt).hex, hex.encode(external.extract()))
  })

  test('SIGHASH_ALL when the PSBT asks; any other type is refused', async () => {
    const plan = account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    const asking = (type: number) =>
      addToInput(account.createPsbt(plan), 0, Uint8Array.of(0x03), Uint8Array.of(type, 0, 0, 0))
    const {psbt} = await account.signPsbt(asking(SigHash.ALL))
    const signature = testnet.decodePsbt(psbt).inputs[0]?.taprootKeySignature
    assert.equal(signature?.length, 65)
    assert.equal(signature?.[64], SigHash.ALL)
    const theirs = Transaction.fromPSBT(psbt)
    theirs.finalize()
    assert.equal(testnet.finalizePsbt(psbt).hex, hex.encode(theirs.extract()))

    for (const type of [0x02, 0x03, 0x81, 0x83, 0x04]) {
      await rejectsWith(account.signPsbt(asking(type)), 'INVALID_ARGUMENT', /sighash/)
    }

    // An explicit SIGHASH_DEFAULT is the default.
    assert.equal(
      testnet.decodePsbt((await account.signPsbt(asking(0))).psbt).inputs[0]?.taprootKeySignature?.length,
      64
    )

    // A signature with another type than the PSBT asks for is no signature of it.
    const other = editInput(psbt, 0, 0x03, () => Uint8Array.of(0, 0, 0, 0))
    throwsWith(() => testnet.finalizePsbt(other), 'INVALID_SIGNATURE')
  })

  test('a Taproot signature commits to every coin: a PSBT that leaves one out is not signed', async () => {
    const tx = new Transaction({lockTime: 0, version: 2})
    tx.addInput({index: 0, txid: '44'.repeat(32), witnessUtxo: {amount: 50_000n, script: account.scriptPubKey}})
    tx.addInput({index: 0, txid: '55'.repeat(32)})
    tx.addOutputAddress(recipient, 40_000n, TEST_NETWORK)
    await rejectsWith(account.signPsbt(tx.toPSBT()), 'INVALID_ARGUMENT', /every coin/)
  })

  test('forged, misplaced or missing signatures never finalize', async () => {
    const plan = account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    const {psbt} = await account.signPsbt(account.createPsbt(plan))
    const flipped = editInput(psbt, 0, 0x13, value => {
      const out = value.slice()
      out[40] = (out[40] ?? 0) ^ 1

      return out
    })
    throwsWith(() => testnet.finalizePsbt(flipped), 'INVALID_SIGNATURE')

    const otherPlan = account.createTransaction({
      amount: 10_000n,
      feeRate: 2,
      to: recipient,
      utxos: [utxo('aa', 50_000)],
    })
    const otherSignature = testnet.decodePsbt((await account.signPsbt(account.createPsbt(otherPlan))).psbt).inputs[0]
      ?.taprootKeySignature
    throwsWith(() => testnet.finalizePsbt(editInput(psbt, 0, 0x13, () => otherSignature)), 'INVALID_SIGNATURE')
    throwsWith(() => testnet.finalizePsbt(account.createPsbt(plan)), 'INVALID_ARGUMENT', /key path/)

    // A final witness that is not one key path signature, or a false one, is refused too.
    const finalized = (witness: Uint8Array[]) =>
      addToInput(
        editInput(psbt, 0, 0x13, () => undefined),
        0,
        Uint8Array.of(0x08),
        bytes.concat(Uint8Array.of(witness.length), ...witness.flatMap(item => [Uint8Array.of(item.length), item]))
      )
    const signature = testnet.decodePsbt(psbt).inputs[0]?.taprootKeySignature ?? new Uint8Array()
    assert.equal(testnet.finalizePsbt(finalized([signature])).hex, testnet.finalizePsbt(psbt).hex)
    throwsWith(() => testnet.finalizePsbt(finalized([signature, Uint8Array.of(0x51)])), 'INVALID_ARGUMENT')
    throwsWith(() => testnet.finalizePsbt(finalized([otherSignature ?? new Uint8Array()])), 'INVALID_SIGNATURE')
  })

  test('malformed Taproot fields are refused', async () => {
    const plan = account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]})
    const psbt = account.createPsbt(plan)
    const {psbt: signed} = await account.signPsbt(psbt)
    const cases = [
      editInput(psbt, 0, 0x17, value => value.subarray(1)),
      editInput(psbt, 0, 0x16, value => value.subarray(0, value.length - 1)),
      editInput(psbt, 0, 0x16, () => Uint8Array.of(5)),
      addToInput(psbt, 0, Uint8Array.of(0x18), new Uint8Array(31)),
      addToInput(psbt, 0, Uint8Array.of(0x13, 0x00), new Uint8Array(64)),
      addToInput(psbt, 0, Uint8Array.of(0x16, 0x01), new Uint8Array(8)),
      editInput(signed, 0, 0x13, value => bytes.concat(value, Uint8Array.of(0))),
      editInput(signed, 0, 0x13, value => bytes.concat(value, Uint8Array.of(4))),
      editInput(signed, 0, 0x13, value => value.subarray(1)),
    ]

    for (const [index, data] of cases.entries()) {
      throwsWith(() => testnet.decodePsbt(data), 'INVALID_ARGUMENT', undefined)
      assert.ok(true, `case ${index}`)
    }
  })

  test('a watch-only Taproot account writes the same PSBTs', () => {
    const watch = testnet.watchAccount({
      addressType: 'p2tr',
      fingerprint: account.fingerprint,
      path: account.path,
      publicKey: account.publicKey,
    })
    assert.equal(watch.address, account.address)
    assert.equal(watch.addressType, 'p2tr')
    assert.equal('signPsbt' in watch, false)
    const plan = watch.createTransaction({amount: 10_000n, feeRate: 2, to: recipient, utxos: [utxo('aa', 50_000)]})
    assert.deepEqual(watch.createPsbt(plan), account.createPsbt(plan))
  })
})

describe('an engine without Schnorr signatures', async () => {
  // An engine from before secp256k1-schnorr and taproot-tweak: the adapter registers, P2WPKH works, Taproot says no.
  const lacking: readonly Capability[] = ['secp256k1-schnorr', 'taproot-tweak']
  const context: AdapterContext = {
    bip32: crypto.bip32,
    ed25519: crypto.ed25519,
    engine: {
      ...crypto.info,
      capabilities: crypto.info.capabilities.filter(name => !lacking.includes(name as Capability)),
      has: capability => !lacking.includes(capability) && crypto.info.has(capability),
    },
    hash: crypto.hash,
    hmac: crypto.hmac,
    random: crypto.random,
    schnorr: crypto.schnorr,
    secp256k1: crypto.secp256k1,
  }
  const older = bitcoinAdapter({network: 'testnet'}).create(context)
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const taproot = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin-testnet'})
  after(() => wallet.dispose())

  test('the adapter does not require them, and P2WPKH accounts work as before', async () => {
    assert.ok(!bitcoinAdapter().requires.some(capability => lacking.includes(capability)))
    const account = await older.deriveAccount(wallet, {})
    const plan = account.createTransaction({
      amount: 10_000n,
      feeRate: 1,
      to: taproot.address,
      utxos: [utxo('aa', 50_000)],
    })
    assert.equal(
      older.finalizePsbt((await account.signPsbt(account.createPsbt(plan))).psbt).hex,
      (await account.signTransaction(plan)).hex
    )
    const signature = await account.signMessage({message: 'still here'})
    assert.equal(await account.verifyMessage({message: 'still here', signature}), true)
    assert.equal(older.validateAddress(taproot.address).valid, true)
  })

  test('Taproot throws UNSUPPORTED, naming what is missing', async () => {
    await rejectsWith(
      older.deriveAccount(wallet, {addressType: 'p2tr'}),
      'UNSUPPORTED',
      /secp256k1-schnorr and taproot-tweak/
    )
    throwsWith(() => older.addressFromPublicKey(taproot.publicKey, 'p2tr'), 'UNSUPPORTED', /taproot-tweak/)
    throwsWith(
      () => older.watchAccount({addressType: 'p2tr', fingerprint: 1, path: taproot.path, publicKey: taproot.publicKey}),
      'UNSUPPORTED'
    )
    const plan = taproot.createTransaction({
      amount: 10_000n,
      feeRate: 1,
      to: taproot.address,
      utxos: [utxo('aa', 50_000)],
    })
    const {psbt} = await taproot.signPsbt(taproot.createPsbt(plan))
    throwsWith(() => older.finalizePsbt(psbt), 'UNSUPPORTED', /secp256k1-schnorr/)
    const signature = await taproot.signMessage({message: 'hi'})
    throwsWith(() => older.verifyMessage({address: taproot.address, message: 'hi', signature}), 'UNSUPPORTED')
  })
})
