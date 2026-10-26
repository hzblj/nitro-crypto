import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {hex, isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {NETWORK, p2pk, p2pkh, p2sh, p2tr, p2wpkh, p2wsh, TEST_NETWORK, Transaction} from '@scure/btc-signer'

import {type BitcoinTransactionPlan, type BitcoinUtxo, bitcoinAdapter} from '../src'
import {encodeDerSignature} from '../src/der'
import {bip143Digest, p2wpkhScriptCode, type RawTransaction, serializeTransaction} from '../src/transaction'

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const crypto = createTestCryptoEngine({
  adapters: [bitcoinAdapter(), bitcoinAdapter({id: 'bitcoin-testnet', network: 'testnet'})],
})
const testnet = crypto.chains['bitcoin-testnet']
const sha256 = crypto.hash.sha256

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

const rejectsWith = async (promise: Promise<unknown>, code: Parameters<typeof isCryptoError>[1]) =>
  assert.rejects(promise, error => isCryptoError(error, code))

const throwsWith = (run: () => unknown, code: Parameters<typeof isCryptoError>[1], message?: RegExp) =>
  assert.throws(run, error => isCryptoError(error, code) && (!message || message.test(error.message)))

describe('BIP-143', () => {
  // BIP-143's "Native P2WPKH" example: two inputs, the second one P2WPKH, which is the one signed here.
  const tx: RawTransaction = {
    inputs: [
      {
        sequence: 0xffffffee,
        txid: hex.decode('fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f'),
        value: 625_000_000n,
        vout: 0,
      },
      {
        sequence: 0xffffffff,
        txid: hex.decode('ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a'),
        value: 600_000_000n,
        vout: 1,
      },
    ],
    locktime: 0x11,
    outputs: [
      {scriptPubKey: hex.decode('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'), value: 112_340_000n},
      {scriptPubKey: hex.decode('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac'), value: 223_450_000n},
    ],
    version: 1,
  }

  test('the unsigned transaction serializes as published', () => {
    assert.equal(
      hex.encode(serializeTransaction(tx)),
      '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
    )
  })

  test('the P2WPKH input`s sighash and signature are the published ones, through the engine', () => {
    const scriptCode = p2wpkhScriptCode(hex.decode('1d0f172a0ecb48aee1be1f2687d2963ae33f71a1'))
    const digest = bip143Digest(tx, 1, scriptCode, sha256)
    assert.equal(hex.encode(digest), 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')

    const key = crypto.keys.importRawSecret(
      'secp256k1',
      hex.decode('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9')
    )
    assert.equal(hex.encode(key.publicKey()), '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357')
    assert.equal(
      hex.encode(encodeDerSignature(key.sign(digest).signature)),
      '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee'
    )
    key.dispose()
  })
})

describe('DER', () => {
  test('integers lose leading zeros and gain one where the high bit is set', () => {
    const signature = new Uint8Array(64)
    signature[31] = 1
    signature[32] = 0x80
    assert.equal(hex.encode(encodeDerSignature(signature)), `3026020101022100${'80'}${'00'.repeat(31)}`)
    throwsWith(() => encodeDerSignature(new Uint8Array(63)), 'INVALID_SIGNATURE')
  })
})

describe('parity with @scure/btc-signer', () => {
  test('random payments from a BIP-84 testnet account sign to the same bytes and txid', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
    const account = await wallet.deriveAccount({chain: 'bitcoin-testnet'})
    const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC)).derive(account.path)
    const privateKey = reference.privateKey ?? new Uint8Array()
    const other = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC, 'other')).derive("m/84'/1'/0'/0/0")
    const otherKey = other.publicKey ?? new Uint8Array()
    const recipients = [
      p2wpkh(otherKey, TEST_NETWORK).address,
      p2tr(otherKey.subarray(1), undefined, TEST_NETWORK).address,
      p2wsh(p2pk(otherKey), TEST_NETWORK).address,
      p2pkh(otherKey, TEST_NETWORK).address,
      p2sh(p2wpkh(otherKey, TEST_NETWORK), TEST_NETWORK).address,
      account.address,
    ].map(address => address ?? '')
    const random = seeded(84)
    const randomHex = (length: number) =>
      Array.from({length}, () =>
        Math.floor(random() * 256)
          .toString(16)
          .padStart(2, '0')
      ).join('')

    for (let round = 0; round < 24; round++) {
      const utxos = Array.from({length: 1 + Math.floor(random() * 4)}, () => ({
        txid: randomHex(32),
        value: BigInt(5_000 + Math.floor(random() * 2_000_000)),
        vout: Math.floor(random() * 4),
      }))
      const total = utxos.reduce((sum, coin) => sum + coin.value, 0n)
      const to = recipients[round % recipients.length] ?? ''
      const amount = round % 5 === 4 ? 'max' : 1_000n + BigInt(Math.floor(random() * Number(total / 2n)))
      const feeRate = [1, 1.5, 2, 5, 12.3][round % 5] ?? 1
      const plan = account.createTransaction({amount, feeRate, to, utxos})
      const signed = await account.signTransaction(plan)

      const theirs = new Transaction({lockTime: 0, version: 2})
      for (const input of plan.inputs) {
        theirs.addInput({
          index: input.vout,
          sequence: 0xfffffffd,
          txid: input.txid,
          witnessUtxo: {amount: input.value, script: account.scriptPubKey},
        })
      }
      for (const output of plan.outputs) {
        theirs.addOutput({amount: output.value, script: output.scriptPubKey})
      }
      theirs.sign(privateKey)
      theirs.finalize()

      assert.equal(signed.hex, theirs.hex, `round ${round}`)
      assert.equal(signed.txid, theirs.id)
      assert.equal(signed.weight, theirs.weight)
      assert.equal(signed.vsize, theirs.vsize)
      assert.equal(signed.fee, theirs.fee)
      // The estimate assumes the longest signature, so it is an upper bound, by under a byte per input.
      assert.ok(signed.vsize <= plan.vsize && signed.vsize >= plan.vsize - plan.inputs.length, `round ${round}`)
      assert.ok(Number(plan.fee) >= Math.floor(signed.vsize * feeRate), `round ${round}`)
    }
    wallet.dispose()
  })
})

describe('coin selection', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const account = await wallet.deriveAccount({chain: 'bitcoin-testnet'})
  const recipient = (await wallet.deriveAccount({chain: 'bitcoin-testnet', index: 1})).address
  after(() => wallet.dispose())

  test('largest coins first, change back to the account', () => {
    const plan = account.createTransaction({
      amount: 40_000n,
      feeRate: 1,
      to: recipient,
      utxos: [utxo('aa', 10_000), utxo('bb', 50_000), utxo('cc', 30_000)],
    })
    assert.deepEqual(
      plan.inputs.map(input => input.value),
      [50_000n]
    )
    assert.equal(plan.vsize, 141)
    assert.equal(plan.fee, 141n)
    assert.equal(plan.change, 50_000n - 40_000n - 141n)
    assert.deepEqual(
      plan.outputs.map(output => [output.address, output.value]),
      [
        [recipient, 40_000n],
        [account.address, plan.change],
      ]
    )
  })

  test('more coins when one is not enough, and change to a stated address', () => {
    const plan = account.createTransaction({
      amount: 55_000n,
      changeAddress: recipient,
      feeRate: 2,
      to: account.address,
      utxos: [utxo('aa', 10_000), utxo('bb', 50_000), utxo('cc', 30_000)],
    })
    assert.deepEqual(
      plan.inputs.map(input => input.value),
      [50_000n, 30_000n]
    )
    assert.equal(plan.outputs[1]?.address, recipient)
    assert.equal(plan.fee, BigInt(plan.vsize * 2))
  })

  test('change under the dust limit joins the fee, and there is no change output', () => {
    // 100,000 sats less 99,500 leaves 500; at 2 sat/vB the fee with change is 282, which leaves 218: dust.
    const plan = account.createTransaction({amount: 99_500n, feeRate: 2, to: recipient, utxos: [utxo('aa', 100_000)]})
    assert.equal(plan.outputs.length, 1)
    assert.equal(plan.change, 0n)
    assert.equal(plan.fee, 500n)
    assert.equal(plan.vsize, 110)
  })

  test('max spends every coin, with no change', () => {
    const plan = account.createTransaction({
      amount: 'max',
      feeRate: 3,
      to: recipient,
      utxos: [utxo('aa', 10_000), utxo('bb', 20_000, 1)],
    })
    assert.equal(plan.inputs.length, 2)
    assert.equal(plan.outputs.length, 1)
    assert.equal(plan.vsize, 178)
    assert.equal(plan.fee, 534n)
    assert.equal(plan.amount, 30_000n - 534n)
    assert.equal(plan.outputs[0]?.value, plan.amount)
  })

  test('not enough funds says how much is missing', () => {
    throwsWith(
      () => account.createTransaction({amount: 60_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 50_000)]}),
      'INVALID_ARGUMENT',
      /10110 short/
    )
    throwsWith(
      () => account.createTransaction({amount: 'max', feeRate: 10, to: recipient, utxos: [utxo('aa', 1_000)]}),
      'INVALID_ARGUMENT',
      /dust/
    )
  })

  test('the dust limit follows the recipient`s output type', () => {
    const p2pkhAddress = p2pkh(account.publicKey, TEST_NETWORK).address ?? ''
    const p2trAddress = p2tr(account.publicKey.subarray(1), undefined, TEST_NETWORK).address ?? ''
    const p2shAddress = p2sh(p2wpkh(account.publicKey, TEST_NETWORK), TEST_NETWORK).address ?? ''
    assert.equal(testnet.dustThreshold(recipient), 294n)
    assert.equal(testnet.dustThreshold(p2trAddress), 330n)
    assert.equal(testnet.dustThreshold(p2wsh(p2pk(account.publicKey), TEST_NETWORK).address ?? ''), 330n)
    assert.equal(testnet.dustThreshold(p2pkhAddress), 546n)
    assert.equal(testnet.dustThreshold(p2shAddress), 540n)
    const coins = [utxo('aa', 100_000)]
    throwsWith(
      () => account.createTransaction({amount: 293n, feeRate: 1, to: recipient, utxos: coins}),
      'INVALID_ARGUMENT'
    )
    assert.equal(account.createTransaction({amount: 294n, feeRate: 1, to: recipient, utxos: coins}).amount, 294n)
    throwsWith(
      () => account.createTransaction({amount: 545n, feeRate: 1, to: p2pkhAddress, utxos: coins}),
      'INVALID_ARGUMENT'
    )
    throwsWith(() => testnet.dustThreshold('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), 'INVALID_ADDRESS')
  })

  test('an address of another network is refused, and so is anything that is not one', () => {
    const coins = [utxo('aa', 100_000)]
    const mainnetAddress = p2wpkh(account.publicKey, NETWORK).address ?? ''
    throwsWith(
      () => account.createTransaction({amount: 10_000n, feeRate: 1, to: mainnetAddress, utxos: coins}),
      'INVALID_ADDRESS',
      /testnet/
    )
    throwsWith(
      () =>
        account.createTransaction({amount: 10_000n, changeAddress: 'nope', feeRate: 1, to: recipient, utxos: coins}),
      'INVALID_ADDRESS'
    )
  })

  test('fee rates, amounts and coins are checked', () => {
    const coins = [utxo('aa', 100_000)]
    for (const feeRate of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      throwsWith(
        () => account.createTransaction({amount: 10_000n, feeRate, to: recipient, utxos: coins}),
        'INVALID_ARGUMENT'
      )
    }
    for (const amount of [0n, -5n, 10_000 as unknown as bigint, 2_100_000_000_000_001n]) {
      throwsWith(() => account.createTransaction({amount, feeRate: 1, to: recipient, utxos: coins}), 'INVALID_ARGUMENT')
    }
    for (const utxos of [
      [],
      [utxo('aa', 1), utxo('aa', 2)],
      [{...utxo('aa', 1_000), txid: 'zz'}],
      [{...utxo('aa', 1_000), vout: -1}],
      [{...utxo('aa', 1_000), value: 1_000 as unknown as bigint}],
    ]) {
      throwsWith(
        () => account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos}),
        'INVALID_ARGUMENT'
      )
    }
  })

  test('a plan changed after it was made is refused before anything is signed', async () => {
    const plan = account.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 100_000)]})
    const [first, second] = plan.outputs
    assert.ok(first && second)
    const tampered: BitcoinTransactionPlan[] = [
      {...plan, fee: plan.fee + 1n},
      {...plan, outputs: [{...first, value: first.value + 1n}, second]},
      {...plan, outputs: [{...first, scriptPubKey: second.scriptPubKey}, second]},
      {...plan, outputs: [{...first, value: 200_000n}, second]},
      {...plan, outputs: []},
    ]
    for (const changed of tampered) {
      await rejectsWith(account.signTransaction(changed), 'INVALID_ARGUMENT')
    }
  })

  test('signing needs the wallet: once disposed, it throws DISPOSED', async () => {
    const own = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
    const spender = await own.deriveAccount({chain: 'bitcoin-testnet'})
    const plan = spender.createTransaction({amount: 10_000n, feeRate: 1, to: recipient, utxos: [utxo('aa', 100_000)]})
    own.dispose()
    await rejectsWith(spender.signTransaction(plan), 'DISPOSED')
  })

  test('the adapter states what it signs', () => {
    assert.equal(bitcoinAdapter().features.transactionSigning, true)
    assert.equal(bitcoinAdapter().features.psbt, false)
    assert.deepEqual(bitcoinAdapter().formats.signature, ['p2wpkh-bip143'])
  })
})
