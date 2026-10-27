import assert from 'node:assert/strict'
import {describe, test} from 'node:test'

import {schnorr} from '@noble/curves/secp256k1.js'
import {bytesToNumberBE, concatBytes} from '@noble/curves/utils.js'

import {isCryptoError} from '../src/core/errors'
import {hex, utf8} from '../src/encoding'
import {createAbi} from './abi'
import {ABANDON, crypto, engineVectorText, seededBytes} from './support'

const throwsCode = (run: () => unknown, code: string) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

/** BIP-341's output key by @noble/curves: Q = lift_x(P) + TapTweak(P || merkle root)·G. */
const nobleTweak = (internal: Uint8Array, merkleRoot?: Uint8Array) => {
  const point = schnorr.utils.lift_x(bytesToNumberBE(internal))
  const tweak = schnorr.utils.taggedHash('TapTweak', merkleRoot ? concatBytes(internal, merkleRoot) : internal)
  const output = point.add(schnorr.Point.BASE.multiply(bytesToNumberBE(tweak))).toBytes(true)

  return {parity: output[0] === 3 ? 1 : 0, publicKey: output.slice(1)}
}

/** The engine's own C ABI, for the WebAssembly build's test hook: Schnorr signing with the aux randomness given. */
const abi = createAbi()

const signWithAux = (secret: Uint8Array, message: Uint8Array, aux: Uint8Array, taproot?: {merkleRoot?: Uint8Array}) =>
  abi.frame(frame => {
    const handle = frame.allocate(8)
    const [secretPointer, secretLength] = frame.input(secret)
    assert.equal(abi.engine.nc_key_import(1, secretPointer, secretLength, handle), 0)
    const key = frame.u64(handle)

    try {
      const [messagePointer, messageLength] = frame.input(message)
      const [rootPointer, rootLength] = frame.input(taproot?.merkleRoot ?? new Uint8Array())
      const [auxPointer, auxLength] = frame.input(aux)
      const out = frame.allocate(64)
      const written = frame.allocate(4)
      const status = abi.engine.nc_wasm_test_sign_schnorr(
        key,
        messagePointer,
        messageLength,
        taproot ? 1 : 0,
        rootPointer,
        rootLength,
        auxPointer,
        auxLength,
        out,
        64,
        written
      )
      assert.equal(abi.statusName(status), 'NC_OK')

      return frame.read(out, frame.u32(written))
    } finally {
      abi.engine.nc_handle_destroy(key)
    }
  })

describe('BIP-340 Schnorr', () => {
  test('every published vector: signed with its aux_rand, and verified', () => {
    const [, ...rows] = engineVectorText('bip340.csv').trim().split(/\r?\n/)
    assert.equal(rows.length, 19)
    let signed = 0

    for (const row of rows) {
      const [index, secret, publicKey, aux, message, signature, result, comment] = row.split(',')
      const [key, msg, sig] = [hex.decode(publicKey ?? ''), hex.decode(message ?? ''), hex.decode(signature ?? '')]

      if (secret) {
        const imported = crypto.keys.importRawSecret('secp256k1', hex.decode(secret))
        assert.deepEqual(imported.xOnlyPublicKey(), key, `vector ${index}`)
        imported.dispose()
        assert.deepEqual(signWithAux(hex.decode(secret), msg, hex.decode(aux ?? '')), sig, `vector ${index}`)
        signed++
      }

      if (result === 'TRUE') {
        assert.equal(crypto.schnorr.verify(key, msg, sig), true, `vector ${index}`)
      } else if (comment?.startsWith('public key')) {
        throwsCode(() => crypto.schnorr.verify(key, msg, sig), 'INVALID_PUBLIC_KEY')
      } else {
        assert.equal(crypto.schnorr.verify(key, msg, sig), false, `vector ${index}`)
      }
    }

    assert.equal(signed, 8)
  })

  test('keys and signatures agree with @noble/curves both ways, on random keys and messages of any length', () => {
    const random = seededBytes(70)

    for (let round = 0; round < 32; round++) {
      const secret = schnorr.utils.randomSecretKey(random.bytes(48))
      const message = random.bytes(random.integer(100))
      const key = crypto.keys.importRawSecret('secp256k1', secret)
      const publicKey = schnorr.getPublicKey(secret)
      assert.deepEqual(key.xOnlyPublicKey(), publicKey)
      assert.deepEqual(key.xOnlyPublicKey(), key.publicKey().subarray(1))

      const ours = key.signSchnorr(message)
      assert.equal(ours.length, 64)
      assert.equal(schnorr.verify(ours, message, publicKey), true)
      assert.equal(crypto.schnorr.verify(publicKey, message, ours), true)
      const theirs = schnorr.sign(message, secret, random.bytes(32))
      assert.equal(crypto.schnorr.verify(publicKey, message, theirs), true)

      // The same aux randomness gives the same signature as @noble's.
      const aux = random.bytes(32)
      assert.deepEqual(signWithAux(secret, message, aux), schnorr.sign(message, secret, aux))
      key.dispose()
    }
  })

  test('fresh aux randomness: two signatures of one message differ, and both verify', () => {
    const key = crypto.keys.generate('secp256k1')
    const message = utf8.encode('BIP-340')
    const [first, second] = [key.signSchnorr(message), key.signSchnorr(message)]
    assert.notDeepEqual(first, second)
    assert.equal(crypto.schnorr.verify(key.xOnlyPublicKey(), message, first), true)
    assert.equal(crypto.schnorr.verify(key.xOnlyPublicKey(), message, second), true)
    assert.equal(crypto.schnorr.verify(key.xOnlyPublicKey(), new Uint8Array(), key.signSchnorr(new Uint8Array())), true)
    key.dispose()
  })

  test('verify is false for another message or a changed signature, and throws for malformed keys and lengths', () => {
    const key = crypto.keys.generate('secp256k1')
    const message = crypto.random(32)
    const signature = key.signSchnorr(message)
    const publicKey = key.xOnlyPublicKey()

    const changed = signature.slice()
    changed[10] = (changed[10] ?? 0) ^ 1
    assert.equal(crypto.schnorr.verify(publicKey, message, changed), false)
    assert.equal(crypto.schnorr.verify(publicKey, message.subarray(1), signature), false)
    // s equal to the group order: malformed, so false.
    const order = hex.decode('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
    assert.equal(crypto.schnorr.verify(publicKey, message, concatBytes(signature.subarray(0, 32), order)), false)

    throwsCode(() => crypto.schnorr.verify(key.publicKey(), message, signature), 'INVALID_LENGTH')
    throwsCode(() => crypto.schnorr.verify(publicKey, message, signature.subarray(1)), 'INVALID_LENGTH')
    const offCurve = new Uint8Array(32)
    offCurve[31] = 5
    throwsCode(() => crypto.schnorr.verify(offCurve, message, signature), 'INVALID_PUBLIC_KEY')
    key.dispose()
    throwsCode(() => key.signSchnorr(message), 'DISPOSED')
    throwsCode(() => key.xOnlyPublicKey(), 'DISPOSED')
  })
})

type Bip341 = {
  scriptPubKey: {
    given: {internalPubkey: string}
    intermediary: {merkleRoot: string | null; tweakedPubkey: string}
    expected: {scriptPathControlBlocks?: string[]}
  }[]
  keyPathSpending: {
    inputSpending: {
      given: {internalPrivkey: string; merkleRoot: string | null}
      intermediary: {internalPubkey: string; sigHash: string}
      expected: {witness: string[]}
    }[]
  }[]
}

describe('BIP-341 Taproot', () => {
  const vectors = JSON.parse(engineVectorText('bip341.json')) as Bip341
  const root = (merkleRoot: string | null) => (merkleRoot === null ? undefined : hex.decode(merkleRoot))

  test('output keys and their parity from every scriptPubKey vector', () => {
    assert.equal(vectors.scriptPubKey.length, 7)

    for (const {given, intermediary, expected} of vectors.scriptPubKey) {
      const output = crypto.schnorr.taprootTweak(hex.decode(given.internalPubkey), root(intermediary.merkleRoot))
      assert.equal(hex.encode(output.publicKey), intermediary.tweakedPubkey)

      for (const block of expected.scriptPathControlBlocks ?? []) {
        assert.equal(Number.parseInt(block.slice(0, 2), 16) & 1, output.parity)
      }
    }
  })

  test('every key path signature, with the vectors` zero aux randomness and with fresh', () => {
    let inputs = 0

    for (const spending of vectors.keyPathSpending) {
      for (const {given, intermediary, expected} of spending.inputSpending) {
        const secret = hex.decode(given.internalPrivkey)
        const merkleRoot = root(given.merkleRoot)
        const sighash = hex.decode(intermediary.sigHash)
        const witness = (expected.witness[0] ?? '').slice(0, 128)
        assert.equal(hex.encode(signWithAux(secret, sighash, new Uint8Array(32), {merkleRoot})), witness)

        const key = crypto.keys.importRawSecret('secp256k1', secret)
        assert.equal(hex.encode(key.xOnlyPublicKey()), intermediary.internalPubkey)
        const output = crypto.schnorr.taprootTweak(key.xOnlyPublicKey(), merkleRoot)
        const signature = key.signTaproot(sighash, merkleRoot)
        assert.equal(crypto.schnorr.verify(output.publicKey, sighash, signature), true)
        assert.equal(crypto.schnorr.verify(key.xOnlyPublicKey(), sighash, signature), false)
        key.dispose()
        inputs++
      }
    }

    assert.equal(inputs, 7)
  })

  test('BIP-86: the first receiving key of "abandon ... about", from the seed and from the account`s xpub', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const key = wallet.deriveKey('bip32', "m/86'/0'/0'/0/0")
    const internal = 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115'
    const output = 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'
    assert.equal(hex.encode(key.xOnlyPublicKey()), internal)
    assert.equal(hex.encode(crypto.schnorr.taprootTweak(key.xOnlyPublicKey()).publicKey), output)

    // A watch-only wallet has the account's extended public key, and compressed keys below it.
    const account = wallet.extendedPublicKey("m/86'/0'/0'")
    const watched = crypto.bip32.derivePublic(account, 'm/0/0').publicKey
    assert.equal(hex.encode(crypto.schnorr.taprootTweak(watched).publicKey), output)

    const sighash = crypto.random(32)
    assert.equal(crypto.schnorr.verify(hex.decode(output), sighash, key.signTaproot(sighash)), true)
    wallet.dispose()
  })

  test('the tweak agrees with @noble/curves on random keys and roots, x-only and SEC1 alike', () => {
    const random = seededBytes(71)

    for (let round = 0; round < 16; round++) {
      const key = crypto.keys.importRawSecret('secp256k1', schnorr.utils.randomSecretKey(random.bytes(48)))
      const merkleRoot = round % 2 === 0 ? undefined : random.bytes(32)
      const expected = nobleTweak(key.xOnlyPublicKey(), merkleRoot)
      assert.deepEqual(crypto.schnorr.taprootTweak(key.xOnlyPublicKey(), merkleRoot), expected)
      assert.deepEqual(crypto.schnorr.taprootTweak(key.publicKey(), merkleRoot), expected)
      assert.deepEqual(crypto.schnorr.taprootTweak(key.publicKey('uncompressed'), merkleRoot), expected)
      key.dispose()
    }
  })

  test('refusals: a sighash or merkle root of another length, an empty root, keys of another length', () => {
    const key = crypto.keys.generate('secp256k1')
    const sighash = crypto.random(32)
    throwsCode(() => key.signTaproot(sighash.subarray(1)), 'INVALID_LENGTH')
    throwsCode(() => key.signTaproot(sighash, new Uint8Array(31)), 'INVALID_LENGTH')
    throwsCode(() => key.signTaproot(sighash, new Uint8Array(0)), 'INVALID_LENGTH')
    throwsCode(() => crypto.schnorr.taprootTweak(key.xOnlyPublicKey(), new Uint8Array(0)), 'INVALID_LENGTH')
    throwsCode(() => crypto.schnorr.taprootTweak(key.xOnlyPublicKey().subarray(1)), 'INVALID_LENGTH')
    const offCurve = new Uint8Array(32)
    offCurve[31] = 5
    throwsCode(() => crypto.schnorr.taprootTweak(offCurve), 'INVALID_PUBLIC_KEY')
    key.dispose()
    throwsCode(() => key.signTaproot(sighash), 'DISPOSED')
  })

  test('the engine reports both capabilities', () => {
    assert.ok(crypto.info.has('secp256k1-schnorr'))
    assert.ok(crypto.info.has('taproot-tweak'))
  })
})
