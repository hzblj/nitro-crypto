import assert from 'node:assert/strict'
import {after, describe, test} from 'node:test'

import {bytes, hex, isCryptoError, utf8} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {sha256 as nobleSha256} from '@noble/hashes/sha2.js'
import {NETWORK, p2pkh, p2sh, p2tr, p2wpkh, TaprootControlBlock, TEST_NETWORK} from '@scure/btc-signer'

import {bitcoinAdapter} from '../src'
import {decodeBase64, encodeBase64} from '../src/base64'
import {bip322MessageHash, bip322ToSign, bip322ToSpend, signMessage} from '../src/message'
import {type AccountSigner, hash256, serializeTransaction} from '../src/transaction'
import {MNEMONIC, rejectsWith, seeded, throwsWith, vectors, wifSecret} from './support'

/** BIP-322's published vectors, verbatim (bip-0322/basic-test-vectors.json and generated-test-vectors.json). */
type Simple = {
  message: string
  private_keys: string[]
  address: string
  type: string
  bip322_signatures: string[]
}
type Basic = {
  tx_hashes: {
    message: string
    address: string
    message_hash: string
    to_spend_tx_hash: string
    to_sign_tx_hash: string
  }[]
  simple: Simple[]
  error: {description: string; message: string; address: string; signature: string}[]
}
type Generated = {
  simple: Simple[]
  full: Simple[]
  proof_of_funds: Simple[]
  error: {description: string; message: string; address: string; signature: string}[]
}

const basic = vectors<Basic>('bip322-basic-test-vectors.json')
const generated = vectors<Generated>('bip322-generated-test-vectors.json')

const crypto = createTestCryptoEngine({
  adapters: [bitcoinAdapter(), bitcoinAdapter({id: 'bitcoin-testnet', network: 'testnet'})],
})
const mainnet = crypto.chains.bitcoin
const testnet = crypto.chains['bitcoin-testnet']
const sha256 = crypto.hash.sha256

/** A signer for a raw key, as an account of `type` would be. */
const signerOf = (secret: Uint8Array, type: AccountSigner['type']): AccountSigner => {
  const key = crypto.keys.importRawSecret('secp256k1', secret)
  const publicKey = key.publicKey()
  const address = mainnet.addressFromPublicKey(publicKey, type)
  const validation = mainnet.validateAddress(address)
  assert.ok(validation.valid)

  return {key, publicKey, scriptPubKey: validation.scriptPubKey, type}
}

/** True, false, or the error code it throws: what a verifier says about a vector. */
const verdict = (address: string, message: string, signature: string) => {
  try {
    return mainnet.verifyMessage({address, message, signature})
  } catch (error) {
    if (isCryptoError(error)) {
      return error.code
    }

    throw error
  }
}

describe('BIP-322 vectors', () => {
  test('message hashes, and the ids of to_spend and to_sign', () => {
    assert.equal(basic.tx_hashes.length, 3)

    for (const vector of basic.tx_hashes) {
      const validation = mainnet.validateAddress(vector.address)
      assert.ok(validation.valid)
      const messageHash = bip322MessageHash(utf8.encode(vector.message), sha256)
      assert.equal(hex.encode(messageHash), vector.message_hash)
      const toSpend = bip322ToSpend(messageHash, validation.scriptPubKey, sha256)
      assert.equal(hex.encode(toSpend.slice().reverse()), vector.to_spend_tx_hash)
      const toSign = hash256(serializeTransaction(bip322ToSign(toSpend)), sha256)
      assert.equal(hex.encode(toSign.reverse()), vector.to_sign_tx_hash)
    }
  })

  test('every simple P2WPKH and P2TR signature verifies, prefixed or not; script addresses are undecided', () => {
    let checked = 0

    for (const vector of [...basic.simple, ...generated.simple]) {
      for (const signature of vector.bip322_signatures) {
        if (vector.type === 'p2wpkh' || vector.type === 'p2tr') {
          assert.equal(verdict(vector.address, vector.message, signature), true, `${vector.type} ${vector.message}`)
          // The other spelling verifies too: with `smp`, and without it, as before BIP-322 was final.
          const other = signature.startsWith('smp') ? signature.slice(3) : `smp${signature}`
          assert.equal(verdict(vector.address, vector.message, other), true)
          assert.equal(verdict(vector.address, `${vector.message}!`, signature), false)
          checked++
        } else {
          // A P2WSH witness script needs a script interpreter: inconclusive, not false.
          assert.equal(verdict(vector.address, vector.message, signature), 'UNSUPPORTED', vector.type)
        }
      }
    }

    assert.equal(checked, 7)
  })

  test('full and proof-of-funds signatures are undecided here, never true', () => {
    for (const vector of [...generated.full, ...generated.proof_of_funds]) {
      for (const signature of vector.bip322_signatures) {
        assert.equal(verdict(vector.address, vector.message, signature), 'UNSUPPORTED', vector.type)
      }
    }
  })

  test('every error vector is false, or undecided when it is a form this does not check', () => {
    for (const vector of [...basic.error, ...generated.error]) {
      const result = verdict(vector.address, vector.message, vector.signature)
      // A P2WSH witness of the address's own script is undecided (the message is wrong, but only a script
      // interpreter can tell); a witness of another script is plainly false.
      const undecided = vector.signature.startsWith('ful') || /^wrong message .*p2wsh/.test(vector.description)
      assert.equal(result, undecided ? 'UNSUPPORTED' : false, vector.description)
    }
  })

  test('P2WPKH signatures from the vectors` keys are the deterministic (RFC 6979) ones, byte for byte', () => {
    let compared = 0

    for (const vector of [...basic.simple, ...generated.simple].filter(item => item.type === 'p2wpkh')) {
      const [wif = ''] = vector.private_keys
      const signer = signerOf(wifSecret(wif, sha256), 'p2wpkh')
      const signature = signMessage(vector.message, 'bip322', signer, sha256)
      // Each vector's last signature is RFC 6979's; Bitcoin Core's first one grinds for a low R.
      assert.equal(signature, vector.bip322_signatures.at(-1))
      assert.equal(signMessage(vector.message, 'bip322-unprefixed', signer, sha256), signature.slice(3))
      signer.key.dispose()
      compared++
    }

    assert.equal(compared, 3)
  })

  test('P2TR signatures from the vectors` keys verify, at the vectors` addresses', () => {
    for (const vector of [...basic.simple, ...generated.simple].filter(item => item.type === 'p2tr')) {
      const [wif = ''] = vector.private_keys
      const signer = signerOf(wifSecret(wif, sha256), 'p2tr')
      assert.equal(mainnet.addressFromPublicKey(signer.publicKey, 'p2tr'), vector.address)
      const signature = signMessage(vector.message, 'bip322', signer, sha256)
      // SIGHASH_DEFAULT: one item of 64 bytes.
      assert.deepEqual(decodeBase64(signature.slice(3)).subarray(0, 2), Uint8Array.of(1, 64))
      assert.equal(mainnet.verifyMessage({address: vector.address, message: vector.message, signature}), true)
      signer.key.dispose()
    }
  })
})

describe('accounts sign messages', async () => {
  const wallet = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
  const segwit = await wallet.deriveAccount({chain: 'bitcoin'})
  const taproot = await wallet.deriveAccount({addressType: 'p2tr', chain: 'bitcoin'})
  after(() => wallet.dispose())

  test('BIP-322 by default, prefixed; verified by the account and by the chain, and by nobody else', async () => {
    for (const account of [segwit, taproot]) {
      for (const message of ['', 'Hello World', utf8.encode('bytes \u0000 too'), crypto.random(300)]) {
        const signature = await account.signMessage({message})
        assert.ok(signature.startsWith('smp'))
        assert.equal(await account.verifyMessage({message, signature}), true)
        assert.equal(mainnet.verifyMessage({address: account.address, message, signature}), true)
        const unprefixed = await account.signMessage({format: 'bip322-unprefixed', message})
        assert.equal(mainnet.verifyMessage({address: account.address, message, signature: unprefixed}), true)
        assert.equal(await account.verifyMessage({message: 'another', signature}), false)
        const other = account === segwit ? taproot : segwit
        assert.equal(mainnet.verifyMessage({address: other.address, message, signature}), false)
      }
    }
  })

  test('legacy signatures for P2WPKH (BIP-137 headers 39 to 42), and none for Taproot', async () => {
    const message = 'Sign in to example.com'
    const signature = await segwit.signMessage({format: 'legacy', message})
    const decoded = decodeBase64(signature)
    assert.equal(decoded.length, 65)
    assert.ok((decoded[0] ?? 0) >= 39 && (decoded[0] ?? 0) <= 42)
    assert.equal(await segwit.verifyMessage({message, signature}), true)
    assert.equal(await segwit.verifyMessage({message: `${message}.`, signature}), false)
    await rejectsWith(taproot.signMessage({format: 'legacy', message}), 'INVALID_ARGUMENT', /Taproot/)
    await rejectsWith(segwit.signMessage({format: 'bip137' as 'legacy', message}), 'INVALID_ARGUMENT')
    await rejectsWith(segwit.signMessage({message: 5 as unknown as string}), 'INVALID_ARGUMENT')
  })

  test('verification refuses what is not an address of its network, and is false for garbage', () => {
    const signature = 'smpAA=='
    throwsWith(() => mainnet.verifyMessage({address: 'nope', message: '', signature}), 'INVALID_ADDRESS')
    throwsWith(
      () => testnet.verifyMessage({address: segwit.address, message: '', signature}),
      'INVALID_ADDRESS',
      /testnet/
    )

    for (const garbage of ['', 'smp', '!!!!', 'AAAA', `smp${encodeBase64(new Uint8Array(200))}`, 'A'.repeat(88)]) {
      assert.equal(mainnet.verifyMessage({address: segwit.address, message: '', signature: garbage}), false, garbage)
      assert.equal(mainnet.verifyMessage({address: taproot.address, message: '', signature: garbage}), false, garbage)
    }

    // A Taproot witness with an annex is not decided here.
    const annex = `smp${encodeBase64(Uint8Array.of(2, 1, 0x51, 1, 0x50))}`
    throwsWith(() => mainnet.verifyMessage({address: taproot.address, message: '', signature: annex}), 'UNSUPPORTED')
  })

  test('a Taproot script path is undecided when it commits to the address, and false when it does not', () => {
    const internalKey = taproot.publicKey.subarray(1)
    const script = bytes.concat(Uint8Array.of(0x20), internalKey, Uint8Array.of(0xac))
    const tree = p2tr(internalKey, [{script}, {script: Uint8Array.of(0x51)}], NETWORK, true)
    const [[control] = []] = tree.tapLeafScript ?? []
    assert.ok(control)
    const witness = (block: Uint8Array) =>
      `smp${encodeBase64(
        bytes.concat(
          Uint8Array.of(3, 64),
          new Uint8Array(64),
          Uint8Array.of(script.length),
          script,
          Uint8Array.of(block.length),
          block
        )
      )}`
    const block = TaprootControlBlock.encode(control)
    const address = tree.address ?? ''
    throwsWith(
      () => mainnet.verifyMessage({address, message: '', signature: witness(block)}),
      'UNSUPPORTED',
      /script path/
    )

    // The other parity, another sibling, or another address: no commitment, so plainly false.
    const flipped = block.slice()
    flipped[0] = (flipped[0] ?? 0) ^ 1
    const sibling = block.slice()
    sibling[40] = (sibling[40] ?? 0) ^ 1
    assert.equal(mainnet.verifyMessage({address, message: '', signature: witness(flipped)}), false)
    assert.equal(mainnet.verifyMessage({address, message: '', signature: witness(sibling)}), false)
    assert.equal(mainnet.verifyMessage({address: taproot.address, message: '', signature: witness(block)}), false)
    assert.equal(mainnet.verifyMessage({address, message: '', signature: witness(block.subarray(1))}), false)
  })

  test('a disposed wallet signs nothing', async () => {
    const own = await crypto.createEphemeralWallet({mnemonic: MNEMONIC})
    const account = await own.deriveAccount({addressType: 'p2tr', chain: 'bitcoin'})
    own.dispose()
    await rejectsWith(account.signMessage({message: 'hi'}), 'DISPOSED')
  })
})

describe('legacy signatures (BIP-137)', () => {
  // Bitcoin Core's test/functional/rpc_signmessagewithprivkey.py: a testnet key, its P2PKH address and signature.
  const core = {
    address: 'mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB',
    message: 'This is just a test message',
    secret: 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N',
    signature: 'INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=',
  }

  test('Bitcoin Core`s signature verifies for its P2PKH address, and the same key signs the same r and s', () => {
    assert.equal(testnet.verifyMessage({address: core.address, message: core.message, signature: core.signature}), true)
    assert.equal(testnet.verifyMessage({address: core.address, message: 'other', signature: core.signature}), false)

    const signer = signerOf(wifSecret(core.secret, sha256), 'p2wpkh')
    const ours = decodeBase64(signMessage(core.message, 'legacy', signer, sha256))
    const theirs = decodeBase64(core.signature)
    // Core writes 31 + recovery (compressed P2PKH); a P2WPKH address gets BIP-137's 39 + recovery.
    assert.equal(ours[0], (theirs[0] ?? 0) + 8)
    assert.deepEqual(ours.subarray(1), theirs.subarray(1))
    signer.key.dispose()
  })

  test('headers as Electrum reads them: 31 to 34 for any compressed address type, the others for their own', () => {
    const random = seeded(137)
    const secret = secp256k1.utils.randomSecretKey(random.bytes(48))
    const compressed = secp256k1.getPublicKey(secret, true)
    const uncompressed = secp256k1.getPublicKey(secret, false)
    const message = 'Electrum, Sparrow, Trezor'
    const digest = nobleSha256(
      nobleSha256(
        bytes.concat(
          utf8.encode('\u0018Bitcoin Signed Message:\n'),
          Uint8Array.of(message.length),
          utf8.encode(message)
        )
      )
    )
    // @noble/curves' recoverable signature: the recovery id, then r and s.
    const recovered = secp256k1.sign(digest, secret, {format: 'recovered', prehash: false})
    const signature = (base: number) =>
      encodeBase64(bytes.concat(Uint8Array.of(base + (recovered[0] ?? 0)), recovered.subarray(1)))
    const addresses = {
      p2pkh: p2pkh(compressed, NETWORK).address ?? '',
      p2pkhUncompressed: p2pkh(uncompressed, NETWORK).address ?? '',
      p2sh: p2sh(p2wpkh(compressed, NETWORK), NETWORK).address ?? '',
      p2tr: p2tr(compressed.subarray(1), undefined, NETWORK).address ?? '',
      p2wpkh: p2wpkh(compressed, NETWORK).address ?? '',
    }
    const accepts = (base: number) =>
      Object.entries(addresses)
        .filter(([, address]) => mainnet.verifyMessage({address, message, signature: signature(base)}))
        .map(([type]) => type)

    assert.deepEqual(accepts(27), ['p2pkhUncompressed'])
    assert.deepEqual(accepts(31), ['p2pkh', 'p2sh', 'p2wpkh'])
    assert.deepEqual(accepts(35), ['p2sh'])
    assert.deepEqual(accepts(39), ['p2wpkh'])
    // A header outside 27 to 42 is no legacy signature, and no witness either.
    assert.equal(mainnet.verifyMessage({address: addresses.p2wpkh, message, signature: signature(43)}), false)
  })

  test('the same signatures as @noble/curves on random keys and messages', () => {
    const random = seeded(1337)

    for (let round = 0; round < 24; round++) {
      const secret = secp256k1.utils.randomSecretKey(random.bytes(48))
      const message = round % 3 === 0 ? random.bytes(random.integer(400)) : `message ${round} ${'x'.repeat(round * 20)}`
      const data = typeof message === 'string' ? utf8.encode(message) : message
      const length =
        data.length < 0xfd ? Uint8Array.of(data.length) : Uint8Array.of(0xfd, data.length & 0xff, data.length >> 8)
      const digest = nobleSha256(
        nobleSha256(bytes.concat(utf8.encode('\u0018Bitcoin Signed Message:\n'), length, data))
      )
      const recovered = secp256k1.sign(digest, secret, {format: 'recovered', prehash: false})
      const expected = encodeBase64(bytes.concat(Uint8Array.of(39 + (recovered[0] ?? 0)), recovered.subarray(1)))

      const signer = signerOf(secret, 'p2wpkh')
      assert.equal(signMessage(message, 'legacy', signer, sha256), expected, `round ${round}`)
      const address = p2wpkh(secp256k1.getPublicKey(secret, true), NETWORK).address ?? ''
      assert.equal(mainnet.verifyMessage({address, message, signature: expected}), true)
      signer.key.dispose()
    }
  })

  test('the testnet chain reads testnet addresses', () => {
    const secret = wifSecret(core.secret, sha256)
    const signer = signerOf(secret, 'p2wpkh')
    const signature = signMessage(core.message, 'legacy', signer, sha256)
    const address = p2wpkh(signer.publicKey, TEST_NETWORK).address ?? ''
    assert.equal(testnet.verifyMessage({address, message: core.message, signature}), true)
    signer.key.dispose()
  })
})

describe('Base64', () => {
  test('round trips at every length, and refuses what is not canonical', () => {
    const random = seeded(64)

    for (let length = 0; length < 40; length++) {
      const data = random.bytes(length)
      const text = encodeBase64(data)
      assert.equal(text, Buffer.from(data).toString('base64'))
      assert.deepEqual(decodeBase64(text), data)
      assert.deepEqual(decodeBase64(text.replace(/=+$/, '')), data)
    }

    for (const text of ['A', 'AB=', 'A===', 'AB?=', 'QR==', 'QUI=x', ' QUJD', 'QUJD\n']) {
      throwsWith(() => decodeBase64(text), 'INVALID_ENCODING')
    }
  })
})
