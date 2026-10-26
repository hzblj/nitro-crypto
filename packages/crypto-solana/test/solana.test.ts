import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import {base58, isCryptoError, utf8} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {hmac} from '@noble/hashes/hmac.js'
import {sha512} from '@noble/hashes/sha2.js'
import {mnemonicToSeedSync} from '@scure/bip39'
import {
  createKeyPairFromPrivateKeyBytes,
  getAddressFromPublicKey,
  isAddress,
  type SignatureBytes,
  signBytes,
  verifySignature,
} from '@solana/kit'

import {solanaAdapter, VERSION} from '../src'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const crypto = createTestCryptoEngine({
  adapters: [solanaAdapter(), solanaAdapter({cluster: 'devnet', id: 'solana-devnet'})],
})
const solana = crypto.chains.solana

/** SLIP-0010 written out with @noble's HMAC, hardened steps only: the seed to give @solana/kit, independently. */
const slip10Seed = (seed: Uint8Array, path: readonly number[]) => {
  let node = hmac(sha512, utf8.encode('ed25519 seed'), seed)
  for (const index of path) {
    const data = new Uint8Array(37)
    data.set(node.subarray(0, 32), 1)
    new DataView(data.buffer).setUint32(33, (index | 0x80000000) >>> 0)
    node = hmac(sha512, node.subarray(32), data)
  }
  return node.subarray(0, 32)
}

describe('accounts', () => {
  test("\"abandon … about\" at m/44'/501'/0'/0' is the address Phantom and Solflare show", async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const account = await wallet.deriveAccount({chain: 'solana'})
    assert.equal(account.address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')
    assert.equal(account.path, "m/44'/501'/0'/0'")
    assert.equal(account.cluster, 'mainnet-beta')
    wallet.dispose()
  })

  test('addresses and signatures equal @solana/kit for an independently derived key, account by account', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase: 'nitro'})
    const seed = mnemonicToSeedSync(ABANDON, 'nitro')
    for (const index of [0, 1, 9, 42]) {
      const account = await wallet.deriveAccount({account: index, chain: 'solana'})
      const pair = await createKeyPairFromPrivateKeyBytes(slip10Seed(seed, [44, 501, index, 0]))
      assert.equal(account.address, await getAddressFromPublicKey(pair.publicKey))
      assert.ok(isAddress(account.address))

      for (const message of [new Uint8Array(), utf8.encode('Hello from Expo'), new Uint8Array(1000).fill(7)]) {
        const ours = await account.signMessage({message})
        assert.deepEqual(ours, new Uint8Array(await signBytes(pair.privateKey, message)))
        assert.equal(await verifySignature(pair.publicKey, ours as SignatureBytes, message), true)
      }
    }
    wallet.dispose()
  })

  test('the same key on every cluster, each account tagged with its own', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const devnet = await wallet.deriveAccount({chain: 'solana-devnet'})
    assert.equal(devnet.address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')
    assert.equal(devnet.cluster, 'devnet')
    wallet.dispose()
  })

  test('a path with a normal step is refused: SLIP-0010 Ed25519 is hardened only', async () => {
    const wallet = await crypto.createEphemeralWallet()
    await assert.rejects(
      () => wallet.deriveAccount({chain: 'solana', path: "m/44'/501'/0'/0"}),
      error => isCryptoError(error, 'INVALID_PATH')
    )
    await assert.rejects(
      () => wallet.deriveAccount({account: -1, chain: 'solana'}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })
})

describe('messages', () => {
  test('sign and verify, with bytes or Base58 signatures; changes do not verify', async () => {
    const wallet = await crypto.createEphemeralWallet()
    const account = await wallet.deriveAccount({chain: 'solana'})
    const other = await wallet.deriveAccount({account: 1, chain: 'solana'})
    const signature = await account.signMessage({message: 'Hello from Expo'})

    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature}), true)
    assert.equal(
      solana.verifyMessage({address: account.address, message: 'Hello from Expo', signature: base58.encode(signature)}),
      true
    )
    assert.equal(await account.verifyMessage({message: 'Hello from Expo!', signature}), false)
    assert.equal(await other.verifyMessage({message: 'Hello from Expo', signature}), false)
    const tampered = signature.slice()
    tampered[63] = (tampered[63] ?? 0) ^ 1
    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature: tampered}), false)
    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature: 'not base58 0OIl'}), false)
    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature: signature.subarray(1)}), false)
    wallet.dispose()
  })

  test('an off-curve address verifies nothing; a malformed one throws', () => {
    // 32 bytes whose y-coordinate is no point: an address a program could own, with no key behind it.
    const offCurve = base58.encode(new Uint8Array(32).fill(0xff).map((byte, index) => (index === 31 ? 0x7f : byte)))
    assert.equal(solana.validateAddress(offCurve).valid, true)
    assert.equal(solana.verifyMessage({address: offCurve, message: 'x', signature: new Uint8Array(64)}), false)
    assert.throws(
      () => solana.verifyMessage({address: 'nope', message: 'x', signature: new Uint8Array(64)}),
      error => isCryptoError(error, 'INVALID_ADDRESS')
    )
  })
})

describe('addresses', () => {
  test('validation: 32 bytes of canonical Base58, as @solana/kit decides', () => {
    for (const address of [
      '11111111111111111111111111111111',
      'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk',
      'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    ]) {
      assert.equal(solana.validateAddress(address).valid, true, address)
      assert.equal(isAddress(address), true)
    }
    for (const address of [
      '',
      '0x00',
      '1'.repeat(31),
      '1'.repeat(33),
      'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqkk',
    ]) {
      assert.equal(solana.validateAddress(address).valid, false, address)
      assert.equal(isAddress(address), false, address)
    }
  })

  test('agrees with @solana/kit`s isAddress on random Base58 text of every plausible length', () => {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    let state = 7
    const next = () => {
      state = (state * 1103515245 + 12345) % 2 ** 31
      return state
    }
    for (let round = 0; round < 5000; round++) {
      const length = 30 + (next() % 17)
      const text = Array.from({length}, () => alphabet[next() % 58]).join('')
      assert.equal(solana.validateAddress(text).valid, isAddress(text), text)
    }
  })
})

describe('adapter', () => {
  test('describes itself honestly, and refuses unknown clusters', () => {
    const adapter = solanaAdapter()
    assert.equal(adapter.curve, 'ed25519')
    assert.equal(adapter.features.transactionSigning, false)
    assert.equal(solanaAdapter({cluster: 'devnet'}).name, 'Solana devnet')
    assert.throws(
      () => solanaAdapter({cluster: 'localnet' as 'devnet'}),
      error => isCryptoError(error, 'INVALID_CONFIG')
    )
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8'))
    assert.equal(VERSION, manifest.version)
    assert.equal(adapter.version, manifest.version)
  })
})
