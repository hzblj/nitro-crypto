import assert from 'node:assert/strict'
import {readdirSync, readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import {isCryptoError} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {getAddress, hashMessage, recoverMessageAddress, verifyMessage} from 'viem'
import {mnemonicToAccount} from 'viem/accounts'

import {ethereumAdapter, type Hex, VERSION} from '../src'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const HARDHAT = 'test test test test test test test test test test test junk'

const crypto = createTestCryptoEngine({
  adapters: [ethereumAdapter(), ethereumAdapter({chainId: 8453, id: 'base', name: 'Base'})],
})
const ethereum = crypto.chains.ethereum

const throwsCode = (run: () => unknown, code: string) =>
  assert.throws(run, error => isCryptoError(error) && error.code === code, code)

describe('accounts', () => {
  test('published addresses: "abandon … about" and the Hardhat development mnemonic', async () => {
    const abandon = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    assert.equal(
      (await abandon.deriveAccount({chain: 'ethereum'})).address,
      '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'
    )
    abandon.dispose()

    const hardhat = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const first = await hardhat.deriveAccount({chain: 'ethereum', index: 0})
    const second = await hardhat.deriveAccount({chain: 'ethereum', index: 1})
    assert.equal(first.address, '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
    assert.equal(second.address, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8')
    assert.equal(first.path, "m/44'/60'/0'/0/0")
    hardhat.dispose()
  })

  test('addresses, public keys and personal_sign signatures equal viem, account by account', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    for (const [account, index] of [
      [0, 0],
      [0, 5],
      [2, 1],
      [7, 19],
    ] as const) {
      const ours = await wallet.deriveAccount({account, chain: 'ethereum', index})
      const theirs = mnemonicToAccount(HARDHAT, {accountIndex: account, addressIndex: index})
      assert.equal(ours.address, theirs.address)
      assert.equal(ours.publicKey, theirs.publicKey)
      for (const message of ['Hello from Expo', '', 'ñandú 日本 😀', new Uint8Array([0, 1, 2, 255])]) {
        const viemMessage = typeof message === 'string' ? message : {raw: message}
        assert.equal(await ours.signMessage({message}), await theirs.signMessage({message: viemMessage}))
      }
    }
    wallet.dispose()
  })

  test('an explicit path, such as Ledger Live`s, derives the same key as viem', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const ledger = await wallet.deriveAccount({chain: 'ethereum', path: "m/44'/60'/3'/0/0"})
    assert.equal(ledger.address, mnemonicToAccount(ABANDON, {path: "m/44'/60'/3'/0/0"}).address)
    wallet.dispose()
  })

  test('out-of-range indexes are refused', async () => {
    const wallet = await crypto.createEphemeralWallet()
    await assert.rejects(
      () => wallet.deriveAccount({chain: 'ethereum', index: -1}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    await assert.rejects(
      () => wallet.deriveAccount({account: 2 ** 31, chain: 'ethereum'}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    await assert.rejects(
      () => wallet.deriveAccount({account: 0.5, chain: 'ethereum'}),
      error => isCryptoError(error, 'INVALID_ARGUMENT')
    )
    wallet.dispose()
  })

  test('one key, several EVM networks: the same address, each with its chain id', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
    const mainnet = await wallet.deriveAccount({chain: 'ethereum'})
    const base = await wallet.deriveAccount({chain: 'base'})
    assert.equal(base.address, mainnet.address)
    assert.deepEqual(mainnet.network, {chainId: 1, name: 'Ethereum'})
    assert.deepEqual(base.network, {chainId: 8453, name: 'Base'})
    assert.equal(base.chain, 'base')
    wallet.dispose()
  })
})

describe('messages', () => {
  test('the EIP-191 digest equals viem`s', () => {
    for (const message of ['', 'hello world', 'ñandú', 'x'.repeat(1000)]) {
      assert.equal(`0x${Buffer.from(ethereum.hashMessage(message)).toString('hex')}`, hashMessage(message))
    }
  })

  test('our signatures verify in viem, and viem`s recover here', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'ethereum'})
    const signature = await account.signMessage({message: 'Hello from Expo'})
    assert.equal(await verifyMessage({address: account.address, message: 'Hello from Expo', signature}), true)
    assert.equal(await recoverMessageAddress({message: 'Hello from Expo', signature}), account.address)

    const viemSignature = await mnemonicToAccount(HARDHAT).signMessage({message: 'from viem'})
    assert.equal(ethereum.recoverMessageAddress({message: 'from viem', signature: viemSignature}), account.address)
    assert.equal(await account.verifyMessage({message: 'from viem', signature: viemSignature}), true)
    wallet.dispose()
  })

  test('a changed message, a changed signature or another signer does not verify', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'ethereum'})
    const other = await wallet.deriveAccount({chain: 'ethereum', index: 1})
    const signature = await account.signMessage({message: 'Hello from Expo'})

    assert.equal(await account.verifyMessage({message: 'Hello from Expo!', signature}), false)
    assert.equal(await other.verifyMessage({message: 'Hello from Expo', signature}), false)
    const flipped = `${signature.slice(0, 10)}${signature[10] === '0' ? '1' : '0'}${signature.slice(11)}` as Hex
    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature: flipped}), false)
    assert.equal(await account.verifyMessage({message: 'Hello from Expo', signature: '0x1234'}), false)
    assert.equal(ethereum.recoverMessageAddress({message: 'x', signature: `0x${'00'.repeat(65)}`}), undefined)
    wallet.dispose()
  })

  test('v may be 27/28 or 0/1; anything else does not verify', async () => {
    const wallet = await crypto.createEphemeralWallet({mnemonic: HARDHAT})
    const account = await wallet.deriveAccount({chain: 'ethereum'})
    const signature = await account.signMessage({message: 'm'})
    const v = Number.parseInt(signature.slice(-2), 16)
    const zeroBased = `${signature.slice(0, -2)}${(v - 27).toString(16).padStart(2, '0')}` as Hex
    assert.equal(ethereum.verifyMessage({address: account.address, message: 'm', signature: zeroBased}), true)
    assert.equal(
      ethereum.verifyMessage({address: account.address, message: 'm', signature: `${signature.slice(0, -2)}1d` as Hex}),
      false
    )
    wallet.dispose()
  })

  test('signing with a disposed wallet`s account throws DISPOSED', async () => {
    const wallet = await crypto.createEphemeralWallet()
    const account = await wallet.deriveAccount({chain: 'ethereum'})
    wallet.dispose()
    await assert.rejects(
      () => account.signMessage({message: 'x'}),
      error => isCryptoError(error, 'DISPOSED')
    )
  })
})

describe('addresses', () => {
  // EIP-55's own examples: all caps, all lower, and mixed case.
  const EIP55 = [
    '0x52908400098527886E0F7030069857D2E4169EE7',
    '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
    '0xde709f2102306220921060314715629080e2fb77',
    '0x27b1fdb04752bbc536007a920d24acb045561c26',
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]

  test('EIP-55 checksums equal the spec`s and viem`s', () => {
    for (const address of EIP55) {
      assert.equal(ethereum.checksumAddress(address.toLowerCase()), getAddress(address))
    }
    for (const address of EIP55.slice(4)) {
      assert.equal(ethereum.checksumAddress(address.toLowerCase()), address)
    }
  })

  test('validation: uniform case has no checksum, mixed case must be EIP-55', () => {
    assert.deepEqual(ethereum.validateAddress(EIP55[4] ?? ''), {checksum: 'valid', normalized: EIP55[4], valid: true})
    assert.deepEqual(ethereum.validateAddress((EIP55[4] ?? '').toLowerCase()), {
      checksum: 'absent',
      normalized: EIP55[4],
      valid: true,
    })
    const typo = (EIP55[4] ?? '').replace('aAeb', 'aaeb')
    assert.equal(ethereum.validateAddress(typo).valid, false)
    for (const bad of [
      '',
      '0x',
      '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe',
      '0xZZ',
    ]) {
      assert.equal(ethereum.validateAddress(bad).valid, false, bad)
    }
    throwsCode(() => ethereum.checksumAddress(typo), 'INVALID_ADDRESS')
    throwsCode(() => ethereum.verifyMessage({address: '0x12', message: 'x', signature: '0x00'}), 'INVALID_ADDRESS')
  })
})

describe('adapter', () => {
  test('describes itself: capabilities, formats, features, and the package version', () => {
    const adapter = ethereumAdapter()
    assert.equal(adapter.id, 'ethereum')
    assert.equal(adapter.curve, 'secp256k1')
    assert.deepEqual(adapter.formats, {
      address: ['eip55'],
      signature: ['eip191', 'eip712', 'eip155', 'eip2930', 'eip1559', 'eip7702'],
    })
    assert.deepEqual(adapter.features, {
      accessLists: true,
      blobTransactions: false,
      contractCreation: true,
      hashSigning: false,
      legacyTransactions: true,
      messageSigning: true,
      setCodeTransactions: true,
      transactionSigning: true,
      typedData: true,
    })
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8'))
    assert.equal(adapter.version, manifest.version)
    assert.equal(VERSION, manifest.version)
  })

  test('the main entry never imports viem: only the /viem subpath does', () => {
    const sources = path.join(import.meta.dirname, '../src')
    for (const file of readdirSync(sources)) {
      const text = readFileSync(path.join(sources, file), 'utf8')
      const importsViem = /from '(viem|viem\/[^']*)'/.test(text)
      assert.equal(importsViem, file === 'viem.ts', file)
      if (file !== 'viem.ts') {
        assert.doesNotMatch(text, /from '\.\/viem'/, file)
      }
    }
  })

  test('invalid configurations are refused', () => {
    throwsCode(() => ethereumAdapter({chainId: 0}), 'INVALID_CONFIG')
    throwsCode(() => ethereumAdapter({chainId: 1.5}), 'INVALID_CONFIG')
    throwsCode(() => ethereumAdapter({name: ' '}), 'INVALID_CONFIG')
  })
})
