import assert from 'node:assert/strict'
import {test} from 'node:test'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

import {createWalletAdapters, deriveAccounts, SEPOLIA_CHAIN_ID} from '../src/core/chains'
import {formatExact, formatUnits, formatWhen, parseUnits, shortAddress} from '../src/utils/units'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

test('the wallet derives the addresses MetaMask, BIP-84 testnet wallets and Phantom show for the same phrase', async () => {
  const crypto = createTestCryptoEngine({adapters: createWalletAdapters()})
  const keys = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const accounts = await deriveAccounts(keys)

  assert.equal(accounts.ethereum.address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94')
  assert.equal(accounts.ethereum.network.chainId, SEPOLIA_CHAIN_ID)
  // BIP-84's published test-network vector: m/84'/1'/0'/0/0.
  assert.equal(accounts.bitcoin.address, 'tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl')
  assert.equal(accounts.bitcoin.path, "m/84'/1'/0'/0/0")
  assert.equal(accounts.solana.address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk')
  assert.equal(accounts.solana.cluster, 'devnet')

  keys.dispose()
  assert.equal(crypto.liveHandles(), 0)
})

test('a generated phrase opens a wallet, and the same phrase opens the same one again', async () => {
  const crypto = createTestCryptoEngine({adapters: createWalletAdapters()})
  const phrase = crypto.mnemonic.generate(12)
  const first = await crypto.createEphemeralWallet({mnemonic: phrase})
  const second = await crypto.createEphemeralWallet({mnemonic: phrase})

  assert.equal(first.fingerprint, second.fingerprint)
  assert.equal((await deriveAccounts(first)).ethereum.address, (await deriveAccounts(second)).ethereum.address)
  first.dispose()
  second.dispose()
})

test('amounts parse from what people type and format back without losing a unit', () => {
  assert.equal(parseUnits('1.5', 18), 1_500_000_000_000_000_000n)
  assert.equal(parseUnits('0,0001', 8), 10_000n)
  assert.equal(parseUnits('.5', 9), 500_000_000n)
  assert.equal(parseUnits('12', 6), 12_000_000n)
  assert.equal(parseUnits('1.123456789', 6), undefined)
  assert.equal(parseUnits('-1', 6), undefined)
  assert.equal(parseUnits('abc', 6), undefined)
  assert.equal(parseUnits('', 6), undefined)

  assert.equal(formatUnits(1_500_000_000_000_000_000n, 18), '1.5')
  assert.equal(formatUnits(123_456_789_000n, 6), '123,456.789')
  assert.equal(formatUnits(1n, 18), '0')
  assert.equal(formatUnits(1n, 8, 8), '0.00000001')
  assert.equal(formatExact(123_456_789_000n, 6), '123456.789')
  assert.equal(parseUnits(formatExact(987_654_321n, 9), 9), 987_654_321n)
})

test('addresses shorten, times read as people say them', () => {
  assert.equal(shortAddress('0x9858EfFD232B4033E47d90003D41EC34EcaEda94'), '0x9858…da94')
  assert.equal(shortAddress('short'), 'short')

  const now = Date.parse('2026-10-26T12:00:00Z')
  assert.equal(formatWhen(undefined, now), 'Pending')
  assert.equal(formatWhen(now - 20_000, now), 'Just now')
  assert.equal(formatWhen(now - 5 * 60_000, now), '5 min ago')
  assert.equal(formatWhen(now - 3 * 3_600_000, now), '3 h ago')
  assert.equal(formatWhen(now - 30 * 3_600_000, now), 'Yesterday')
  assert.equal(formatWhen(now - 3 * 86_400_000, now), '3 days ago')
})
