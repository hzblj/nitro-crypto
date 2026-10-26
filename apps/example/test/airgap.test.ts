import assert from 'node:assert/strict'
import {test} from 'node:test'

import {
  CRYPTO_HDKEY,
  createMultipartDecoder,
  createMultipartEncoder,
  decodeUR,
  fromUR,
  isAirgapError,
  type UR,
} from '@hzblj/crypto-airgap'
import type {ExtendedPublicKey} from '@hzblj/nitro-crypto'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

import {
  type AccountsAt,
  accountPathOf,
  airgapsOf,
  fingerprintOf,
  PAIRING_TYPES,
  pairingRequest,
  readPairing,
  readSignRequest,
  SIGN_REQUEST_TYPES,
  signScannedRequest,
} from '../src/core/airgap'
import {createWalletAdapters, deriveAccounts, type WalletKeys} from '../src/core/chains'
import {LOOPBACK_CHAINS, runLoopback, transmit} from '../src/features/debug/airgap/loopback'
import {createAdapters} from '../src/features/debug/chains'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

/** Every part of a UR, as an animated QR shows them, read by a decoder with this allowlist. */
const scan = (ur: UR, allowedTypes: readonly string[]) => {
  const {sha256} = createTestCryptoEngine().hash
  const encoder = createMultipartEncoder(ur, {maxFragmentLength: 80, sha256})
  const decoder = createMultipartDecoder({allowedTypes, sha256})

  while (!decoder.isComplete()) {
    decoder.receivePart(encoder.nextPart().toUpperCase())
  }

  return decoder.result()
}

/** The wallet's keys as the session hands them out: extended public keys, and accounts derived on demand. */
const sessionOf = (
  keys: WalletKeys
): {extendedPublicKey: (path: string) => ExtendedPublicKey; accountsAt: AccountsAt} => ({
  accountsAt: {
    bitcoin: path => keys.deriveAccount({chain: 'bitcoin', path}),
    ethereum: path => keys.deriveAccount({chain: 'ethereum', path}),
  },
  extendedPublicKey: path => keys.extendedPublicKey(path),
})

test('a pairing code carries the account keys, and a watch-only wallet reads the same accounts back', async () => {
  const crypto = createTestCryptoEngine({adapters: createWalletAdapters()})
  const keys = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const accounts = await deriveAccounts(keys)
  const {extendedPublicKey} = sessionOf(keys)
  const code = pairingRequest(crypto, accounts, keys.fingerprint, 'nitro', extendedPublicKey)
  const paired = readPairing(crypto, scan(code, PAIRING_TYPES))

  assert.equal(paired.fingerprint, 0x73c5da0a)
  assert.equal(paired.device, 'Nitro Wallet')
  assert.deepEqual(paired.ethereum, {
    address: accounts.ethereum.address,
    fingerprint: 0x73c5da0a,
    path: accounts.ethereum.path,
  })
  assert.deepEqual(paired.solana, {
    address: accounts.solana.address,
    fingerprint: 0x73c5da0a,
    path: accounts.solana.path,
  })
  assert.ok(paired.bitcoin)
  assert.equal(crypto.chains.bitcoin.watchAccount(paired.bitcoin).address, accounts.bitcoin.address)
  assert.equal(fingerprintOf('73c5da0a'), keys.fingerprint)
  assert.equal(accountPathOf(accounts.bitcoin.path), "m/84'/1'/0'")

  // Sparrow's code and MetaMask's are a watch-only Nitro Wallet's too.
  const sparrow = readPairing(
    crypto,
    scan(pairingRequest(crypto, accounts, keys.fingerprint, 'sparrow', extendedPublicKey), PAIRING_TYPES)
  )
  assert.deepEqual(sparrow.bitcoin, paired.bitcoin)
  assert.equal(sparrow.ethereum, undefined)
  const metamask = readPairing(
    crypto,
    scan(pairingRequest(crypto, accounts, keys.fingerprint, 'metamask', extendedPublicKey), PAIRING_TYPES)
  )
  assert.deepEqual(metamask.ethereum, paired.ethereum)
  assert.equal(metamask.device, 'Nitro Wallet')
  keys.dispose()
})

test('the signer signs for any address of its accounts, as Sparrow and MetaMask ask, and refuses another wallet`s', async () => {
  const crypto = createTestCryptoEngine({adapters: createWalletAdapters()})
  const keys = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const accounts = await deriveAccounts(keys)
  const other = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase: 'other'})
  const strangers = await deriveAccounts(other)
  const airgap = airgapsOf(crypto)
  const {accountsAt, extendedPublicKey} = sessionOf(keys)

  // What MetaMask does with the account key: an address further down, and a request for it.
  const shared = fromUR(CRYPTO_HDKEY, pairingRequest(crypto, accounts, keys.fingerprint, 'metamask', extendedPublicKey))
  const account = airgap.ethereum.watchAccount(shared, undefined, 4)
  const request = {
    account,
    requestId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    transaction: {
      gas: 21_000n,
      maxFeePerGas: 2_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      nonce: 3,
      to: strangers.ethereum.address,
      value: 1_000_000_000_000_000n,
    },
  }
  const scanned = readSignRequest(
    crypto,
    scan(airgap.ethereum.encodeSignRequest(request), SIGN_REQUEST_TYPES),
    accounts,
    keys.fingerprint
  )
  assert.ok(scanned.chain === 'ethereum')
  assert.equal(scanned.request.path, "m/44'/60'/0'/0/4")

  const answer = await signScannedRequest(crypto, scanned, accounts, accountsAt)
  const response = airgap.ethereum.decodeSignResponse(answer, {request})
  assert.ok(response.kind === 'transaction')
  assert.equal(
    crypto.chains.ethereum.recoverTransactionAddress({
      signature: response.transaction.signature,
      transaction: request.transaction,
    }),
    account.address
  )

  assert.throws(
    () => readSignRequest(crypto, airgap.ethereum.encodeSignRequest(request), strangers, other.fingerprint),
    error => isAirgapError(error, 'REQUEST_MISMATCH')
  )
  keys.dispose()
  other.dispose()
})

test('a Keystone 3 Pro`s accounts pair with the watch-only wallet: its Ethereum account, and Solana`s', () => {
  const crypto = createTestCryptoEngine({adapters: createWalletAdapters()})
  // keystone-sdk-rust's crypto-multi-accounts test: an Ethereum account key and a Solana key of one Keystone.
  const paired = readPairing(
    crypto,
    decodeUR(
      'UR:CRYPTO-MULTI-ACCOUNTS/OXADCYWMCMJKCTAOLFTAADDLOTAXHDCLAXRSJEQZPETEIMAXTOBSTIJNJKVSIMPRCWFHYTSTWDLYTDNBTDHHYNDMCYJPOEUECSAAHDCXEOTEWFLFMYPLAXWPDTHPFHWNATYAFHMUDPLUAHGSNLVONLBESRGLCHFYJOPDFMHGAMTAADDYOYADLNCSDWYKCSFNYKAEYKTAADDLOEAXHDCXTIDIFEHYSFWTETHESRMYCLKEHPZORHHEJSCYCMZOVDLFPEKGEOPTKICTCHWMSNKKAMTAADDYOYADLNCSDWYKCFADYKYKAEYKAXJTGRIHKKJKJYJLJTIHCXEOCXGDJPJLAHIHEHDMEHDMDYDLEYYLLD',
      {allowedTypes: PAIRING_TYPES}
    )
  )

  assert.equal(paired.device, 'Keystone 3 Pro')
  assert.equal(paired.ethereum?.path, "m/44'/60'/0'/0/0")
  assert.equal(paired.solana?.path, "m/44'/501'/0'")
  assert.equal(paired.bitcoin, undefined)
})

test('the Debug tab`s loopback signs and checks on every chain with an air-gap package', async () => {
  const crypto = createTestCryptoEngine({adapters: createAdapters()})
  const wallet = await crypto.createEphemeralWallet({mnemonic: ABANDON})
  const account = ((chain: string, n: number) =>
    wallet.deriveAccount(
      (chain === 'solana' ? {account: n, chain} : {chain, index: n}) as Parameters<typeof wallet.deriveAccount>[0]
    )) as Parameters<typeof runLoopback>[3]

  for (const chain of LOOPBACK_CHAINS) {
    const run = await runLoopback(crypto, chain, wallet.fingerprint, account)
    assert.equal(run.chain, chain)
    assert.ok(run.request.fragments > 1, `${chain}: the request needs several parts`)
    assert.ok(run.request.read < run.request.shown, `${chain}: the camera missed some parts`)
    assert.ok(run.verified.length > 0)
  }

  assert.equal(transmit({cbor: Uint8Array.of(0x41, 0x01), type: 'bytes'}, ['bytes'], crypto.hash.sha256).fragments, 1)
  wallet.dispose()
})
