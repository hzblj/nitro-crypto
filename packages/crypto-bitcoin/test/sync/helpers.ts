import assert from 'node:assert/strict'

import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'
import {HDKey} from '@scure/bip32'
import {mnemonicToSeedSync} from '@scure/bip39'
import {p2wpkh, TEST_NETWORK} from '@scure/btc-signer'

import {bitcoinAdapter} from '../../src'
import {
  type BitcoinSyncOptions,
  createBitcoinSync,
  esploraBackend,
  isSyncError,
  type SyncErrorCode,
} from '../../src/sync'
import {createFakeEsplora} from './fake-esplora'

export const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

export const ACCOUNT_PATH = "m/84'/1'/0'"

export const crypto = createTestCryptoEngine({adapters: [bitcoinAdapter({network: 'testnet'})]})
export const chain = crypto.chains.bitcoin

/** The same account, by an independent implementation: @scure/bip32 for the keys, btc-signer for the addresses. */
export const reference = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC))
export const referenceAccount = reference.derive(ACCOUNT_PATH)

export const referenceKey = (change: 0 | 1, index: number) => referenceAccount.deriveChild(change).deriveChild(index)

export const referenceAddress = (change: 0 | 1, index: number) =>
  p2wpkh(referenceKey(change, index).publicKey ?? new Uint8Array(), TEST_NETWORK).address ?? ''

export const openWallet = () => crypto.createEphemeralWallet({mnemonic: MNEMONIC})

export const URL = 'https://esplora.test/api'

type Setup = {
  readonly recommended?: boolean
  readonly sync?: Partial<BitcoinSyncOptions>
}

/** A fake Esplora, a backend over it, and a sync of the test account (or of what `sync` says). */
export const setup = async ({recommended, sync = {}}: Setup = {}) => {
  const wallet = await openWallet()
  const esplora = createFakeEsplora({recommended})
  const backend = esploraBackend({fetch: esplora.fetch, network: 'testnet', retryDelayMs: 1, url: URL})
  const options = {
    backend,
    chain,
    ...('account' in sync || 'address' in sync
      ? {}
      : {extendedKey: wallet.extendedPublicKey(ACCOUNT_PATH), fingerprint: wallet.fingerprint}),
    ...sync,
  } as BitcoinSyncOptions

  return {backend, esplora, sync: createBitcoinSync(options), wallet}
}

export const throwsSync = (run: () => unknown, code: SyncErrorCode, message?: RegExp) =>
  assert.throws(run, error => isSyncError(error, code) && (!message || message.test(error.message)))

export const rejectsSync = (promise: Promise<unknown>, code: SyncErrorCode, message?: RegExp) =>
  assert.rejects(promise, error => isSyncError(error, code) && (!message || message.test(error.message)))

/** The requests that read an address's history, by address. */
export const historyReads = (requests: readonly string[]) =>
  requests.filter(request => /\/address\/[a-z0-9]+\/txs/.test(request)).map(request => request.split('/')[2])
