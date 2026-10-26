import type {MnemonicCheck, MnemonicLength} from '@hzblj/nitro-crypto'

import {type LockReason, useCacheStore, useSessionStore, useWalletStore, type WalletRecord} from '../store'
import {deriveAccounts, type WalletKeys} from './chains'
import {walletCrypto, walletEngine} from './engine'
import {
  availableProtection,
  confirmPresence,
  erasePhrase,
  type PhraseRead,
  readPhrase,
  savePhrase,
  takeLegacyRecord,
} from './keychain'

/**
 * The wallet's life cycle, outside React: the stores hold what screens show, and these functions are the only code that
 * touches the seed. Its keys live in the engine for as long as the wallet is unlocked, behind this one reference.
 */
let keys: WalletKeys | null = null

const session = () => useSessionStore.getState()

const dispose = () => {
  keys?.dispose()
  keys = null
}

const fingerprintHex = (opened: WalletKeys) => opened.fingerprint.toString(16).padStart(8, '0')

/** Runs a system prompt (Face ID, the passcode) without the app-switcher cover taking it for leaving the app. */
const withPrompt = async <T>(run: () => Promise<T>): Promise<T> => {
  session().beginPrompt()
  try {
    return await run()
  } finally {
    session().endPrompt()
  }
}

const message = (error: unknown) => (error instanceof Error ? error.message : String(error))

/**
 * Decides where the app starts: no engine, no wallet, or a locked one. A record left in the Keychain by an older build
 * moves to the encrypted store; a phrase with no record (iOS keeps the Keychain across a reinstall) is deleted, so a
 * reinstall starts empty and only the written phrase brings the wallet back.
 */
export const initializeWallet = async () => {
  const engine = walletEngine()

  if ('error' in engine) {
    session().setUnavailable(engine.error.message)
    return
  }

  let {record} = useWalletStore.getState()

  if (!record) {
    record = await takeLegacyRecord().catch(() => null)
    if (record) {
      useWalletStore.getState().setRecord(record)
    }
  }

  if (!record) {
    await erasePhrase().catch(() => undefined)
    session().setEmpty()
    return
  }

  session().setLocked('launch')
}

const open = async (phrase: string, record: WalletRecord) => {
  const crypto = walletCrypto()

  if (!crypto) {
    return
  }

  const opened = await crypto.createEphemeralWallet({mnemonic: phrase})

  if (fingerprintHex(opened) !== record.fingerprint) {
    opened.dispose()
    session().setLocked('manual', 'The stored phrase does not belong to this wallet.')
    return
  }

  const accounts = await deriveAccounts(opened)
  dispose()
  keys = opened
  session().setUnlocked(accounts)
}

/** Reads the phrase from the Keychain (one Face ID prompt) and derives the keys in the engine again. */
export const unlockWallet = async () => {
  const {record} = useWalletStore.getState()

  if (session().status !== 'locked' || !record) {
    return
  }

  const read = await withPrompt(() => readPhrase(record, 'Unlock your wallet'))

  switch (read.status) {
    case 'ok':
      try {
        await open(read.phrase, record)
      } catch (error) {
        session().setLocked('manual', message(error))
      }
      return
    case 'lost':
      session().setLocked(
        'manual',
        `The stored recovery phrase can no longer be read (${record.method} changed since it was saved). Restore the wallet from your written phrase.`,
        true
      )
      return
    case 'failed':
      session().setLocked('manual', read.message)
      return
    case 'cancelled':
      return
  }
}

/** Zeroizes the seed and every key in the engine; the stored phrase stays. */
export const lockWallet = (reason: LockReason = 'manual') => {
  dispose()

  if (session().status === 'unlocked') {
    session().setLocked(reason)
  }
}

/** Stores `phrase` behind the device's strongest protection, and opens the wallet. */
export const createWallet = async (phrase: string, origin: WalletRecord['origin']) => {
  const crypto = walletCrypto()

  if (!crypto) {
    throw new Error('The native engine is not available.')
  }

  const {method, protection} = await availableProtection()
  const created = await crypto.createEphemeralWallet({mnemonic: phrase})
  const record: WalletRecord = {
    createdAt: new Date(),
    fingerprint: fingerprintHex(created),
    method,
    origin,
    protection,
    words: created.words,
  }

  try {
    await withPrompt(() => savePhrase(phrase, protection))
    const accounts = await deriveAccounts(created)
    dispose()
    keys = created
    useCacheStore.getState().clearCache()
    useWalletStore.getState().resetWallet()
    useWalletStore.getState().setRecord(record)
    session().setUnlocked(accounts)
  } catch (error) {
    created.dispose()
    throw error
  }
}

/** Deletes the phrase from the Keychain and everything the stores know about the wallet. */
export const removeWallet = async () => {
  await erasePhrase()
  dispose()
  useCacheStore.getState().clearCache()
  useWalletStore.getState().resetWallet()
  session().setEmpty()
}

export const revealPhrase = async (): Promise<PhraseRead> => {
  const {record} = useWalletStore.getState()

  if (session().status !== 'unlocked' || !record) {
    return {status: 'cancelled'}
  }

  return withPrompt(() => readPhrase(record, 'Show your recovery phrase'))
}

/** Asks for Face ID (or the passcode) before something that moves funds or signs. */
export const confirmWithUser = async (reason: string): Promise<boolean> => {
  const {record} = useWalletStore.getState()

  if (session().status !== 'unlocked' || !record) {
    return false
  }

  return withPrompt(() => confirmPresence(record, reason))
}

/** A fresh recovery phrase from the engine's CSPRNG. Nothing is stored until `createWallet`. */
export const generatePhrase = (words: MnemonicLength = 12): string => {
  const crypto = walletCrypto()

  if (!crypto) {
    throw new Error('The native engine is not available.')
  }

  return crypto.mnemonic.generate(words)
}

export const checkPhrase = (phrase: string): MnemonicCheck =>
  walletCrypto()?.mnemonic.validate(phrase) ?? {reason: 'INVALID_MNEMONIC', valid: false, words: 0}
