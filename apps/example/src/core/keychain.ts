import {
  AuthenticationType,
  authenticateAsync,
  getEnrolledLevelAsync,
  hasHardwareAsync,
  isEnrolledAsync,
  SecurityLevel,
  supportedAuthenticationTypesAsync,
} from 'expo-local-authentication'
import {
  canUseBiometricAuthentication,
  deleteItemAsync,
  getItemAsync,
  type SecureStoreOptions,
  setItemAsync,
  WHEN_UNLOCKED_THIS_DEVICE_ONLY,
} from 'expo-secure-store'
import {Platform} from 'react-native'

import type {Protection, WalletRecord} from '../store'

const PHRASE_KEY = 'nitro-wallet.phrase'
/** Where the record lived before the encrypted store: read once, moved, deleted. */
const LEGACY_RECORD_KEY = 'nitro-wallet.record'
/** Never in a backup, never on another device, only while the device is unlocked. */
const BASE: SecureStoreOptions = {keychainAccessible: WHEN_UNLOCKED_THIS_DEVICE_ONLY}

const phraseOptions = (protection: Protection, prompt?: string): SecureStoreOptions =>
  protection === 'biometrics' ? {...BASE, authenticationPrompt: prompt, requireAuthentication: true} : BASE

/** The strongest protection this device offers right now, and its name. */
export const availableProtection = async (): Promise<{protection: Protection; method: string}> => {
  const [hardware, enrolled, level, types] = await Promise.all([
    hasHardwareAsync(),
    isEnrolledAsync(),
    getEnrolledLevelAsync(),
    supportedAuthenticationTypesAsync(),
  ])

  if (hardware && enrolled && canUseBiometricAuthentication()) {
    const face = types.includes(AuthenticationType.FACIAL_RECOGNITION)
    const method = Platform.OS === 'ios' ? (face ? 'Face ID' : 'Touch ID') : 'Biometrics'

    return {method, protection: 'biometrics'}
  }

  return level >= SecurityLevel.SECRET
    ? {method: 'Passcode', protection: 'passcode'}
    : {method: 'None', protection: 'none'}
}

/**
 * Asks the person in front of the device, the way the record says: the system prompt for biometrics or the passcode,
 * and a pass on a device that has neither. `false` when they cancel.
 */
export const confirmPresence = async (record: Pick<WalletRecord, 'protection'>, reason: string): Promise<boolean> => {
  if (record.protection === 'none') {
    return true
  }

  const result = await authenticateAsync({
    cancelLabel: 'Cancel',
    disableDeviceFallback: false,
    promptMessage: reason,
  })

  return result.success
}

/** A record from a build that kept it in the Keychain, moved out on first launch of this one. */
export const takeLegacyRecord = async (): Promise<WalletRecord | null> => {
  const text = await getItemAsync(LEGACY_RECORD_KEY, BASE)

  if (!text) {
    return null
  }

  await deleteItemAsync(LEGACY_RECORD_KEY, BASE)
  const legacy = JSON.parse(text) as Omit<WalletRecord, 'createdAt'> & {createdAt: string; version: number}

  return {...legacy, createdAt: new Date(legacy.createdAt)}
}

/** Stores the phrase under the protection the record names. The record goes to the encrypted store. */
export const savePhrase = (phrase: string, protection: Protection): Promise<void> =>
  setItemAsync(PHRASE_KEY, phrase, phraseOptions(protection, 'Save your wallet'))

export type PhraseRead =
  | {readonly status: 'ok'; readonly phrase: string}
  | {readonly status: 'cancelled'}
  /** The system refused this time (too many attempts, a locked Keychain): try again later. */
  | {readonly status: 'failed'; readonly message: string}
  /** The item is gone: Face ID was re-enrolled, which invalidates biometric items by design. */
  | {readonly status: 'lost'}

/** The recovery phrase, after the person proves they are there. Each read is one prompt. */
export const readPhrase = async (record: Pick<WalletRecord, 'protection'>, reason: string): Promise<PhraseRead> => {
  if (record.protection !== 'biometrics' && !(await confirmPresence(record, reason))) {
    return {status: 'cancelled'}
  }

  try {
    const phrase = await getItemAsync(PHRASE_KEY, phraseOptions(record.protection, reason))

    return phrase ? {phrase, status: 'ok'} : {status: 'lost'}
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)

    return /cancel/i.test(message) ? {status: 'cancelled'} : {message, status: 'failed'}
  }
}

/** Deletes the phrase, and a record an older build left beside it. */
export const erasePhrase = async (): Promise<void> => {
  await deleteItemAsync(LEGACY_RECORD_KEY, BASE)
  await deleteItemAsync(PHRASE_KEY, BASE)
}
