import {AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY, getItem, setItem} from 'expo-secure-store'

import {walletCrypto} from '../core/engine'

const KEY = 'nitro-wallet.storage-key'
const OPTIONS = {keychainAccessible: AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY}
/** 24 bytes are 32 characters of Base64: MMKV's longest AES-256 key, and 192 bits of the engine's randomness. */
const KEY_BYTES = 24

/**
 * The MMKV encryption key: drawn once from the engine's CSPRNG and kept in the Keychain (Keystore on Android), never on
 * this device's disk in the clear and never in the bundle. Losing it makes the stores unreadable, so a failure throws
 * instead of opening an empty store.
 */
export const storageKey = (): string => {
  const stored = getItem(KEY, OPTIONS)

  if (stored) {
    return stored
  }

  const crypto = walletCrypto()

  if (!crypto) {
    throw new Error('The native engine is unavailable, so the encrypted store cannot get its key.')
  }

  const key = btoa(String.fromCharCode(...crypto.random(KEY_BYTES)))
  setItem(KEY, key, OPTIONS)

  return key
}
