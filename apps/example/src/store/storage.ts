import {createMMKV} from 'react-native-mmkv'
import {createJSONStorage, type PersistStorage} from 'zustand/middleware'

import {replacer, reviver} from './serialize'
import {storageKey} from './storage-key'

/** The stores' file: AES-256 with a per-device key from the Keychain, one process, this app only. */
export const storage = createMMKV({
  encryptionKey: storageKey(),
  encryptionType: 'AES-256',
  id: 'nitro-wallet',
  mode: 'single-process',
})

/** Zustand's JSON storage over the encrypted MMKV: synchronous, so a store is hydrated before its first render. */
export const createCustomStorage = <S>(): PersistStorage<S> | undefined =>
  createJSONStorage(
    () => ({
      getItem: (name: string) => storage.getString(name) ?? null,
      removeItem: (name: string) => {
        storage.remove(name)
      },
      setItem: (name: string, value: string) => storage.set(name, value),
    }),
    {replacer, reviver}
  )
