import {createSelectorFunctions} from 'auto-zustand-selectors-hook'
import {create} from 'zustand'
import {persist} from 'zustand/middleware'
import {immer} from 'zustand/middleware/immer'

import {createCustomStorage} from '../storage'
import {pendingSlice, recordSlice, settingsSlice} from './slices'
import type {WalletStore} from './types'

export const WALLET_STORE_VERSION = 1
export const WALLET_STORE_NAME = '@wallet-store'

const walletStore = create<WalletStore>()(
  persist(
    immer((...store) => ({
      ...recordSlice(...store),
      ...settingsSlice(...store),
      ...pendingSlice(...store),
      resetWallet: () =>
        store[0](state => {
          state.record = null
          state.pending = []
          state.autoLock = 'minute'
        }),
    })),
    {
      name: WALLET_STORE_NAME,
      partialize: ({autoLock, pending, record}) => ({autoLock, pending, record}),
      storage: createCustomStorage<Pick<WalletStore, 'autoLock' | 'pending' | 'record'>>(),
      version: WALLET_STORE_VERSION,
    }
  )
)

/** The wallet that lives on this device: its record, its settings, what it sent. Persisted, encrypted. */
export const useWalletStore = createSelectorFunctions(walletStore)

export * from './types'
