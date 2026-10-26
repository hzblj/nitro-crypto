import {createSelectorFunctions} from 'auto-zustand-selectors-hook'
import {create} from 'zustand'
import {persist} from 'zustand/middleware'
import {immer} from 'zustand/middleware/immer'

import {createCustomStorage} from '../storage'
import {entriesSlice} from './slices'
import type {CacheStore} from './types'

export const CACHE_STORE_VERSION = 1
export const CACHE_STORE_NAME = '@cache-store'

const cacheStore = create<CacheStore>()(
  persist(
    immer((...store) => ({
      ...entriesSlice(...store),
    })),
    {
      name: CACHE_STORE_NAME,
      // The answers survive a restart, so the wallet opens on its last balances; requests in flight do not.
      partialize: ({entries}) => ({entries}),
      storage: createCustomStorage<Pick<CacheStore, 'entries'>>(),
      version: CACHE_STORE_VERSION,
    }
  )
)

/** What the networks last said: balances, histories, prices. Public data, persisted encrypted all the same. */
export const useCacheStore = createSelectorFunctions(cacheStore)

export * from './types'
