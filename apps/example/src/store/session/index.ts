import {createSelectorFunctions} from 'auto-zustand-selectors-hook'
import {create} from 'zustand'
import {immer} from 'zustand/middleware/immer'

import {appSlice, lockSlice} from './slices'
import type {SessionStore} from './types'

const sessionStore = create<SessionStore>()(
  immer((...store) => ({
    ...lockSlice(...store),
    ...appSlice(...store),
  }))
)

/** This run of the app: locked or not, the accounts while unlocked, the app's foreground state. Never persisted. */
export const useSessionStore = createSelectorFunctions(sessionStore)

/** Cover the screen: the app is in the app switcher, no system prompt of ours is up, and a wallet is open. */
export const useCovered = () =>
  useSessionStore(state => state.appState !== 'active' && state.prompting === 0 && state.status === 'unlocked')

export * from './types'
