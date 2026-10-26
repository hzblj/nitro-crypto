import {createSelectorFunctions} from 'auto-zustand-selectors-hook'
import {create} from 'zustand'
import {immer} from 'zustand/middleware/immer'

import {signerSlice, watchSlice} from './slices'
import type {AirgapStore} from './types'

const airgapStore = create<AirgapStore>()(
  immer((...store) => ({
    ...signerSlice(...store),
    ...watchSlice(...store),
  }))
)

/**
 * Air-gapped signing in this run of the app: the request being reviewed, and the signer a watch-only session paired
 * with. Never persisted: a request is answered or dropped, and a pairing is one scan away.
 */
export const useAirgapStore = createSelectorFunctions(airgapStore)

export * from './types'
