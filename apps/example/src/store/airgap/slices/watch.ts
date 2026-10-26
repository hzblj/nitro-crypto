import type {CreateWatchSlice} from '../types'

export const watchSlice: CreateWatchSlice = set => ({
  paired: null,
  setPaired: signer =>
    set(state => {
      state.paired = signer as typeof state.paired
    }),
  unpair: () =>
    set(state => {
      state.paired = null
    }),
})
