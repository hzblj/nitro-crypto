import type {CreateSignerSlice} from '../types'

export const signerSlice: CreateSignerSlice = set => ({
  clearIncoming: () =>
    set(state => {
      state.incoming = null
    }),
  incoming: null,
  setIncoming: request =>
    set(state => {
      // Frozen by the package that read it, bytes and all: stored as it is, never drafted.
      state.incoming = request as typeof state.incoming
    }),
})
