import type {CreatePendingSlice} from '../types'

/** A broadcast that never shows up (dropped from a mempool) stops being listed after a day. */
const FORGET_AFTER_MS = 24 * 60 * 60 * 1000

export const pendingSlice: CreatePendingSlice = set => ({
  addPending: transaction =>
    set(state => {
      state.pending = [transaction, ...state.pending.filter(entry => entry.hash !== transaction.hash)]
    }),
  pending: [],
  settlePending: hashes =>
    set(state => {
      const settled = new Set(hashes)
      const now = Date.now()
      state.pending = state.pending.filter(
        entry => !settled.has(entry.hash) && now - entry.sentAt.getTime() < FORGET_AFTER_MS
      )
    }),
})
