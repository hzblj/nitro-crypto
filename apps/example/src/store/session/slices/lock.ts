import type {CreateLockSlice} from '../types'

export const lockSlice: CreateLockSlice = set => ({
  accounts: null,
  lockReason: 'launch',
  lost: false,
  problem: null,
  setEmpty: () =>
    set(state => {
      state.status = 'empty'
      state.accounts = null
      state.problem = null
      state.lost = false
    }),
  setLocked: (reason, problem, lost = false) =>
    set(state => {
      state.status = 'locked'
      state.lockReason = reason
      state.accounts = null
      state.problem = problem ?? null
      state.lost = lost
    }),
  setUnavailable: problem =>
    set(state => {
      state.status = 'unavailable'
      state.problem = problem
    }),
  setUnlocked: accounts =>
    set(state => {
      state.status = 'unlocked'
      // Frozen objects with the engine's keys behind them: stored as they are, never drafted.
      state.accounts = accounts as typeof state.accounts
      state.problem = null
      state.lost = false
    }),
  status: 'loading',
})
