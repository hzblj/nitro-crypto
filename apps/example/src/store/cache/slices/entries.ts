import type {CreateEntriesSlice} from '../types'

export const entriesSlice: CreateEntriesSlice = set => ({
  begin: key =>
    set(state => {
      state.requests[key] = {loading: true}
    }),
  clearCache: () =>
    set(state => {
      state.entries = {}
      state.requests = {}
    }),
  entries: {},
  expire: prefix =>
    set(state => {
      for (const [key, entry] of Object.entries(state.entries)) {
        if (key.startsWith(prefix)) {
          state.entries[key] = {...entry, at: 0}
        }
      }
    }),
  reject: (key, error) =>
    set(state => {
      state.requests[key] = {error, loading: false}
    }),
  requests: {},
  resolve: (key, data) =>
    set(state => {
      // Balances and histories are replaced whole: drafting them would only copy what is thrown away.
      state.entries[key] = {at: Date.now(), data: data as never}
      state.requests[key] = {loading: false}
    }),
})
