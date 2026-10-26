import type {StateCreator} from 'zustand'

/** One answer from the network, and when it came. */
export type CacheEntry = {readonly data: unknown; readonly at: number}

/** A key's request: running, or what it failed with last. Never persisted. */
export type CacheRequest = {readonly loading: boolean; readonly error?: string}

export type EntriesSlice = {
  entries: Record<string, CacheEntry>
  requests: Record<string, CacheRequest>
  begin: (key: string) => void
  resolve: (key: string, data: unknown) => void
  reject: (key: string, error: string) => void
  /** Marks every key starting with `prefix` stale, so the next screen to show it reloads it. */
  expire: (prefix: string) => void
  clearCache: () => void
}

export type CacheStore = EntriesSlice

export type CreateEntriesSlice = StateCreator<CacheStore, [['zustand/immer', never]], [], EntriesSlice>
