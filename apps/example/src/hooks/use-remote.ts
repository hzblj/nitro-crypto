import {useCallback, useEffect, useRef} from 'react'

import {useCacheStore} from '../store'

/**
 * What the wallet reads from the network, through the cache store: one entry per key, shared by every screen that shows
 * it and persisted, so the wallet opens on its last balances while fresh ones load. Not a query library, on purpose.
 */

type Loader = () => Promise<unknown>

const loaders = new Map<string, Loader>()
const inflight = new Map<string, Promise<void>>()
const cache = () => useCacheStore.getState()

const load = (key: string, loader: Loader): Promise<void> => {
  const running = inflight.get(key)

  if (running) {
    return running
  }

  cache().begin(key)
  const promise = loader()
    .then(
      data => cache().resolve(key, data),
      (error: unknown) => cache().reject(key, error instanceof Error ? error.message : String(error))
    )
    .finally(() => inflight.delete(key))
  inflight.set(key, promise)

  return promise
}

/** Reloads every entry whose key starts with `prefix` that a screen has asked for: after a send, say. */
export const invalidate = (prefix = '') => {
  cache().expire(prefix)
  for (const [key, loader] of loaders) {
    if (key.startsWith(prefix)) {
      load(key, loader)
    }
  }
}

export type Remote<T> = {
  readonly data: T | undefined
  /** Why the last load failed; the data shown is then the last that loaded. */
  readonly error: string | undefined
  /** True while a load runs, including a refresh over data already shown. */
  readonly loading: boolean
  readonly refresh: () => Promise<void>
}

/**
 * `loader`'s result under `key`, loaded when nothing is stored for it or what is stored is older than `staleMs`. A
 * `null` key loads nothing: the wallet is locked, or the address is not known yet.
 */
export const useRemote = <T>(key: string | null, loader: () => Promise<T>, staleMs = 30_000): Remote<T> => {
  const entry = useCacheStore(state => (key ? state.entries[key] : undefined))
  const request = useCacheStore(state => (key ? state.requests[key] : undefined))
  const latest = useRef(loader)
  latest.current = loader

  useEffect(() => {
    if (!key) {
      return
    }

    const run = () => latest.current()
    loaders.set(key, run)
    const stored = cache().entries[key]

    if (!stored || Date.now() - stored.at > staleMs) {
      load(key, run)
    }
  }, [key, staleMs])

  const refresh = useCallback(() => (key ? load(key, () => latest.current()) : Promise.resolve()), [key])

  return {
    data: entry?.data as T | undefined,
    error: request?.error,
    loading: key !== null && (request?.loading ?? entry === undefined),
    refresh,
  }
}
