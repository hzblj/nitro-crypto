import {SyncError} from './errors'

/** What every backend call takes: an `AbortSignal`, which ends the call (and any wait between retries) at once. */
export type RequestOptions = {readonly signal?: AbortSignal}

/** What a request asks of a `SyncFetch`: always a method, headers and a signal; a body for a broadcast. */
export type SyncRequestInit = {
  readonly method: 'GET' | 'POST'
  /** Every request's (`headers` from the options), and `content-type: text/plain` with a body. */
  readonly headers: Readonly<Record<string, string>>
  /** The transaction's hex, on `POST /tx`; absent otherwise. */
  readonly body?: string
  /**
   * Fires on the caller's abort and on the timeout. Forward it to the HTTP client, so the request is really cancelled:
   * the sync stops waiting either way, but a request that keeps running holds its place among `concurrency` until it
   * settles.
   */
  readonly signal: AbortSignal
}

/** The part of a response the backend reads: its status, one header (`retry-after`) and its body as text. */
export type SyncResponse = {
  readonly ok: boolean
  readonly status: number
  readonly headers: {readonly get: (name: string) => string | null}
  /** The whole body, read once. */
  readonly text: () => Promise<string>
}

/**
 * The HTTP client a backend sends its requests through: the global `fetch`, `react-native-nitro-fetch`'s `fetch`, or a
 * function of your own over any client (axios, a native module, a proxy that adds authentication), as long as it
 * resolves to what `SyncResponse` lists. Resolve for every status (a 404 or a 503 is an answer); reject only when there
 * is no answer at all (no connection, a reset, the signal). It is called with a full URL (the backend's `url` and the
 * path) and a `SyncRequestInit`; forward its `signal`.
 *
 * ```ts
 * const viaAxios: SyncFetch = async (url, {body, headers, method, signal}) => {
 *   const answer = await axios.request({data: body, headers, method, signal, url, validateStatus: () => true})
 *   return {
 *     headers: {get: name => answer.headers[name.toLowerCase()] ?? null},
 *     ok: answer.status >= 200 && answer.status < 300,
 *     status: answer.status,
 *     text: async () => (typeof answer.data === 'string' ? answer.data : JSON.stringify(answer.data)),
 *   }
 * }
 * ```
 */
export type SyncFetch = (url: string, init: SyncRequestInit) => Promise<SyncResponse>

export type HttpOptions = {
  /** Milliseconds one attempt may take, from its start to its whole body. 15 seconds unless stated. */
  readonly timeoutMs?: number
  /** Attempts after the first, for a timeout, a lost connection, a 429 or a 5xx. 3 unless stated. */
  readonly retries?: number
  /** The first wait before a retry, doubled each time (with jitter, at most 30 seconds). 500 ms unless stated. */
  readonly retryDelayMs?: number
  /**
   * Requests in flight at once, across every call of this backend. A request counts until the HTTP client settles it,
   * even after the sync stopped waiting for it (a fetcher that ignores the signal). 4 unless stated.
   */
  readonly concurrency?: number
  /**
   * Request starts per second, sustained, across every call of this backend (retries included): what keeps a long
   * first sync from looking like abuse to a public server. Unlimited unless stated (`esploraBackend` states it).
   */
  readonly requestsPerSecond?: number
  /** Requests that may start at once after a quiet spell, before `requestsPerSecond` spaces the rest. 1 unless stated. */
  readonly burst?: number
  /**
   * Connection failures in a row (no answer at all: refused, timed out, no route) after which the backend is taken
   * for unreachable: every request fails at once with `UNREACHABLE`, none goes out, for `unreachablePauseMs`. 5 unless
   * stated.
   */
  readonly unreachableAfter?: number
  /**
   * How long an unreachable backend is left alone before one request tries it again: 30 seconds unless stated,
   * doubled after each failed try, up to 10 minutes. A server that has blocked this IP address is not asked again
   * every few seconds.
   */
  readonly unreachablePauseMs?: number
  /** Sent with every request: an API key for a hosted service, say. */
  readonly headers?: Readonly<Record<string, string>>
  /**
   * The HTTP client (see `SyncFetch`): `react-native-nitro-fetch`'s `fetch`, or your own. The global `fetch` unless
   * stated, looked up when a request goes out.
   */
  readonly fetch?: SyncFetch
}

type Request = {
  readonly path: string
  readonly method?: 'GET' | 'POST'
  readonly body?: string
  /** A 404 is an answer (`undefined`), not an error. */
  readonly notFound?: boolean
  /** A 4xx is the node refusing a transaction: `BROADCAST_REJECTED` with its reason. */
  readonly broadcast?: boolean
}

export type HttpClient = {
  readonly text: (request: Request, options?: RequestOptions) => Promise<string | undefined>
  readonly json: (request: Request, options?: RequestOptions) => Promise<unknown>
}

const MAX_DELAY_MS = 30_000
const MAX_PAUSE_MS = 600_000

const aborted = () => new SyncError('ABORTED')

/**
 * At most `concurrency` slots taken at once; the rest wait their turn, first come first served. `acquire` resolves
 * to the slot's release, which frees it once (later calls do nothing); a waiter whose signal fires leaves the queue.
 */
export const createLimiter = (concurrency: number) => {
  let active = 0
  const queue: (() => void)[] = []

  const grant = (): (() => void) => {
    active++
    let released = false

    return () => {
      if (!released) {
        released = true
        active--
        queue.shift()?.()
      }
    }
  }

  const acquire = (signal?: AbortSignal): Promise<() => void> =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(aborted())
        return
      }

      if (active < concurrency) {
        resolve(grant())
        return
      }

      const onAbort = () => {
        const index = queue.indexOf(waiter)

        if (index >= 0) {
          queue.splice(index, 1)
        }

        reject(aborted())
      }
      const waiter = () => {
        signal?.removeEventListener('abort', onAbort)
        resolve(grant())
      }

      queue.push(waiter)
      signal?.addEventListener('abort', onAbort, {once: true})
    })

  /** Runs `task` in a slot, released when it settles. */
  const run = async <T>(task: () => Promise<T>, signal?: AbortSignal): Promise<T> => {
    const release = await acquire(signal)

    try {
      return await task()
    } finally {
      release()
    }
  }

  return {acquire, active: () => active, run}
}

/** Waits `ms`, or rejects with `ABORTED` as soon as `signal` fires. */
export const delay = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(aborted())
      return
    }

    const onAbort = () => {
      clearTimeout(timer)
      reject(aborted())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)

    signal?.addEventListener('abort', onAbort, {once: true})
  })

/** `promise`, or a rejection with `ABORTED` as soon as `signal` fires, whichever comes first. */
const untilAborted = <T>(promise: Promise<T>, signal: AbortSignal) =>
  new Promise<T>((resolve, reject) => {
    if (signal.aborted) {
      reject(aborted())
      return
    }

    const onAbort = () => reject(aborted())
    signal.addEventListener('abort', onAbort, {once: true})
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      error => {
        signal.removeEventListener('abort', onAbort)
        reject(error)
      }
    )
  })

/**
 * Request starts spaced to `rate` per second, `burst` of them at once after a quiet spell: a token bucket, written as
 * the generic cell rate algorithm so that waiting callers keep their order (each reserves its slot when it asks).
 */
export const createPacer = (rate: number, burst: number) => {
  if (rate === Number.POSITIVE_INFINITY) {
    // Unpaced: nothing to wait for.
    return (_signal?: AbortSignal) => Promise.resolve()
  }

  const interval = 1000 / rate
  const tolerance = (burst - 1) * interval
  // The theoretical arrival time of the next request, had every one before it come exactly on schedule.
  let next = 0

  return async (signal?: AbortSignal) => {
    const now = Date.now()
    const start = Math.max(now, next - tolerance)
    next = Math.max(next, now) + interval

    if (start > now) {
      await delay(start - now, signal)
    }
  }
}

/** The seconds or HTTP date of a `Retry-After` header, in milliseconds from now. */
const retryAfter = (header: string | null): number | undefined => {
  if (!header) {
    return undefined
  }

  const seconds = Number(header)

  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds * 1000
  }

  const date = Date.parse(header)

  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : undefined
}

/** The reason in a refusal: a node's JSON-RPC `message` (as mempool.space wraps it), an API's `message`, or the text. */
export const reasonOf = (text: string): string => {
  const json = text.indexOf('{')
  const candidates = json >= 0 ? [text.slice(json), text] : [text]

  for (const candidate of candidates) {
    try {
      const body = JSON.parse(candidate) as {message?: unknown; error?: {message?: unknown}}
      const message = body?.error?.message ?? body?.message

      if (typeof message === 'string' && message.length > 0) {
        return message
      }
    } catch {
      // Not JSON: the text is the reason.
    }
  }

  return text
}

type Attempt = {
  readonly retry: true
  readonly error: SyncError
  readonly wait?: number
  /** No answer at all: the connection was refused, dropped or timed out. */
  readonly connection?: boolean
}

const RETRY_STATUSES = new Set([429, 500, 502, 503, 504])

/**
 * An HTTP client with what a wallet's sync needs, over any `SyncFetch`: a timeout per attempt, the caller's
 * `AbortSignal`, retries with exponential backoff (and `Retry-After`) for what may pass (a timeout, a lost
 * connection, 429, 5xx), at most `concurrency` requests in flight, at most `requestsPerSecond` starting, a pause once
 * the server cannot be reached at all, and every failure a `SyncError`. URLs are built by hand: React Native's `URL` is
 * partial.
 */
export const createHttpClient = (base: string, options: HttpOptions = {}): HttpClient => {
  const root = base.replace(/\/+$/, '')
  const timeoutMs = options.timeoutMs ?? 15_000
  const retries = options.retries ?? 3
  const retryDelayMs = options.retryDelayMs ?? 500
  const concurrency = options.concurrency ?? 4
  const requestsPerSecond = options.requestsPerSecond ?? Number.POSITIVE_INFINITY
  const burst = options.burst ?? 1
  const unreachableAfter = options.unreachableAfter ?? 5
  const unreachablePauseMs = options.unreachablePauseMs ?? 30_000
  const headers = options.headers ?? {}

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new SyncError('INVALID_ARGUMENT', 'A timeout is a positive number of milliseconds.')
  }

  if (!Number.isInteger(retries) || retries < 0 || retries > 10) {
    throw new SyncError('INVALID_ARGUMENT', 'Retries are an integer from 0 to 10.')
  }

  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    throw new SyncError('INVALID_ARGUMENT', 'Concurrency is an integer from 1 to 64.')
  }

  if (typeof requestsPerSecond !== 'number' || !(requestsPerSecond > 0)) {
    throw new SyncError('INVALID_ARGUMENT', 'Requests per second are more than 0 (Infinity for no pacing).')
  }

  if (!Number.isInteger(burst) || burst < 1 || burst > 1000) {
    throw new SyncError('INVALID_ARGUMENT', 'A burst is an integer from 1 to 1000.')
  }

  if (!Number.isInteger(unreachableAfter) || unreachableAfter < 1) {
    throw new SyncError('INVALID_ARGUMENT', 'Failures before a pause are a positive integer.')
  }

  if (!Number.isFinite(unreachablePauseMs) || unreachablePauseMs < 0) {
    throw new SyncError('INVALID_ARGUMENT', 'A pause is a number of milliseconds.')
  }

  if (options.fetch !== undefined && typeof options.fetch !== 'function') {
    throw new SyncError('INVALID_ARGUMENT', 'A fetch is a function.')
  }

  const limiter = createLimiter(concurrency)
  const pace = createPacer(requestsPerSecond, burst)
  // Looked up per request, not at creation: an app may install its fetch after creating the backend.
  const fetcher: SyncFetch = options.fetch ?? ((url, init) => globalThis.fetch(url, init))
  // Connection failures in a row, across every request, and when the next request may try the server again.
  let failures = 0
  let pausedUntil = 0
  let pause = unreachablePauseMs

  const unreachable = (cause?: unknown) =>
    new SyncError(
      'UNREACHABLE',
      `The backend could not be reached ${unreachableAfter} times in a row (no network, or a server refusing this address): it is tried again in ${Math.ceil(Math.max(0, pausedUntil - Date.now()) / 1000)} s.`,
      {cause}
    )

  /**
   * One attempt: a slot among `concurrency`, its turn under the pace, then the request under the timeout. The sync
   * stops waiting at the timeout or the caller's abort whatever the HTTP client does; the slot is freed only when the
   * client settles the request, so a client that ignores the signal still never has more than `concurrency` running.
   */
  const attempt = async (
    request: Request,
    signal: AbortSignal | undefined
  ): Promise<{readonly body: string | undefined} | Attempt> => {
    const release = await limiter.acquire(signal)
    let settled: Promise<unknown> | undefined

    try {
      await pace(signal)
    } catch (error) {
      release()
      throw error
    }

    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, timeoutMs)
    const onAbort = () => controller.abort()
    signal?.addEventListener('abort', onAbort, {once: true})

    try {
      const exchange = (async () => {
        const response = await fetcher(`${root}${request.path}`, {
          ...(request.body === undefined ? {} : {body: request.body}),
          headers: request.body === undefined ? {...headers} : {...headers, 'content-type': 'text/plain'},
          method: request.method ?? 'GET',
          signal: controller.signal,
        })

        return {response, text: await response.text()}
      })()
      settled = exchange.then(release, release)
      const {response, text} = await untilAborted(exchange, controller.signal)

      if (response.ok) {
        return {body: text}
      }

      if (response.status === 404 && request.notFound) {
        return {body: undefined}
      }

      const reason = reasonOf(String(text).trim()).slice(0, 300)

      if (RETRY_STATUSES.has(response.status)) {
        const code = response.status === 429 ? 'RATE_LIMITED' : 'BACKEND_ERROR'

        return {
          error: new SyncError(code, `The backend answered ${response.status}${reason ? `: ${reason}` : '.'}`),
          retry: true,
          wait: retryAfter(response.headers.get('retry-after')),
        }
      }

      throw request.broadcast && response.status >= 400 && response.status < 500
        ? new SyncError('BROADCAST_REJECTED', reason || `The node refused the transaction (${response.status}).`)
        : new SyncError('BACKEND_ERROR', `The backend answered ${response.status}${reason ? `: ${reason}` : '.'}`)
    } catch (error) {
      if (signal?.aborted) {
        throw aborted()
      }

      if (timedOut) {
        return {
          connection: true,
          error: new SyncError('TIMEOUT', `The backend did not answer within ${timeoutMs} ms.`),
          retry: true,
        }
      }

      if (error instanceof SyncError) {
        throw error
      }

      return {connection: true, error: new SyncError('NETWORK_ERROR', undefined, {cause: error}), retry: true}
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)

      if (!settled) {
        release()
      }
    }
  }

  /** Any answer from the server, even an error status, proves it reachable. */
  const reached = () => {
    failures = 0
    pause = unreachablePauseMs
  }

  const text = async (request: Request, {signal}: RequestOptions = {}) => {
    for (let tries = 0; ; tries++) {
      if (signal?.aborted) {
        throw aborted()
      }

      if (Date.now() < pausedUntil) {
        throw unreachable()
      }

      let result: Awaited<ReturnType<typeof attempt>>

      try {
        result = await attempt(request, signal)
      } catch (error) {
        if (error instanceof SyncError && error.code !== 'ABORTED') {
          reached()
        }

        throw error
      }

      if (!('body' in result) && result.retry && result.connection) {
        failures++

        if (failures >= unreachableAfter) {
          pausedUntil = Date.now() + pause
          pause = Math.min(MAX_PAUSE_MS, pause * 2)

          throw unreachable(result.error)
        }
      } else {
        reached()
      }

      if ('body' in result) {
        return result.body
      }

      if (!result.retry || tries >= retries) {
        throw result.retry ? result.error : new SyncError('BACKEND_ERROR')
      }

      const backoff = retryDelayMs * 2 ** tries * (0.5 + Math.random() / 2)
      await delay(Math.min(MAX_DELAY_MS, Math.max(backoff, result.wait ?? 0)), signal)
    }
  }

  const json = async (request: Request, options?: RequestOptions) => {
    const body = await text(request, options)

    if (body === undefined) {
      return undefined
    }

    try {
      return JSON.parse(body) as unknown
    } catch (error) {
      throw new SyncError('INVALID_RESPONSE', 'The backend answered something that is not JSON.', {cause: error})
    }
  }

  return Object.freeze({json, text})
}
