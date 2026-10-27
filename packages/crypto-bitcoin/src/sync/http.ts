import {SyncError} from './errors'

/** What every backend call takes: an `AbortSignal`, which ends the call (and any wait between retries) at once. */
export type RequestOptions = {readonly signal?: AbortSignal}

export type HttpOptions = {
  /** Milliseconds one attempt may take, the body included. 15 seconds unless stated. */
  readonly timeoutMs?: number
  /** Attempts after the first, for a timeout, a lost connection, a 429 or a 5xx. 3 unless stated. */
  readonly retries?: number
  /** The first wait before a retry, doubled each time (with jitter, at most 30 seconds). 500 ms unless stated. */
  readonly retryDelayMs?: number
  /** Requests in flight at once, across every call of this backend. 4 unless stated. */
  readonly concurrency?: number
  /** Sent with every request: an API key for a hosted service, say. */
  readonly headers?: Readonly<Record<string, string>>
  /** `fetch`, unless stated: React Native's, Node's or a test's. */
  readonly fetch?: typeof fetch
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

/** At most `concurrency` tasks at once; the rest wait their turn, first come first served. */
export const createLimiter = (concurrency: number) => {
  let active = 0
  const queue: (() => void)[] = []

  const release = () => {
    active--
    queue.shift()?.()
  }

  return async <T>(task: () => Promise<T>): Promise<T> => {
    if (active >= concurrency) {
      await new Promise<void>(resolve => queue.push(resolve))
    }

    active++

    try {
      return await task()
    } finally {
      release()
    }
  }
}

const aborted = () => new SyncError('ABORTED')

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

type Attempt = {readonly retry: true; readonly error: SyncError; readonly wait?: number} | {readonly retry: false}

const RETRY_STATUSES = new Set([429, 500, 502, 503, 504])

/**
 * `fetch` with what a wallet's sync needs: a timeout per attempt, the caller's `AbortSignal`, retries with exponential
 * backoff (and `Retry-After`) for what may pass (a timeout, a lost connection, 429, 5xx), at most `concurrency`
 * requests at once, and every failure a `SyncError`. URLs are built by hand: React Native's `URL` is partial.
 */
export const createHttpClient = (base: string, options: HttpOptions = {}): HttpClient => {
  const root = base.replace(/\/+$/, '')
  const timeoutMs = options.timeoutMs ?? 15_000
  const retries = options.retries ?? 3
  const retryDelayMs = options.retryDelayMs ?? 500
  const concurrency = options.concurrency ?? 4
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

  const limit = createLimiter(concurrency)
  const fetcher: typeof fetch = options.fetch ?? ((...args) => globalThis.fetch(...args))

  /** One attempt: the body as text, `undefined` for an allowed 404, or what to do about the failure. */
  const attempt = async (
    request: Request,
    signal: AbortSignal | undefined
  ): Promise<{readonly body: string | undefined} | Attempt> => {
    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, timeoutMs)
    const onAbort = () => controller.abort()
    signal?.addEventListener('abort', onAbort, {once: true})

    try {
      const response = await fetcher(`${root}${request.path}`, {
        body: request.body,
        headers: {
          ...headers,
          ...(request.body === undefined ? {} : {'content-type': 'text/plain'}),
        },
        method: request.method ?? 'GET',
        signal: controller.signal,
      })
      const text = await response.text()

      if (response.ok) {
        return {body: text}
      }

      if (response.status === 404 && request.notFound) {
        return {body: undefined}
      }

      const reason = reasonOf(text.trim()).slice(0, 300)

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
      if (error instanceof SyncError) {
        throw error
      }

      if (signal?.aborted) {
        throw aborted()
      }

      return timedOut
        ? {error: new SyncError('TIMEOUT', `The backend did not answer within ${timeoutMs} ms.`), retry: true}
        : {error: new SyncError('NETWORK_ERROR', undefined, {cause: error}), retry: true}
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
  }

  const text = (request: Request, {signal}: RequestOptions = {}) =>
    limit(async () => {
      for (let tries = 0; ; tries++) {
        if (signal?.aborted) {
          throw aborted()
        }

        const result = await attempt(request, signal)

        if ('body' in result) {
          return result.body
        }

        if (!result.retry || tries >= retries) {
          throw result.retry ? result.error : new SyncError('BACKEND_ERROR')
        }

        const backoff = retryDelayMs * 2 ** tries * (0.5 + Math.random() / 2)
        await delay(Math.min(MAX_DELAY_MS, Math.max(backoff, result.wait ?? 0)), signal)
      }
    })

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
