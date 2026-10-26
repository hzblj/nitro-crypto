/** A request the network refused, with the reason it gave: what the user sees when a send fails. */
export class NetworkError extends Error {
  override name = 'NetworkError'
}

const TIMEOUT_MS = 20_000

/** The host of a URL, without React Native's partial `URL`. */
const hostOf = (url: string) => url.replace(/^\w+:\/\//, '').split('/')[0] ?? url

const withTimeout = async (url: string, init: RequestInit = {}): Promise<Response> => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    return await fetch(url, {...init, signal: controller.signal})
  } catch (error) {
    throw new NetworkError(
      controller.signal.aborted ? `${hostOf(url)} did not answer in time.` : `${hostOf(url)} is unreachable.`,
      {cause: error}
    )
  } finally {
    clearTimeout(timer)
  }
}

/** The reason a refusal gives: a JSON-RPC error's message, an API's `message`, else the text itself. */
const reasonOf = (text: string): string => {
  try {
    const body = JSON.parse(text) as unknown
    const first = Array.isArray(body) ? body[0] : body
    const message = (first as {error?: {message?: string}; message?: string} | undefined)?.error?.message
    return message ?? (first as {message?: string} | undefined)?.message ?? text
  } catch {
    return text
  }
}

const failure = async (response: Response) => {
  const text = (await response.text().catch(() => '')).trim()

  return new NetworkError(text ? reasonOf(text).slice(0, 300) : `${hostOf(response.url)} answered ${response.status}.`)
}

export const getJson = async <T>(url: string): Promise<T> => {
  const response = await withTimeout(url, {headers: {accept: 'application/json'}})

  if (!response.ok) {
    throw await failure(response)
  }

  return (await response.json()) as T
}

/** POSTs a body as text, as Esplora takes a raw transaction, and returns the text answer. */
export const postText = async (url: string, body: string): Promise<string> => {
  const response = await withTimeout(url, {body, headers: {'content-type': 'text/plain'}, method: 'POST'})

  if (!response.ok) {
    throw await failure(response)
  }

  return (await response.text()).trim()
}

type RpcCall = {readonly method: string; readonly params: readonly unknown[]}
type RpcReply = {readonly id: number; readonly result?: unknown; readonly error?: {message: string; code: number}}

let nextId = 1

/** Each call's result, or the error it got: a batch where one refusal should not lose the rest. */
export type Settled = {readonly result: unknown} | {readonly error: NetworkError}

/** JSON-RPC 2.0, several calls in one round trip, each settled on its own. */
export const rpcBatchSettled = async (url: string, calls: readonly RpcCall[]): Promise<Settled[]> => {
  const first = nextId
  nextId += calls.length
  const body = calls.map((call, index) => ({id: first + index, jsonrpc: '2.0', ...call}))
  const response = await withTimeout(url, {
    body: JSON.stringify(body),
    headers: {'content-type': 'application/json'},
    method: 'POST',
  })

  if (!response.ok) {
    throw await failure(response)
  }

  const replies = (await response.json()) as RpcReply[] | RpcReply
  const byId = new Map((Array.isArray(replies) ? replies : [replies]).map(reply => [reply.id, reply]))

  return calls.map((call, index) => {
    const reply = byId.get(first + index)

    return !reply || reply.error
      ? {error: new NetworkError(reply?.error?.message ?? `${call.method} got no answer.`)}
      : {result: reply.result}
  })
}

/** JSON-RPC 2.0, several calls in one round trip; each result in the order asked, or the first error thrown. */
export const rpcBatch = async (url: string, calls: readonly RpcCall[]): Promise<unknown[]> =>
  (await rpcBatchSettled(url, calls)).map(settled => {
    if ('error' in settled) {
      throw settled.error
    }
    return settled.result
  })

export const rpc = async <T>(url: string, method: string, params: readonly unknown[] = []): Promise<T> => {
  const [result] = await rpcBatch(url, [{method, params}])

  return result as T
}
