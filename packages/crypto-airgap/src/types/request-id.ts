import {fromHex, toHex} from '../bytes'
import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {readBytes, readTagged, writeTagged} from '../schema'

/**
 * A request's id: a UUID in its usual text (`9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`), lowercase. Requests carry it
 * as `#6.37(bytes .size 16)`, and a response repeats it: the first check that the response answers this request.
 */
export type RequestId = string

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** The IANA tag for a UUID. */
export const UUID_TAG = 37

const format = (bytes: Uint8Array): RequestId => {
  const text = toHex(bytes)

  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`
}

/**
 * A new random request id (UUID version 4), from `random`, a source of secure random bytes the app chooses, such as
 * the engine's `crypto.random`. No global is reached for, so tests can pass fixed bytes.
 */
export const createRequestId = (random: (length: number) => Uint8Array): RequestId => {
  const bytes = random(16).slice(0, 16)

  if (bytes.length !== 16) {
    throw new AirgapError('INVALID_ARGUMENT', 'A request id needs 16 random bytes.')
  }

  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80

  return format(bytes)
}

/** Whether `id` is a UUID in lowercase text. */
export const isRequestId = (id: unknown): id is RequestId => typeof id === 'string' && UUID.test(id)

export const writeRequestId = (id: RequestId): CborValue => {
  if (!isRequestId(id)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A request id is a UUID in lowercase text.')
  }

  return writeTagged(UUID_TAG, fromHex(id.replaceAll('-', '')))
}

/** The id in `#6.37(bytes)`. Any 16 bytes are taken as given: signers do not all set the version bits. */
export const readRequestId = (item: CborValue, what = 'A request id'): RequestId =>
  format(readBytes(readTagged(item, UUID_TAG, what), what, 16))
