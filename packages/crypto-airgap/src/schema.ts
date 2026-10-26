import {type CborKey, type CborMap, type CborValue, cborTag, isCborTagged} from './cbor'
import {AirgapError} from './errors'

/**
 * Readers for the fields of a registry type, each one a check: a value of the wrong kind or size is
 * `INVALID_PROTOCOL_DATA`, named by `what` and never quoted. Unknown map keys are ignored, as the registry's other
 * implementations ignore them; every key a type reads is checked.
 */

export const protocolError = (message: string) => new AirgapError('INVALID_PROTOCOL_DATA', message)

export const readMap = (item: CborValue, what: string): CborMap => {
  if (!(item instanceof Map)) {
    throw protocolError(`${what} is a CBOR map.`)
  }

  return item
}

export const readArray = (item: CborValue, what: string, maxLength = 1024): readonly CborValue[] => {
  if (!Array.isArray(item)) {
    throw protocolError(`${what} is a CBOR array.`)
  }

  if (item.length > maxLength) {
    throw new AirgapError('PAYLOAD_TOO_LARGE', `${what} has more entries than this accepts.`)
  }

  return item
}

export const readBytes = (item: CborValue, what: string, length?: number | readonly number[]): Uint8Array => {
  if (!(item instanceof Uint8Array)) {
    throw protocolError(`${what} is a byte string.`)
  }

  const lengths = typeof length === 'number' ? [length] : length

  if (lengths && !lengths.includes(item.length)) {
    throw protocolError(`${what} is ${lengths.join(' or ')} bytes.`)
  }

  return item
}

export const readText = (item: CborValue, what: string, maxLength = 1024): string => {
  if (typeof item !== 'string') {
    throw protocolError(`${what} is text.`)
  }

  if (item.length > maxLength) {
    throw protocolError(`${what} is longer than this accepts.`)
  }

  return item
}

export const readUint = (item: CborValue, what: string, max = Number.MAX_SAFE_INTEGER): number => {
  if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0 || item > max) {
    throw protocolError(`${what} is an integer from 0 to ${max}.`)
  }

  return item
}

export const readBool = (item: CborValue, what: string): boolean => {
  if (typeof item !== 'boolean') {
    throw protocolError(`${what} is true or false.`)
  }

  return item
}

/** The value inside `#6.<tag>(…)`. An untagged value, or another tag, is refused: the tag says what the value is. */
export const readTagged = (item: CborValue, tag: number, what: string): CborValue => {
  if (!isCborTagged(item) || item.tag !== tag) {
    throw protocolError(`${what} is tagged ${tag}.`)
  }

  return item.value
}

/** A required field: `undefined` (absent) is refused. */
export const required = (map: CborMap, key: CborKey, what: string): CborValue => {
  const value = map.get(key)

  if (value === undefined) {
    throw protocolError(`${what} is missing.`)
  }

  return value
}

/** An optional field through `read`, or `undefined` when absent. */
export const optional = <T>(map: CborMap, key: CborKey, read: (item: CborValue) => T): T | undefined => {
  const value = map.get(key)

  return value === undefined ? undefined : read(value)
}

/** A map from entries, leaving out those whose value is `undefined`: how optional fields are written. */
export const writeMap = (entries: readonly (readonly [CborKey, CborValue])[]): CborMap =>
  new Map(entries.filter(([, value]) => value !== undefined))

export const writeTagged = cborTag

/** `value` without its `undefined` fields, frozen: what a decoded type returns, so absent means absent. */
export const compact = <T extends object>(value: T): T =>
  Object.freeze(Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined))) as T

export const UINT32_MAX = 0xffffffff
