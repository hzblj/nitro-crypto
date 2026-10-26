import {bytewords} from './bytewords'
import {AirgapError} from './errors'

/**
 * A Uniform Resource: a type and the CBOR of a value of that type. `Type` narrows it where one is known
 * (`UR<'crypto-psbt'>`). The bytes are the payload; the string a QR code shows is `encodeUR(ur)`.
 */
export type UR<Type extends string = string> = {readonly type: Type; readonly cbor: Uint8Array}

const TYPE = /^[a-z0-9]+(-[a-z0-9]+)*$/

/** Whether `type` is a UR type name: lowercase letters, digits, and single dashes between them. */
export const isURType = (type: string): boolean => TYPE.test(type)

/**
 * Types that carry seeds or private keys. Refused at the first part, whatever an allowlist says: an air-gapped
 * signer has no reason to send one, and a wallet that scans one has already been asked to do something unsafe.
 */
export const SECRET_UR_TYPES: readonly string[] = Object.freeze([
  'crypto-seed',
  'seed',
  'crypto-bip39',
  'bip39',
  'crypto-sskr',
  'sskr',
  'crypto-prvkeys',
  'prvkeys',
  'crypto-prvkey',
  'private-key-base',
])

export const DEFAULT_MAX_MESSAGE_BYTES = 1_000_000

export type URAllowlist = {
  /** The types to accept. Anything else is `UNSUPPORTED_UR_TYPE`; a secret type is `PRIVATE_KEY_MATERIAL`. */
  readonly allowedTypes: readonly string[]
  /** The largest payload to accept, in bytes of CBOR. 1,000,000 unless stated. */
  readonly maxMessageBytes?: number
}

export const checkAllowlist = ({allowedTypes, maxMessageBytes}: URAllowlist) => {
  if (!Array.isArray(allowedTypes) || allowedTypes.length === 0 || !allowedTypes.every(isURType)) {
    throw new AirgapError('INVALID_ARGUMENT', 'Allowed types are a non-empty list of UR type names.')
  }

  if (allowedTypes.some(type => SECRET_UR_TYPES.includes(type))) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'A type that carries seeds or private keys cannot be allowed.')
  }

  const limit = maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES

  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new AirgapError('INVALID_ARGUMENT', 'The message limit is a positive number of bytes.')
  }

  return limit
}

/** Refuses a type the allowlist does not name, a secret one before anything else. */
export const admitType = (type: string, allowedTypes: readonly string[]) => {
  if (SECRET_UR_TYPES.includes(type)) {
    throw new AirgapError('PRIVATE_KEY_MATERIAL', 'This UR carries a seed or private key, which is refused.')
  }

  if (!allowedTypes.includes(type)) {
    throw new AirgapError('UNSUPPORTED_UR_TYPE', `A ${type} UR is not one this accepts.`)
  }
}

export type ParsedUR = {
  readonly type: string
  /** For a multipart part: its number (from 1) and the number of fragments. */
  readonly sequence?: {readonly seqNum: number; readonly seqLength: number}
  /** The Bytewords body, lowercase. */
  readonly body: string
}

const SEQUENCE = /^([1-9][0-9]{0,9})-([1-9][0-9]{0,9})$/

const MAX_UINT32 = 0xffffffff

/** Splits a UR string into its type, sequence and body, in either case. Throws `INVALID_UR`. */
export const parseUR = (text: string): ParsedUR => {
  if (typeof text !== 'string') {
    throw new AirgapError('INVALID_UR', 'A UR is text.')
  }

  const lower = text.trim().toLowerCase()

  if (!lower.startsWith('ur:')) {
    throw new AirgapError('INVALID_UR', 'A UR starts with `ur:`.')
  }

  const components = lower.slice(3).split('/')
  const [type = '', ...rest] = components

  if (!isURType(type)) {
    throw new AirgapError('INVALID_UR', 'A UR type is lowercase letters, digits and dashes.')
  }

  if (rest.length === 1) {
    return {body: rest[0] ?? '', type}
  }

  if (rest.length !== 2) {
    throw new AirgapError('INVALID_UR', 'A UR is `ur:type/body`, or `ur:type/n-m/body` for a part.')
  }

  const match = SEQUENCE.exec(rest[0] ?? '')
  const seqNum = Number(match?.[1])
  const seqLength = Number(match?.[2])

  if (!match || seqNum > MAX_UINT32 || seqLength > MAX_UINT32) {
    throw new AirgapError('INVALID_UR', 'A multipart UR`s sequence is two positive numbers, `n-m`.')
  }

  return {body: rest[1] ?? '', sequence: {seqLength, seqNum}, type}
}

/** The CBOR bytes a Bytewords body of this many letters carries, before decoding it. */
export const bodyBytes = (body: string) => Math.max(0, Math.floor(body.length / 2) - 4)

/**
 * The single-part UR string of `ur`: `ur:<type>/<minimal Bytewords of the CBOR and its CRC-32>`, lowercase. A QR
 * code is smaller in uppercase (its alphanumeric mode): `encodeUR(ur).toUpperCase()`. A payload too large for one
 * code goes through `createMultipartEncoder` instead.
 */
export const encodeUR = (ur: UR): string => {
  if (!isURType(ur.type)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A UR type is lowercase letters, digits and dashes.')
  }

  if (!(ur.cbor instanceof Uint8Array) || ur.cbor.length === 0) {
    throw new AirgapError('INVALID_ARGUMENT', 'A UR carries at least one byte of CBOR.')
  }

  return `ur:${ur.type}/${bytewords.encode(ur.cbor, 'minimal')}`
}

/**
 * The UR in a single-part UR string, of a type `allowedTypes` names. The CBOR is returned as received: decode it
 * with its type (`fromUR`) or a registry. A part of a multipart UR is `INVALID_UR` here (scan it with
 * `createMultipartDecoder`); a type not allowed is `UNSUPPORTED_UR_TYPE`, a secret one `PRIVATE_KEY_MATERIAL`.
 */
export const decodeUR = (text: string, options: URAllowlist): UR => {
  const limit = checkAllowlist(options)
  const {body, sequence, type} = parseUR(text)
  admitType(type, options.allowedTypes)

  if (sequence) {
    throw new AirgapError('INVALID_UR', 'This is one part of a multipart UR: read it with a multipart decoder.')
  }

  if (bodyBytes(body) > limit) {
    throw new AirgapError('PAYLOAD_TOO_LARGE')
  }

  return Object.freeze({cbor: bytewords.decode(body, 'minimal'), type})
}
