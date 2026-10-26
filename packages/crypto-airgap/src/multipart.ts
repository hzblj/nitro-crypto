import {bytewords} from './bytewords'
import {type CborValue, decodeCbor, encodeCbor} from './cbor'
import {AirgapError} from './errors'
import {createFountainDecoder, createFountainEncoder, type FountainPart, type Sha256} from './fountain'
import {admitType, bodyBytes, checkAllowlist, encodeUR, isURType, parseUR, type UR, type URAllowlist} from './ur'

/** SHA-256, from the caller: the engine's `crypto.hash.sha256`. The fountain code seeds its generator with it. */
export type WithSha256 = {readonly sha256: Sha256}

const checkSha256 = (sha256: unknown): Sha256 => {
  if (typeof sha256 !== 'function') {
    throw new AirgapError('INVALID_ARGUMENT', 'Multipart parts need SHA-256: pass the engine`s `crypto.hash.sha256`.')
  }

  return sha256 as Sha256
}

export type MultipartEncoderOptions = WithSha256 & {
  /** The most payload bytes a part carries: 200 unless stated. Smaller parts make simpler QR codes, and more of them. */
  readonly maxFragmentLength?: number
  /** The fewest a fragment carries, when the message is split: 10 unless stated. */
  readonly minFragmentLength?: number
  /** The part number to count on from: the first part is this plus one. 0 unless stated. */
  readonly firstSeqNum?: number
}

/**
 * The parts of one message, as strings, one per call. It holds no timer and draws nothing: showing a part, and when
 * to show the next, are the app's. The first `fragmentCount` parts carry one fragment each; every part after them
 * mixes several (fountain codes), so a decoder that missed some parts catches up from any others. A message that fits
 * one part is a single-part UR, returned on every call.
 */
export type MultipartEncoder = {
  readonly type: string
  /** The fragments the message is split into: 1 when it fits a single part. */
  readonly fragmentCount: number
  readonly isSinglePart: boolean
  /** The number of the part `nextPart` returned last; 0 before the first. */
  readonly seqNum: number
  readonly nextPart: () => string
}

const DEFAULT_MAX_FRAGMENT_LENGTH = 200
const DEFAULT_MIN_FRAGMENT_LENGTH = 10

const positive = (value: number, name: string) => {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new AirgapError('INVALID_ARGUMENT', `The ${name} is a positive integer.`)
  }

  return value
}

const encodePart = (type: string, part: FountainPart) => {
  const cbor = encodeCbor([part.seqNum, part.seqLength, part.messageLength, part.checksum, part.data])

  return `ur:${type}/${part.seqNum}-${part.seqLength}/${bytewords.encode(cbor, 'minimal')}`
}

export const createMultipartEncoder = (ur: UR, options: MultipartEncoderOptions): MultipartEncoder => {
  const single = encodeUR(ur)
  const maxFragmentLength = positive(options.maxFragmentLength ?? DEFAULT_MAX_FRAGMENT_LENGTH, 'fragment length')
  const minFragmentLength = positive(options.minFragmentLength ?? DEFAULT_MIN_FRAGMENT_LENGTH, 'fragment minimum')
  const firstSeqNum = options.firstSeqNum ?? 0

  if (minFragmentLength > maxFragmentLength) {
    throw new AirgapError('INVALID_ARGUMENT', 'The fragment minimum is at most the fragment length.')
  }

  if (!Number.isInteger(firstSeqNum) || firstSeqNum < 0 || firstSeqNum > 0xffffffff) {
    throw new AirgapError('INVALID_ARGUMENT', 'The first part number is an integer from 0 to 2^32 - 1.')
  }

  const fountain = createFountainEncoder(
    new Uint8Array(ur.cbor),
    maxFragmentLength,
    minFragmentLength,
    firstSeqNum,
    checkSha256(options.sha256)
  )
  const isSinglePart = fountain.seqLength === 1

  return {
    get fragmentCount() {
      return fountain.seqLength
    },
    isSinglePart,
    nextPart: () => {
      const part = fountain.nextPart()

      return isSinglePart ? single : encodePart(ur.type, part)
    },
    get seqNum() {
      return fountain.seqNum
    },
    type: ur.type,
  }
}

export type MultipartDecoderOptions = URAllowlist &
  WithSha256 & {
    /** The most fragments a message may be split into: 2,048 unless stated. */
    readonly maxFragments?: number
    /** Parts to take before giving up on a message that does not complete: 10,000 unless stated. */
    readonly maxParts?: number
    /** Mixed parts held while they wait for the fragments that reduce them: 512 unless stated. */
    readonly maxPendingParts?: number
  }

export type MultipartProgress = {
  /** The type of the message being read, from its first part. */
  readonly type: string | undefined
  /** Fragments the message has, once a part says so. */
  readonly expectedFragmentCount: number
  /** Fragments recovered so far, directly or by reducing mixed parts. */
  readonly recoveredFragmentCount: number
  /** Parts taken, duplicates included. */
  readonly receivedPartCount: number
  /** Recovered over expected, from 0 to 1. */
  readonly fraction: number
}

/**
 * Reassembles one message from scanned strings, in any order, with duplicates. It decides nothing about when to scan:
 * the app passes each string it reads and asks whether the message is whole.
 */
export type MultipartDecoder = {
  /**
   * Takes one scanned string: a part, or a whole single-part UR. Returns whether it added anything. Throws
   * `SESSION_MISMATCH` for a part of another message (the decoder keeps what it had), `UNSUPPORTED_UR_TYPE` or
   * `PRIVATE_KEY_MATERIAL` for a type not allowed, `INVALID_UR` for a misread or corrupt part, and
   * `PAYLOAD_TOO_LARGE` past a limit.
   */
  readonly receivePart: (text: string) => boolean
  readonly isComplete: () => boolean
  /** The whole message. Throws `INVALID_ARGUMENT` before it is complete. */
  readonly result: () => UR
  readonly progress: MultipartProgress
  /** Forgets the message and overwrites what it held, to read another. */
  readonly reset: () => void
}

const DEFAULT_MAX_FRAGMENTS = 2048
const DEFAULT_MAX_PARTS = 10_000
const DEFAULT_MAX_PENDING_PARTS = 512

/** The five-element array a part's CBOR is: `[seqNum, seqLength, messageLength, checksum, fragment]`. */
const readPart = (cbor: Uint8Array): FountainPart => {
  const value: CborValue = decodeCbor(cbor, {maxDepth: 1, maxItems: 6})
  const [seqNum, seqLength, messageLength, checksum, data] = Array.isArray(value) ? value : []
  const uint32 = (item: CborValue): item is number => typeof item === 'number' && item >= 0 && item <= 0xffffffff

  if (
    !Array.isArray(value) ||
    value.length !== 5 ||
    !uint32(seqNum) ||
    !uint32(seqLength) ||
    !uint32(messageLength) ||
    !uint32(checksum) ||
    !(data instanceof Uint8Array)
  ) {
    throw new AirgapError('INVALID_UR', 'A multipart part is not the five-element array the format defines.')
  }

  return {checksum, data, messageLength, seqLength, seqNum}
}

export const createMultipartDecoder = (options: MultipartDecoderOptions): MultipartDecoder => {
  const maxMessageBytes = checkAllowlist(options)
  const allowedTypes = [...options.allowedTypes]
  const maxParts = positive(options.maxParts ?? DEFAULT_MAX_PARTS, 'part limit')
  const fountain = createFountainDecoder({
    maxFragments: positive(options.maxFragments ?? DEFAULT_MAX_FRAGMENTS, 'fragment limit'),
    maxMessageBytes,
    maxPendingParts: positive(options.maxPendingParts ?? DEFAULT_MAX_PENDING_PARTS, 'pending part limit'),
    sha256: checkSha256(options.sha256),
  })
  let type: string | undefined
  let single: Uint8Array | undefined
  let received = 0

  const reset = () => {
    fountain.reset()
    single?.fill(0)
    single = undefined
    type = undefined
    received = 0
  }

  const isComplete = () => single !== undefined || fountain.result !== undefined

  const receivePart = (text: string): boolean => {
    if (isComplete()) {
      return false
    }

    const parsed = parseUR(text)

    if (type !== undefined && parsed.type !== type) {
      throw new AirgapError('SESSION_MISMATCH', 'This part is of another type than the parts before it.')
    }

    admitType(parsed.type, allowedTypes)

    // A part's CBOR is its fragment and at most 30 bytes of numbers around it.
    if (bodyBytes(parsed.body) > maxMessageBytes + (parsed.sequence ? 32 : 0)) {
      throw new AirgapError('PAYLOAD_TOO_LARGE')
    }

    if (received >= maxParts) {
      throw new AirgapError('PAYLOAD_TOO_LARGE', 'The message did not complete within the configured number of parts.')
    }

    const cbor = bytewords.decode(parsed.body, 'minimal')

    if (!parsed.sequence) {
      if (fountain.expectedPartCount > 0) {
        throw new AirgapError('SESSION_MISMATCH', 'A whole UR arrived in the middle of a multipart message.')
      }

      received++
      type = parsed.type
      single = cbor

      return true
    }

    const part = readPart(cbor)

    if (part.seqNum !== parsed.sequence.seqNum || part.seqLength !== parsed.sequence.seqLength) {
      throw new AirgapError('INVALID_UR', 'A part`s sequence does not match the numbers in its text.')
    }

    const learned = fountain.receive(part)
    received++
    type = parsed.type

    return learned
  }

  return {
    isComplete,
    get progress(): MultipartProgress {
      const expected = single ? 1 : fountain.expectedPartCount
      const recovered = single ? 1 : fountain.recoveredFragmentCount

      return {
        expectedFragmentCount: expected,
        fraction: expected === 0 ? 0 : recovered / expected,
        receivedPartCount: received,
        recoveredFragmentCount: recovered,
        type,
      }
    },
    receivePart,
    reset,
    result: () => {
      const cbor = single ?? fountain.result

      if (!cbor || !type || !isURType(type)) {
        throw new AirgapError('INVALID_ARGUMENT', 'The message is not complete yet.')
      }

      return Object.freeze({cbor: cbor.slice(), type})
    },
  }
}
