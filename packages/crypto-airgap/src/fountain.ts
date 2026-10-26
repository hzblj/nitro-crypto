import {concatBytes, u32be} from './bytes'
import {crc32} from './crc32'
import {AirgapError} from './errors'

/**
 * The fountain code of BCR-2024-001 (multipart URs), as the reference implementation (bc-ur) computes it: the same
 * Xoshiro256** generator, alias sampler, degree distribution and shuffle, so that part N of a message is the same
 * bytes here as in every other implementation, and a decoder here reassembles their parts.
 */

/** SHA-256: the caller's, the engine's `crypto.hash.sha256`. It seeds the generator, over public data only. */
export type Sha256 = (data: Uint8Array) => Uint8Array

const MASK_64 = 0xffffffffffffffffn
const TWO_64 = 2 ** 64

const rotl = (value: bigint, shift: bigint) => ((value << shift) | (value >> (64n - shift))) & MASK_64

/** Xoshiro256**, seeded with the SHA-256 of `seed`, read as four big-endian 64-bit words. */
export const createXoshiro = (seed: Uint8Array, sha256: Sha256) => {
  const digest = sha256(seed)

  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    throw new AirgapError('INVALID_ARGUMENT', 'SHA-256 returns 32 bytes.')
  }

  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
  const state = [0, 8, 16, 24].map(offset => view.getBigUint64(offset, false))

  const next = (): bigint => {
    const [s0 = 0n, s1 = 0n, s2 = 0n, s3 = 0n] = state
    const result = (rotl((s1 * 5n) & MASK_64, 7n) * 9n) & MASK_64
    const t = (s1 << 17n) & MASK_64
    const n2 = s2 ^ s0
    const n3 = s3 ^ s1
    state[1] = s1 ^ n2
    state[0] = s0 ^ n3
    state[2] = n2 ^ t
    state[3] = rotl(n3, 45n)

    return result
  }
  // Rounds to the nearest double, then divides by a power of two: exactly what `double(next()) / (UINT64_MAX + 1.0)`
  // does in the reference.
  const nextDouble = () => Number(next()) / TWO_64
  const nextInt = (low: number, high: number) => Math.floor(nextDouble() * (high - low + 1)) + low

  return {next, nextDouble, nextInt}
}

export type Xoshiro = ReturnType<typeof createXoshiro>

/** Walker's alias method, built as the reference builds it (indexes taken from the end), so draws agree. */
export const createSampler = (weights: readonly number[]) => {
  const count = weights.length
  const sum = weights.reduce((total, weight) => total + weight, 0)
  const scaled = weights.map(weight => (weight * count) / sum)
  const probabilities = new Array<number>(count).fill(0)
  const aliases = new Array<number>(count).fill(0)
  const small: number[] = []
  const large: number[] = []

  for (let index = count - 1; index >= 0; index--) {
    ;((scaled[index] ?? 0) < 1 ? small : large).push(index)
  }

  while (small.length > 0 && large.length > 0) {
    const less = small.pop() ?? 0
    const more = large.pop() ?? 0
    probabilities[less] = scaled[less] ?? 0
    aliases[less] = more
    scaled[more] = (scaled[more] ?? 0) + (scaled[less] ?? 0) - 1
    ;((scaled[more] ?? 0) < 1 ? small : large).push(more)
  }

  for (const index of [...large, ...small]) {
    probabilities[index] = 1
  }

  return (rng: Xoshiro): number => {
    const first = rng.nextDouble()
    const second = rng.nextDouble()
    const index = Math.floor(count * first)

    return second < (probabilities[index] ?? 0) ? index : (aliases[index] ?? 0)
  }
}

/** Degree d with probability proportional to 1/d, from 1 to `seqLength`. */
export const chooseDegree = (seqLength: number, rng: Xoshiro) =>
  createSampler(Array.from({length: seqLength}, (_, index) => 1 / (index + 1)))(rng) + 1

export const shuffle = (items: readonly number[], rng: Xoshiro): number[] => {
  const remaining = [...items]
  const result: number[] = []

  while (remaining.length > 0) {
    const [item] = remaining.splice(rng.nextInt(0, remaining.length - 1), 1)
    result.push(item ?? 0)
  }

  return result
}

/**
 * The fragments part `seqNum` mixes: the first `seqLength` parts carry one fragment each, in order; every later part
 * a pseudo-random set, seeded by its number and the message's checksum.
 */
export const chooseFragments = (seqNum: number, seqLength: number, checksum: number, sha256: Sha256): number[] => {
  if (seqNum <= seqLength) {
    return [seqNum - 1]
  }

  const rng = createXoshiro(concatBytes(u32be(seqNum), u32be(checksum)), sha256)
  const degree = chooseDegree(seqLength, rng)

  return shuffle(
    Array.from({length: seqLength}, (_, index) => index),
    rng
  ).slice(0, degree)
}

/**
 * The smallest fragment length that splits `messageLength` bytes into fragments of at most `maxFragmentLength`, with
 * as few fragments as that allows.
 */
export const fragmentLengthFor = (messageLength: number, minFragmentLength: number, maxFragmentLength: number) => {
  const maxCount = Math.ceil(messageLength / minFragmentLength)
  let length = messageLength

  for (let count = 1; count <= maxCount; count++) {
    length = Math.ceil(messageLength / count)

    if (length <= maxFragmentLength) {
      break
    }
  }

  return length
}

/** One part of a fountain-coded message: what a multipart UR carries, as a five-element CBOR array. */
export type FountainPart = {
  readonly seqNum: number
  readonly seqLength: number
  readonly messageLength: number
  readonly checksum: number
  readonly data: Uint8Array
}

const xorInto = (target: Uint8Array, source: Uint8Array) => {
  for (let index = 0; index < target.length; index++) {
    target[index] = (target[index] ?? 0) ^ (source[index] ?? 0)
  }
}

export const createFountainEncoder = (
  message: Uint8Array,
  maxFragmentLength: number,
  minFragmentLength: number,
  firstSeqNum: number,
  sha256: Sha256
) => {
  const fragmentLength = fragmentLengthFor(message.length, minFragmentLength, maxFragmentLength)
  const fragments: Uint8Array[] = []

  for (let offset = 0; offset < message.length; offset += fragmentLength) {
    const fragment = new Uint8Array(fragmentLength)
    fragment.set(message.subarray(offset, offset + fragmentLength))
    fragments.push(fragment)
  }

  const checksum = crc32(message)
  let seqNum = firstSeqNum >>> 0

  const nextPart = (): FountainPart => {
    seqNum = (seqNum + 1) >>> 0
    const data = new Uint8Array(fragmentLength)

    for (const index of chooseFragments(seqNum, fragments.length, checksum, sha256)) {
      xorInto(data, fragments[index] ?? data)
    }

    return {checksum, data, messageLength: message.length, seqLength: fragments.length, seqNum}
  }

  return {
    nextPart,
    seqLength: fragments.length,
    get seqNum() {
      return seqNum
    },
    wipe: () => {
      for (const fragment of fragments) {
        fragment.fill(0)
      }
    },
  }
}

export type FountainDecoderOptions = {
  /** Seeds the choice of fragments a mixed part carries. */
  readonly sha256: Sha256
  /** The largest message to reassemble, in bytes. */
  readonly maxMessageBytes: number
  /** The most fragments a message may be split into: each mixed part costs time in proportion to their number. */
  readonly maxFragments: number
  /** Mixed parts held while they wait for the fragments that reduce them. */
  readonly maxPendingParts: number
}

type Pending = {indexes: number[]; data: Uint8Array}

const isSubset = (small: readonly number[], large: readonly number[]) => small.every(index => large.includes(index))

/**
 * Reassembles a message from parts in any order, with duplicates. Each part is checked against the first one seen
 * (length, checksum, fragment size); the message, once whole, against its CRC-32. Memory is bounded: the fragments
 * (the message's size) and at most `maxPendingParts` mixed parts.
 */
export const createFountainDecoder = (limits: FountainDecoderOptions) => {
  let expected: {seqLength: number; messageLength: number; checksum: number; fragmentLength: number} | undefined
  let fragments = new Map<number, Uint8Array>()
  let pending: Pending[] = []
  let result: Uint8Array | undefined
  let learned = false

  const reset = () => {
    for (const data of fragments.values()) {
      data.fill(0)
    }

    for (const part of pending) {
      part.data.fill(0)
    }

    result?.fill(0)
    expected = undefined
    fragments = new Map()
    pending = []
    result = undefined
  }

  const check = ({checksum, data, messageLength, seqLength, seqNum}: FountainPart) => {
    if (seqNum < 1 || seqLength < 1 || messageLength < 1 || data.length < 1) {
      throw new AirgapError('INVALID_UR', 'A multipart part has an empty message, fragment or sequence.')
    }

    if (messageLength > limits.maxMessageBytes || seqLength > limits.maxFragments) {
      throw new AirgapError('PAYLOAD_TOO_LARGE', 'The multipart message is larger than the configured limit.')
    }

    // Exactly `seqLength` fragments of this size cover the message, none of them only padding or longer than it.
    if (
      data.length > messageLength ||
      data.length * seqLength < messageLength ||
      data.length * (seqLength - 1) >= messageLength
    ) {
      throw new AirgapError('INVALID_UR', 'A multipart part`s sizes do not describe a message.')
    }

    if (!expected) {
      expected = {checksum, fragmentLength: data.length, messageLength, seqLength}

      return
    }

    if (
      expected.seqLength !== seqLength ||
      expected.messageLength !== messageLength ||
      expected.checksum !== checksum ||
      expected.fragmentLength !== data.length
    ) {
      throw new AirgapError('SESSION_MISMATCH')
    }
  }

  const finish = () => {
    if (!expected || fragments.size !== expected.seqLength) {
      return
    }

    const message = new Uint8Array(expected.seqLength * expected.fragmentLength)

    for (const [index, data] of fragments) {
      message.set(data, index * expected.fragmentLength)
    }

    const trimmed = message.slice(0, expected.messageLength)
    message.fill(0)

    if (crc32(trimmed) !== expected.checksum) {
      // Every part agreed on a checksum the fragments do not produce: corrupt or forged parts, not a misread.
      trimmed.fill(0)
      reset()
      throw new AirgapError('INVALID_UR', 'The reassembled message does not match its checksum.')
    }

    result = trimmed

    // The message is whole: the pieces it was built from are no longer needed.
    for (const data of fragments.values()) {
      data.fill(0)
    }

    for (const part of pending) {
      part.data.fill(0)
    }

    fragments = new Map()
    pending = []
  }

  /** Removes from `part` every fragment it mixes that is already known. */
  const reduceByKnown = (part: Pending) => {
    part.indexes = part.indexes.filter(index => {
      const known = fragments.get(index)

      if (known) {
        xorInto(part.data, known)
      }

      return !known
    })
  }

  /** Runs parts through the known fragments and the pending mixed parts until nothing more reduces. */
  const settle = (queue: Pending[]) => {
    while (queue.length > 0 && !result) {
      const part = queue.shift() as Pending
      reduceByKnown(part)

      if (part.indexes.length === 0) {
        part.data.fill(0)
        continue
      }

      if (part.indexes.length === 1) {
        const [index = 0] = part.indexes
        fragments.set(index, part.data)
        learned = true
        finish()

        // The new fragment may reduce pending parts to single fragments.
        queue.push(...pending.filter(other => other.indexes.includes(index)))
        pending = pending.filter(other => !other.indexes.includes(index))
        continue
      }

      if (
        pending.some(other => other.indexes.length === part.indexes.length && isSubset(other.indexes, part.indexes))
      ) {
        part.data.fill(0)
        continue
      }

      // A pending part that contains this one reduces by it; this one reduces by every pending part it contains.
      const containing = pending.filter(
        other => other.indexes.length > part.indexes.length && isSubset(part.indexes, other.indexes)
      )

      for (const other of containing) {
        xorInto(other.data, part.data)
        other.indexes = other.indexes.filter(index => !part.indexes.includes(index))
      }

      pending = pending.filter(other => !containing.includes(other))
      queue.push(...containing)

      for (const other of pending) {
        if (other.indexes.length < part.indexes.length && isSubset(other.indexes, part.indexes)) {
          xorInto(part.data, other.data)
          part.indexes = part.indexes.filter(index => !other.indexes.includes(index))
        }
      }

      if (part.indexes.length <= 1) {
        queue.push(part)
        continue
      }

      pending.push(part)
      learned = true

      // The oldest go first: they are the least likely to reduce soon.
      while (pending.length > limits.maxPendingParts) {
        pending.shift()?.data.fill(0)
      }
    }
  }

  /** Adds a part. Returns whether it taught the decoder anything; throws for a part of another message. */
  const receive = (part: FountainPart): boolean => {
    if (result) {
      return false
    }

    check(part)
    learned = false
    settle([
      {
        data: new Uint8Array(part.data),
        indexes: chooseFragments(part.seqNum, part.seqLength, part.checksum, limits.sha256),
      },
    ])

    return learned
  }

  return {
    get expectedPartCount() {
      return expected?.seqLength ?? 0
    },
    receive,
    get recoveredFragmentCount() {
      return result ? (expected?.seqLength ?? 0) : fragments.size
    },
    reset,
    get result() {
      return result
    },
  }
}
