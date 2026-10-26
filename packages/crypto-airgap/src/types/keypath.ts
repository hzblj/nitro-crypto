import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {defineURType} from '../registry'
import {
  compact,
  optional,
  protocolError,
  readArray,
  readBool,
  readMap,
  readUint,
  required,
  UINT32_MAX,
  writeMap,
} from '../schema'

/** One step of a derivation path: an index, a range of them, or any index (`*`), hardened or not. */
export type KeypathComponent =
  | {readonly index: number; readonly hardened: boolean}
  | {readonly range: readonly [low: number, high: number]; readonly hardened: boolean}
  | {readonly wildcard: true; readonly hardened: boolean}

/** A derivation path and the key it starts from (BCR-2020-007, `crypto-keypath`, tag 304). */
export type Keypath = {
  readonly components: readonly KeypathComponent[]
  /** The fingerprint of the key the path starts from: the master key's for a full path. */
  readonly sourceFingerprint?: number
  /** How many derivations deep the key is, when the components do not say (a path given only in part). */
  readonly depth?: number
}

const MAX_INDEX = 0x7fffffff

/** BIP-32 depth is one byte. */
const MAX_COMPONENTS = 255

const checkIndex = (index: number) => {
  if (!Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
    throw new AirgapError('INVALID_ARGUMENT', 'A path index is an integer from 0 to 2^31 - 1.')
  }

  return index
}

const checkFingerprint = (fingerprint: number | undefined) => {
  if (fingerprint !== undefined && (!Number.isInteger(fingerprint) || fingerprint < 1 || fingerprint > UINT32_MAX)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A fingerprint is a 32-bit integer other than 0.')
  }

  return fingerprint
}

const toCbor = (keypath: Keypath): CborValue => {
  if (keypath.components.length > MAX_COMPONENTS) {
    throw new AirgapError('INVALID_ARGUMENT', 'A path has at most 255 steps.')
  }

  const components = keypath.components.flatMap(component => {
    const step: CborValue =
      'index' in component
        ? checkIndex(component.index)
        : 'range' in component
          ? [checkIndex(component.range[0]), checkIndex(component.range[1])]
          : []

    return [step, component.hardened === true]
  })

  if (keypath.depth !== undefined && (!Number.isInteger(keypath.depth) || keypath.depth < 0 || keypath.depth > 255)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A depth is an integer from 0 to 255.')
  }

  return writeMap([
    [1, components],
    [2, checkFingerprint(keypath.sourceFingerprint)],
    [3, keypath.depth],
  ])
}

const readComponent = (step: CborValue, hardened: boolean): KeypathComponent => {
  if (typeof step === 'number') {
    return {hardened, index: readUint(step, 'A path index', MAX_INDEX)}
  }

  const range = readArray(step, 'A path step', 2)

  if (range.length === 0) {
    return {hardened, wildcard: true}
  }

  if (range.length !== 2) {
    throw protocolError('A path range is two indexes.')
  }

  const low = readUint(range[0], 'A path range', MAX_INDEX)
  const high = readUint(range[1], 'A path range', MAX_INDEX)

  if (low >= high) {
    throw protocolError('A path range runs from a lower index to a higher one.')
  }

  return {hardened, range: [low, high]}
}

const fromCbor = (item: CborValue): Keypath => {
  const map = readMap(item, 'A keypath')
  const flat = readArray(required(map, 1, 'A keypath`s components'), 'A keypath`s components', MAX_COMPONENTS * 2)

  if (flat.length % 2 !== 0) {
    throw protocolError('A keypath`s components come in pairs: a step and whether it is hardened.')
  }

  const components = Array.from({length: flat.length / 2}, (_, index) =>
    Object.freeze(
      readComponent(flat[index * 2] ?? null, readBool(flat[index * 2 + 1] ?? null, 'A path step`s hardened flag'))
    )
  )
  // Zero is not a fingerprint (the schema says so); an encoder that writes one anyway means "not given".
  const fingerprint = optional(map, 2, value => readUint(value, 'A source fingerprint', UINT32_MAX))

  return compact({
    components: Object.freeze(components),
    depth: optional(map, 3, value => readUint(value, 'A keypath`s depth', 255)),
    sourceFingerprint: fingerprint === 0 ? undefined : fingerprint,
  })
}

/** `crypto-keypath`: a derivation path, and the fingerprint of the key it starts from. */
export const CRYPTO_KEYPATH = defineURType({fromCbor, tag: 304, toCbor, type: 'crypto-keypath'})

const STEP = /^(\d+|\*)(['hH]?)$/

/**
 * A path as BIP-32 writes it (`m/84'/1'/0'`, with `'` or `h` for hardened, `*` for any index), with the fingerprint
 * of the key it starts from. Throws `INVALID_ARGUMENT` for anything else.
 */
export const parseKeypath = (path: string, sourceFingerprint?: number): Keypath => {
  const [root, ...steps] = path.trim().split('/')

  if (root !== 'm' && root !== 'M') {
    throw new AirgapError('INVALID_ARGUMENT', 'A path starts with `m`.')
  }

  const components = steps.map((step): KeypathComponent => {
    const match = STEP.exec(step)

    if (!match) {
      throw new AirgapError('INVALID_ARGUMENT', "A path step is an index, or `*`, with `'` when hardened.")
    }

    const hardened = match[2] !== ''

    return match[1] === '*' ? {hardened, wildcard: true} : {hardened, index: checkIndex(Number(match[1]))}
  })

  return compact({components, sourceFingerprint: checkFingerprint(sourceFingerprint)})
}

/** The path as BIP-32 writes it: `m/84'/1'/0'`, ranges as `<1;2>`, any index as `*`. */
export const formatKeypath = (keypath: Keypath): string =>
  [
    'm',
    ...keypath.components.map(component => {
      const step =
        'index' in component ? String(component.index) : 'range' in component ? `<${component.range.join(';')}>` : '*'

      return component.hardened ? `${step}'` : step
    }),
  ].join('/')
