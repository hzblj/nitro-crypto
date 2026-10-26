import {
  AirgapError,
  type CborValue,
  CRYPTO_ECKEY,
  CRYPTO_HDKEY,
  compact,
  defineURType,
  type ECKey,
  type HDKey,
  isCborTagged,
  protocolError,
  readArray,
  readBytes,
  readMap,
  readUint,
  required,
  UINT32_MAX,
  writeMap,
  writeTagged,
} from '@hzblj/crypto-airgap'

const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff]

const isPsbt = (data: Uint8Array) => PSBT_MAGIC.every((byte, index) => data[index] === byte)

/**
 * `crypto-psbt` (BCR-2020-006, tag 310): a PSBT's bytes, both ways. A watch-only wallet sends the unsigned PSBT and
 * the signer returns it signed, in the same type: which is why the answer is checked against the question
 * (`bitcoinAirgap(chain).decodeSignResponse`), never trusted for arriving.
 */
export const CRYPTO_PSBT = defineURType({
  fromCbor: (item: CborValue): Uint8Array => {
    const psbt = readBytes(item, 'A PSBT')

    if (!isPsbt(psbt)) {
      throw protocolError('A PSBT starts with the bytes "psbt" and 0xff.')
    }

    return psbt
  },
  tag: 310,
  toCbor: (psbt: Uint8Array): CborValue => {
    if (!(psbt instanceof Uint8Array) || !isPsbt(psbt)) {
      throw new AirgapError('INVALID_ARGUMENT', 'A PSBT starts with the bytes "psbt" and 0xff.')
    }

    return psbt
  },
  type: 'crypto-psbt',
})

/** The script expressions of BCR-2020-010, outermost first in a descriptor: `sh(wpkh(…))` is `['sh', 'wpkh']`. */
export type ScriptExpression =
  | 'sh'
  | 'wsh'
  | 'pk'
  | 'pkh'
  | 'wpkh'
  | 'combo'
  | 'multi'
  | 'sortedmulti'
  | 'tr'
  | 'cosigner'

const SCRIPT_TAGS: Readonly<Record<ScriptExpression, number>> = Object.freeze({
  combo: 405,
  cosigner: 410,
  multi: 406,
  pk: 402,
  pkh: 403,
  sh: 400,
  sortedmulti: 407,
  tr: 409,
  wpkh: 404,
  wsh: 401,
})

const SCRIPTS_BY_TAG = new Map(Object.entries(SCRIPT_TAGS).map(([name, tag]) => [tag, name as ScriptExpression]))

/** A key in a descriptor: an HD key (with its origin, and its chain code when it is extended) or a single EC key. */
export type DescriptorKey = {readonly hdkey: HDKey} | {readonly eckey: ECKey}

/**
 * An output descriptor (BCR-2020-010, `crypto-output`, tag 308): the scripts, outermost first, around one key, or
 * around a threshold of keys for `multi` and `sortedmulti`. Raw scripts and addresses (`raw`, `addr`) are not read.
 */
export type OutputDescriptor = {
  readonly scripts: readonly ScriptExpression[]
  readonly keys: readonly DescriptorKey[]
  /** For `multi` and `sortedmulti`: how many of `keys` must sign. */
  readonly threshold?: number
}

const MAX_SCRIPTS = 4
const MAX_MULTI_KEYS = 20

const writeKey = (key: DescriptorKey): CborValue =>
  'hdkey' in key ? writeTagged(303, CRYPTO_HDKEY.toCbor(key.hdkey)) : writeTagged(306, CRYPTO_ECKEY.toCbor(key.eckey))

const readKey = (item: CborValue): DescriptorKey => {
  if (isCborTagged(item) && item.tag === 303) {
    return {hdkey: CRYPTO_HDKEY.fromCbor(item.value)}
  }

  if (isCborTagged(item) && item.tag === 306) {
    return {eckey: CRYPTO_ECKEY.fromCbor(item.value)}
  }

  throw protocolError('A descriptor key is a tagged HD key (303) or EC key (306).')
}

const isMulti = (script: ScriptExpression | undefined) => script === 'multi' || script === 'sortedmulti'

const outputToCbor = (descriptor: OutputDescriptor): CborValue => {
  const {keys, scripts, threshold} = descriptor
  const innermost = scripts[scripts.length - 1]

  if (scripts.length === 0 || scripts.length > MAX_SCRIPTS || !scripts.every(script => script in SCRIPT_TAGS)) {
    throw new AirgapError('INVALID_ARGUMENT', 'A descriptor has from one to four script expressions.')
  }

  if (scripts.slice(0, -1).some(isMulti)) {
    throw new AirgapError('INVALID_ARGUMENT', 'Only the innermost script expression can be a multisig.')
  }

  let item: CborValue

  if (isMulti(innermost)) {
    if (
      threshold === undefined ||
      !Number.isInteger(threshold) ||
      threshold < 1 ||
      threshold > keys.length ||
      keys.length > MAX_MULTI_KEYS
    ) {
      throw new AirgapError('INVALID_ARGUMENT', 'A multisig needs a threshold from 1 to its number of keys.')
    }

    item = writeMap([
      [1, threshold],
      [2, keys.map(writeKey)],
    ])
  } else {
    const [key] = keys

    if (!key || keys.length !== 1 || threshold !== undefined) {
      throw new AirgapError('INVALID_ARGUMENT', 'A single-key descriptor has one key and no threshold.')
    }

    item = writeKey(key)
  }

  return [...scripts].reverse().reduce((inner, script) => writeTagged(SCRIPT_TAGS[script], inner), item)
}

const outputFromCbor = (item: CborValue): OutputDescriptor => {
  const scripts: ScriptExpression[] = []
  let current = item

  while (isCborTagged(current) && SCRIPTS_BY_TAG.has(current.tag)) {
    if (scripts.length === MAX_SCRIPTS) {
      throw protocolError('A descriptor nests more script expressions than this reads.')
    }

    scripts.push(SCRIPTS_BY_TAG.get(current.tag) as ScriptExpression)
    current = current.value
  }

  if (scripts.length === 0) {
    throw protocolError('A descriptor starts with a script expression this reads (raw scripts and addresses are not).')
  }

  if (!isMulti(scripts[scripts.length - 1])) {
    if (scripts.some(isMulti)) {
      throw protocolError('Only the innermost script expression can be a multisig.')
    }

    return compact({keys: Object.freeze([readKey(current)]), scripts: Object.freeze(scripts)})
  }

  const map = readMap(current, 'A multisig')
  const keys = readArray(required(map, 2, 'A multisig`s keys'), 'A multisig`s keys', MAX_MULTI_KEYS).map(readKey)
  const threshold = readUint(required(map, 1, 'A multisig`s threshold'), 'A multisig`s threshold', MAX_MULTI_KEYS)

  if (threshold < 1 || threshold > keys.length) {
    throw protocolError('A multisig`s threshold runs from 1 to its number of keys.')
  }

  return Object.freeze({keys: Object.freeze(keys), scripts: Object.freeze(scripts), threshold})
}

/** `crypto-output`: one output descriptor. */
export const CRYPTO_OUTPUT = defineURType({
  fromCbor: outputFromCbor,
  tag: 308,
  toCbor: outputToCbor,
  type: 'crypto-output',
})

/** The descriptors of one account of one wallet (BCR-2020-015, `crypto-account`, tag 311). */
export type BitcoinAirgapAccount = {
  /** The fingerprint of the wallet's master key. */
  readonly masterFingerprint: number
  readonly descriptors: readonly OutputDescriptor[]
}

const MAX_DESCRIPTORS = 64

/**
 * `crypto-account`: what a signer shares so a watch-only wallet can follow its accounts. Each descriptor is written
 * inside `#6.308`, as the specification's example is; one written without it (Keystone's registry does) reads too.
 */
export const CRYPTO_ACCOUNT = defineURType({
  fromCbor: (item: CborValue): BitcoinAirgapAccount => {
    const map = readMap(item, 'An account')
    const descriptors = readArray(
      required(map, 2, 'An account`s descriptors'),
      'An account`s descriptors',
      MAX_DESCRIPTORS
    )

    if (descriptors.length === 0) {
      throw protocolError('An account has at least one descriptor.')
    }

    return Object.freeze({
      descriptors: Object.freeze(
        descriptors.map(descriptor =>
          outputFromCbor(isCborTagged(descriptor) && descriptor.tag === 308 ? descriptor.value : descriptor)
        )
      ),
      masterFingerprint: readUint(required(map, 1, 'A master fingerprint'), 'A master fingerprint', UINT32_MAX),
    })
  },
  tag: 311,
  toCbor: (account: BitcoinAirgapAccount): CborValue => {
    if (
      !Number.isInteger(account.masterFingerprint) ||
      account.masterFingerprint < 0 ||
      account.masterFingerprint > UINT32_MAX
    ) {
      throw new AirgapError('INVALID_ARGUMENT', 'A master fingerprint is a 32-bit unsigned integer.')
    }

    if (account.descriptors.length === 0 || account.descriptors.length > MAX_DESCRIPTORS) {
      throw new AirgapError('INVALID_ARGUMENT', 'An account has from 1 to 64 descriptors.')
    }

    return writeMap([
      [1, account.masterFingerprint],
      [2, account.descriptors.map(descriptor => writeTagged(308, outputToCbor(descriptor)))],
    ])
  },
  type: 'crypto-account',
})
