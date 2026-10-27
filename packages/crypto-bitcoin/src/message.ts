import {
  bytes,
  CryptoError,
  isCryptoError,
  type PublicKeyFormat,
  type RecoverableSignature,
  utf8,
} from '@hzblj/nitro-crypto/adapter'

import {type BitcoinAddressValidation, type Hash, hash160, type TaprootTweak, validateAddress} from './address'
import {decodeBase64, encodeBase64} from './base64'
import {decodeDerSignature, encodeDerSignature} from './der'
import type {BitcoinNetwork} from './networks'
import {
  type AccountSigner,
  bip143Digest,
  hash256,
  p2wpkhScriptCode,
  type RawTransaction,
  SIGHASH_ALL,
  SIGHASH_DEFAULT,
  taggedHash,
  taprootSighash,
  u32,
  u64,
  varint,
} from './transaction'

/**
 * Bitcoin message signatures: BIP-322's simple form, which proves control of a P2WPKH or Taproot address by a witness
 * that would spend a coin of it in a transaction committing to the message, and the legacy "Bitcoin Signed Message"
 * (BIP-137), a recoverable ECDSA signature many services still ask for.
 */

/** Text (signed as its UTF-8 bytes) or bytes, signed exactly as given. */
export type BitcoinMessage = string | Uint8Array

/**
 * How `signMessage` writes a signature, Base64 text in each case:
 * - `bip322`: BIP-322's simple signature (the witness), prefixed `smp` as BIP-322 requires since it was finalized.
 * - `bip322-unprefixed`: the same witness without `smp`, for verifiers written before BIP-322 was finalized (2026).
 * - `legacy`: BIP-137, 65 bytes, its header byte 39 to 42 (native SegWit). P2WPKH accounts only.
 */
export type BitcoinMessageFormat = 'bip322' | 'bip322-unprefixed' | 'legacy'

const SIMPLE = 'smp'

/** "\x18Bitcoin Signed Message:\n", which legacy signatures hash before the message. */
const LEGACY_PREFIX = utf8.encode('\u0018Bitcoin Signed Message:\n')

/** BIP-137's header bytes: the recovery id plus 27 (uncompressed P2PKH), 31 (compressed), 35 (P2SH-P2WPKH), 39 (P2WPKH). */
const HEADER_P2WPKH = 39

const messageBytes = (message: BitcoinMessage): Uint8Array => {
  if (typeof message === 'string') {
    return utf8.encode(message)
  }

  if (message instanceof Uint8Array) {
    return message
  }

  throw new CryptoError('INVALID_ARGUMENT', 'A message is text or bytes.')
}

/** BIP-322's message hash: the tagged hash `BIP0322-signed-message` of the message as it is, with no length. */
export const bip322MessageHash = (message: Uint8Array, sha256: Hash): Uint8Array =>
  taggedHash('BIP0322-signed-message', message, sha256)

/**
 * BIP-322's `to_spend`: a virtual transaction (version 0, its one input spending nothing that exists) whose output pays
 * `scriptPubKey` and whose input script commits to the message hash. Its id, in internal byte order.
 */
export const bip322ToSpend = (messageHash: Uint8Array, scriptPubKey: Uint8Array, sha256: Hash): Uint8Array =>
  hash256(
    bytes.concat(
      u32(0),
      varint(1),
      new Uint8Array(32),
      u32(0xffffffff),
      // OP_0 PUSH32 <message hash>
      Uint8Array.of(34, 0x00, 0x20),
      messageHash,
      u32(0),
      varint(1),
      u64(0n),
      varint(scriptPubKey.length),
      scriptPubKey,
      u32(0)
    ),
    sha256
  )

/** BIP-322's `to_sign` of the simple form: version 0, spending `to_spend`'s output, paying nothing to `OP_RETURN`. */
export const bip322ToSign = (toSpend: Uint8Array): RawTransaction => ({
  inputs: [{sequence: 0, txid: toSpend, value: 0n, vout: 0}],
  locktime: 0,
  outputs: [{scriptPubKey: Uint8Array.of(0x6a), value: 0n}],
  version: 0,
})

/** The legacy message digest: double SHA-256 of the prefix, the message's length and the message. */
export const legacyMessageHash = (message: Uint8Array, sha256: Hash): Uint8Array =>
  hash256(bytes.concat(LEGACY_PREFIX, varint(message.length), message), sha256)

const serializeWitness = (items: readonly Uint8Array[]) =>
  bytes.concat(varint(items.length), ...items.flatMap(item => [varint(item.length), item]))

/** A witness stack as BIP-322 encodes it; `undefined` for anything that is not exactly one. */
const parseWitness = (data: Uint8Array): Uint8Array[] | undefined => {
  let offset = 0
  const compactSize = (): number | undefined => {
    const first = data[offset++]

    if (first === undefined) {
      return undefined
    }

    if (first < 0xfd) {
      return first
    }

    if (first !== 0xfd || offset + 2 > data.length) {
      // No witness item or stack this short-lived format needs is 64 KiB or more.
      return undefined
    }

    const value = (data[offset] ?? 0) | ((data[offset + 1] ?? 0) << 8)
    offset += 2

    return value < 0xfd ? undefined : value
  }
  const count = compactSize()

  if (count === undefined) {
    return undefined
  }

  const items: Uint8Array[] = []

  for (let index = 0; index < count; index++) {
    const length = compactSize()

    if (length === undefined || offset + length > data.length) {
      return undefined
    }

    items.push(data.slice(offset, offset + length))
    offset += length
  }

  return offset === data.length ? items : undefined
}

/**
 * Signs `message` for `signer`'s address, in `format`: BIP-322's simple signature (with SIGHASH_ALL for P2WPKH and
 * SIGHASH_DEFAULT for Taproot) or a legacy one. `INVALID_ARGUMENT` for a legacy signature of a Taproot account,
 * which BIP-137 has no form for.
 */
export const signMessage = (
  message: BitcoinMessage,
  format: BitcoinMessageFormat,
  signer: AccountSigner,
  sha256: Hash
): string => {
  const data = messageBytes(message)

  if (format === 'legacy') {
    if (signer.type !== 'p2wpkh') {
      throw new CryptoError('INVALID_ARGUMENT', 'A Taproot address has no legacy signature: sign with BIP-322.')
    }

    const {recovery, signature} = signer.key.sign(legacyMessageHash(data, sha256))

    return encodeBase64(bytes.concat(Uint8Array.of(HEADER_P2WPKH + recovery), signature))
  }

  if (format !== 'bip322' && format !== 'bip322-unprefixed') {
    throw new CryptoError('INVALID_ARGUMENT', 'A message signature`s format is bip322, bip322-unprefixed or legacy.')
  }

  const toSign = bip322ToSign(bip322ToSpend(bip322MessageHash(data, sha256), signer.scriptPubKey, sha256))
  let witness: Uint8Array[]

  if (signer.type === 'p2tr') {
    witness = [signer.key.signTaproot(taprootSighash(toSign, 0, [signer.scriptPubKey], SIGHASH_DEFAULT, sha256))]
  } else {
    const scriptCode = p2wpkhScriptCode(signer.scriptPubKey.subarray(2))
    const {signature} = signer.key.sign(bip143Digest(toSign, 0, scriptCode, sha256))
    witness = [bytes.concat(encodeDerSignature(signature), Uint8Array.of(SIGHASH_ALL)), signer.publicKey]
  }

  const encoded = encodeBase64(serializeWitness(witness))

  return format === 'bip322' ? `${SIMPLE}${encoded}` : encoded
}

export type MessageContext = {
  readonly network: BitcoinNetwork
  readonly sha256: Hash
  readonly ripemd160: Hash
  /** The engine's ECDSA verification (lower S only). */
  readonly verify: (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array) => boolean
  /** The engine's public key recovery. */
  readonly recover: (digest: Uint8Array, signature: RecoverableSignature, format?: PublicKeyFormat) => Uint8Array
  /** The engine's BIP-340 verification; it throws `UNSUPPORTED` on an engine without it. */
  readonly verifySchnorr: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean
  /** The engine's BIP-341 tweak; it throws `UNSUPPORTED` on an engine without it. */
  readonly tweak: TaprootTweak
}

type ValidAddress = Extract<BitcoinAddressValidation, {valid: true}>

/** Whether an engine error means "this does not verify": a key that is no point, a signature that recovers none. */
const isRejection = (error: unknown) =>
  isCryptoError(error, 'INVALID_PUBLIC_KEY') ||
  isCryptoError(error, 'INVALID_SIGNATURE') ||
  isCryptoError(error, 'VERIFICATION_FAILED')

const quietly = (verify: () => boolean): boolean => {
  try {
    return verify()
  } catch (error) {
    if (isRejection(error)) {
      return false
    }

    throw error
  }
}

const inconclusive = (message: string) => new CryptoError('UNSUPPORTED', message)

const lexicographic = (a: Uint8Array, b: Uint8Array) => {
  for (let index = 0; index < a.length; index++) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0)

    if (difference !== 0) {
      return difference
    }
  }

  return 0
}

/**
 * A Taproot witness of more than one item: an annex, or a script path. Either is BIP-322's "inconclusive" here
 * (`UNSUPPORTED`), as long as a script path commits to the output key: its control block's internal key, tweaked by
 * the merkle root of the leaf and the path it gives, must be the key the address pays. Anything else is `false`.
 */
const checkScriptPath = (outputKey: Uint8Array, items: readonly Uint8Array[], context: MessageContext): false => {
  const last = items[items.length - 1] ?? new Uint8Array(0)

  if (last[0] === 0x50) {
    throw inconclusive('A BIP-322 signature with a Taproot annex is not checked here.')
  }

  const leaf = items[items.length - 2] ?? new Uint8Array(0)
  const steps = (last.length - 33) / 32

  if (!Number.isInteger(steps) || steps < 0 || steps > 128) {
    return false
  }

  const leafVersion = (last[0] ?? 0) & 0xfe
  let node = taggedHash('TapLeaf', bytes.concat(Uint8Array.of(leafVersion), varint(leaf.length), leaf), context.sha256)

  for (let step = 0; step < steps; step++) {
    const sibling = last.subarray(33 + step * 32, 65 + step * 32)
    const [first, second] = lexicographic(node, sibling) < 0 ? [node, sibling] : [sibling, node]
    node = taggedHash('TapBranch', bytes.concat(first, second), context.sha256)
  }

  const merkleRoot = node
  const committed = quietly(() => {
    const output = context.tweak(last.subarray(1, 33), merkleRoot)

    return bytes.equal(output.publicKey, outputKey) && output.parity === ((last[0] ?? 0) & 1)
  })

  if (!committed) {
    return false
  }

  throw inconclusive('A BIP-322 signature by a Taproot script path needs a script interpreter: this checks key paths.')
}

const verifySimple = (
  target: ValidAddress,
  message: Uint8Array,
  witness: Uint8Array,
  context: MessageContext
): boolean => {
  const script = target.scriptPubKey

  // Simple signatures are witnesses, so native SegWit only: a legacy address has none.
  if (target.type === 'p2pkh' || target.type === 'p2sh') {
    return false
  }

  const items = parseWitness(witness)

  if (!items || items.length === 0) {
    return false
  }

  if (target.type === 'p2wsh') {
    // The last item is the witness script the address commits to; anything else is plainly no signature of it.
    if (!bytes.equal(context.sha256(items[items.length - 1] ?? new Uint8Array(0)), script.subarray(2))) {
      return false
    }

    throw inconclusive(
      'A BIP-322 signature for a script (P2WSH) needs a script interpreter: this checks P2WPKH and P2TR.'
    )
  }

  if (target.type !== 'p2wpkh' && target.type !== 'p2tr') {
    throw inconclusive('A BIP-322 signature for a witness version this does not know cannot be checked.')
  }

  const toSign = bip322ToSign(bip322ToSpend(bip322MessageHash(message, context.sha256), script, context.sha256))

  if (target.type === 'p2tr') {
    const [signature] = items

    if (items.length > 1) {
      return checkScriptPath(script.subarray(2), items, context)
    }

    // BIP-322 allows SIGHASH_DEFAULT, or SIGHASH_ALL in a 65th byte, and nothing else.
    const hashType = signature?.length === 64 ? SIGHASH_DEFAULT : signature?.[64] === SIGHASH_ALL ? SIGHASH_ALL : -1

    if (!signature || hashType === -1 || signature.length > 65) {
      return false
    }

    const sighash = taprootSighash(toSign, 0, [script], hashType, context.sha256)

    return quietly(() => context.verifySchnorr(script.subarray(2), sighash, signature.subarray(0, 64)))
  }

  const [signature, publicKey] = items

  if (
    items.length !== 2 ||
    !signature ||
    !publicKey ||
    publicKey.length !== 33 ||
    !bytes.equal(hash160(publicKey, context.sha256, context.ripemd160), script.subarray(2)) ||
    signature[signature.length - 1] !== SIGHASH_ALL
  ) {
    return false
  }

  const compact = decodeDerSignature(signature.subarray(0, -1))
  const digest = bip143Digest(toSign, 0, p2wpkhScriptCode(script.subarray(2)), context.sha256)

  return compact !== undefined && quietly(() => context.verify(publicKey, digest, compact))
}

/**
 * A legacy signature verifies when the key it recovers pays the address in a way its header allows, as Electrum
 * reads them: 27 to 30, an uncompressed key's P2PKH; 31 to 34, a compressed key's P2PKH, P2WPKH or P2SH-P2WPKH
 * (what Electrum writes for all three); 35 to 38, P2SH-P2WPKH; 39 to 42, P2WPKH (BIP-137).
 */
const verifyLegacy = (
  target: ValidAddress,
  message: Uint8Array,
  signature: Uint8Array,
  context: MessageContext
): boolean => {
  const header = signature[0] ?? 0
  const compressed = header >= 31
  const recovery = ((header - 27) & 3) as RecoverableSignature['recovery']
  const digest = legacyMessageHash(message, context.sha256)
  let key: Uint8Array

  try {
    key = context.recover(
      digest,
      {recovery, signature: signature.subarray(1)},
      compressed ? 'compressed' : 'uncompressed'
    )
  } catch (error) {
    if (isRejection(error)) {
      return false
    }

    throw error
  }

  const keyHash = hash160(key, context.sha256, context.ripemd160)
  const script = target.scriptPubKey
  const any = header >= 31 && header <= 34

  switch (target.type) {
    case 'p2pkh':
      return header <= 34 && bytes.equal(script.subarray(3, 23), keyHash)
    case 'p2wpkh':
      return (any || header >= 39) && bytes.equal(script.subarray(2), keyHash)
    case 'p2sh':
      return (
        (any || (header >= 35 && header <= 38)) &&
        bytes.equal(
          script.subarray(2, 22),
          hash160(bytes.concat(Uint8Array.of(0x00, 20), keyHash), context.sha256, context.ripemd160)
        )
      )
    default:
      return false
  }
}

/**
 * Whether `signature` is a signature of `message` by `address`: BIP-322's simple form (prefixed `smp`, or not, as
 * written before BIP-322 was final) for P2WPKH and Taproot key path addresses, and a legacy one (65 bytes, its header
 * 27 to 42) for P2PKH, P2SH-P2WPKH and P2WPKH. A malformed signature is `false`. Throws `INVALID_ADDRESS` for an
 * address that is not one of this network, and `UNSUPPORTED` for what this cannot decide: BIP-322's full and
 * proof-of-funds forms, script addresses, Taproot script paths.
 */
export const verifyMessage = (
  address: string,
  message: BitcoinMessage,
  signature: string,
  context: MessageContext
): boolean => {
  const target = validateAddress(address, context.network, context.sha256)

  if (!target.valid) {
    throw new CryptoError('INVALID_ADDRESS', target.reason)
  }

  const data = messageBytes(message)

  if (typeof signature !== 'string') {
    throw new CryptoError('INVALID_ARGUMENT', 'A message signature is Base64 text.')
  }

  const prefix = signature.slice(0, 3)

  if (prefix === 'ful' || prefix === 'pof') {
    throw inconclusive('BIP-322`s full and proof-of-funds signatures are not checked here: simple and legacy ones are.')
  }

  let decoded: Uint8Array

  try {
    decoded = decodeBase64(prefix === SIMPLE ? signature.slice(3) : signature)
  } catch {
    return false
  }

  const header = decoded[0] ?? 0

  if (prefix !== SIMPLE && decoded.length === 65 && header >= 27 && header <= 42) {
    return verifyLegacy(target, data, decoded, context)
  }

  return verifySimple(target, data, decoded, context)
}
