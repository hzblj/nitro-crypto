import {base58, bytes, CryptoError, utf8} from '@hzblj/nitro-crypto/adapter'

import {addressBytes, type SolanaAddress} from './address'

/**
 * How a v0 off-chain message's text may be shown: printable ASCII (0x20 to 0x7e) or UTF-8, each within 1232 bytes
 * with the header (what a hardware wallet can display), or UTF-8 of up to 65535 bytes.
 */
export type SolanaOffchainMessageFormat = 'restricted-ascii' | 'limited-utf8' | 'extended-utf8'

/**
 * A message for signers to sign off the chain, in Solana's off-chain message format: its bytes start with
 * `\xffsolana offchain`, which no transaction can, so a signature of one is never a signature of a transaction.
 *
 * - Version 0 names the application that asks (`applicationDomain`), a format, the signers in order, and the text.
 * - Version 1 names the signers (written in byte order) and the text, of any length.
 */
export type SolanaOffchainMessage =
  | {
      readonly version: 0
      /** 32 bytes naming the application that asks, Base58: a program's address, a DAO's, or any 32 bytes. */
      readonly applicationDomain: string
      /** The most restrictive format the text fits when left out. */
      readonly format?: SolanaOffchainMessageFormat
      /** Every address that must sign, in the order the message lists them. */
      readonly signers: readonly string[]
      readonly text: string
    }
  | {
      readonly version: 1
      /** Every address that must sign. The message lists them in byte order, whatever the order here. */
      readonly signers: readonly string[]
      readonly text: string
    }

/** An off-chain message read back from its bytes: everything a signer shows before it signs. */
export type DecodedSolanaOffchainMessage =
  | {
      readonly version: 0
      readonly applicationDomain: string
      readonly format: SolanaOffchainMessageFormat
      readonly signers: readonly SolanaAddress[]
      readonly text: string
    }
  | {readonly version: 1; readonly signers: readonly SolanaAddress[]; readonly text: string}

/** An off-chain message and one signer's signature of it. */
export type SignedSolanaOffchainMessage = {
  /** The encoded message: the bytes that were signed, and that a verifier needs. */
  readonly message: Uint8Array
  /** The 64-byte Ed25519 signature. */
  readonly signature: Uint8Array
}

/** `\xffsolana offchain`: the signing domain every off-chain message starts with. */
const SIGNING_DOMAIN = Uint8Array.of(0xff, ...utf8.encode('solana offchain'))

/** What a hardware wallet can sign in one go: a v0 message in the two limited formats, header included. */
const LIMITED_LENGTH = 1232
const MAX_TEXT_LENGTH = 0xffff
const MAX_SIGNERS = 255

const FORMATS: readonly SolanaOffchainMessageFormat[] = ['restricted-ascii', 'limited-utf8', 'extended-utf8']

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

/** The v0 header's length: signing domain, version, application domain, format, signer count, signers, text length. */
const v0HeaderLength = (signers: number) => SIGNING_DOMAIN.length + 1 + 32 + 1 + 1 + 32 * signers + 2

const isRestrictedAscii = (text: Uint8Array) => text.every(byte => byte >= 0x20 && byte <= 0x7e)

/** The text's bytes, refused unless they are UTF-8 that decodes back to themselves. */
const checkedText = (text: Uint8Array): string => {
  const decoded = utf8.decode(text)

  if (!bytes.equal(utf8.encode(decoded), text)) {
    throw invalid('An off-chain message`s text is UTF-8.')
  }

  return decoded
}

/** Whether `text` may be sent as `format` in a v0 message with `signers` signers: kit's checks, refused by name. */
const checkFormat = (format: SolanaOffchainMessageFormat, text: Uint8Array, signers: number) => {
  if (text.length === 0) {
    throw invalid('An off-chain message has text.')
  }

  if (format === 'restricted-ascii' && !isRestrictedAscii(text)) {
    throw invalid('A restricted-ascii message is printable ASCII only (0x20 to 0x7e).')
  }

  if (format !== 'extended-utf8' && v0HeaderLength(signers) + text.length > LIMITED_LENGTH) {
    throw invalid(`A ${format} message is at most ${LIMITED_LENGTH} bytes, its header included.`)
  }

  if (text.length > MAX_TEXT_LENGTH) {
    throw invalid(`An off-chain message's text is at most ${MAX_TEXT_LENGTH} bytes.`)
  }
}

/** The bytes of each signer, checked: at least one, at most 255, each a Solana address, none twice. */
const signerBytes = (signers: readonly string[]): Uint8Array[] => {
  if (signers.length === 0 || signers.length > MAX_SIGNERS) {
    throw invalid(`An off-chain message names 1 to ${MAX_SIGNERS} signers.`)
  }

  if (new Set(signers).size !== signers.length) {
    throw invalid('An off-chain message names a signer twice.')
  }

  return signers.map(signer => addressBytes(signer, 'signer'))
}

/** Byte order, which version 1 lists its signers in. */
const compareBytes = (left: Uint8Array, right: Uint8Array) => {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0)

    if (difference !== 0) {
      return difference
    }
  }

  return left.length - right.length
}

/**
 * The bytes of an off-chain message, which each signer signs: @solana/kit's `getOffchainMessageEncoder`, byte for
 * byte. A v0 message without a format gets the most restrictive one its text fits: restricted ASCII, then limited
 * UTF-8, then extended UTF-8.
 */
export const encodeOffchainMessage = (message: SolanaOffchainMessage): Uint8Array => {
  if (message.version !== 0 && message.version !== 1) {
    throw invalid('An off-chain message is version 0 or 1.')
  }

  const text = utf8.encode(message.text)
  const signers = signerBytes(message.signers)

  if (text.length === 0) {
    throw invalid('An off-chain message has text.')
  }

  if (message.version === 1) {
    return bytes.concat(SIGNING_DOMAIN, Uint8Array.of(1, signers.length), ...[...signers].sort(compareBytes), text)
  }

  const domain = addressBytes(message.applicationDomain, 'application domain')
  const limited = v0HeaderLength(signers.length) + text.length <= LIMITED_LENGTH
  const format =
    message.format ?? (limited ? (isRestrictedAscii(text) ? 'restricted-ascii' : 'limited-utf8') : 'extended-utf8')

  if (!FORMATS.includes(format)) {
    throw invalid('A v0 off-chain message`s format is restricted-ascii, limited-utf8 or extended-utf8.')
  }

  checkFormat(format, text, signers.length)
  const length = new Uint8Array(2)
  new DataView(length.buffer).setUint16(0, text.length, true)

  return bytes.concat(
    SIGNING_DOMAIN,
    Uint8Array.of(0),
    domain,
    Uint8Array.of(FORMATS.indexOf(format), signers.length),
    ...signers,
    length,
    text
  )
}

type Reader = {readonly data: Uint8Array; offset: number}

const take = (reader: Reader, length: number): Uint8Array => {
  if (length > reader.data.length - reader.offset) {
    throw invalid('The off-chain message ends in the middle of a field.')
  }

  const out = reader.data.subarray(reader.offset, reader.offset + length)
  reader.offset += length

  return out
}

const readSigners = (reader: Reader): SolanaAddress[] => {
  const count = take(reader, 1)[0] ?? 0

  if (count === 0) {
    throw invalid('An off-chain message names at least one signer.')
  }

  return Array.from({length: count}, () => base58.encode(take(reader, 32)))
}

/**
 * Reads an off-chain message from its bytes, strictly: the signing domain, a version @solana/kit reads (0 or 1),
 * at least one signer and none twice (version 1's in byte order), a format the text keeps to, UTF-8 text, and
 * nothing after it. Anything else is `INVALID_ARGUMENT`; so is a transaction, which never starts with the domain.
 */
export const decodeOffchainMessage = (message: Uint8Array): DecodedSolanaOffchainMessage => {
  const reader: Reader = {data: message, offset: 0}

  if (!bytes.equal(take(reader, SIGNING_DOMAIN.length), SIGNING_DOMAIN)) {
    throw invalid('Not an off-chain message: it does not start with the signing domain.')
  }

  const version = take(reader, 1)[0] ?? 0

  if (version === 1) {
    const signers = readSigners(reader)
    const encoded = signers.map(signer => base58.decode(signer))

    if (encoded.some((signer, index) => index > 0 && compareBytes(encoded[index - 1] ?? signer, signer) >= 0)) {
      throw invalid('A version 1 off-chain message lists its signers once each, in byte order.')
    }

    const text = message.subarray(reader.offset)

    if (text.length === 0) {
      throw invalid('An off-chain message has text.')
    }

    return Object.freeze({signers: Object.freeze(signers), text: checkedText(text), version: 1})
  }

  if (version !== 0) {
    throw invalid(`Off-chain messages are version 0 or 1, not ${version}.`)
  }

  const applicationDomain = base58.encode(take(reader, 32))
  const format = FORMATS[take(reader, 1)[0] ?? 0xff]

  if (format === undefined) {
    throw invalid('A v0 off-chain message`s format is 0, 1 or 2.')
  }

  const signers = readSigners(reader)

  if (new Set(signers).size !== signers.length) {
    throw invalid('An off-chain message names a signer twice.')
  }

  const length = take(reader, 2)
  const text = message.subarray(reader.offset)

  if ((length[0] ?? 0) + ((length[1] ?? 0) << 8) !== text.length) {
    throw invalid('The off-chain message`s length is not its text`s.')
  }

  checkFormat(format, text, signers.length)

  return Object.freeze({
    applicationDomain,
    format,
    signers: Object.freeze(signers),
    text: checkedText(text),
    version: 0,
  })
}

/** The bytes of a message given either way, and its signers, checked as `decodeOffchainMessage` checks them. */
export const offchainMessageBytes = (
  message: SolanaOffchainMessage | Uint8Array
): {readonly bytes: Uint8Array; readonly signers: readonly SolanaAddress[]} => {
  if (message instanceof Uint8Array) {
    return {bytes: message, signers: decodeOffchainMessage(message).signers}
  }

  const encoded = encodeOffchainMessage(message)

  return {bytes: encoded, signers: decodeOffchainMessage(encoded).signers}
}
