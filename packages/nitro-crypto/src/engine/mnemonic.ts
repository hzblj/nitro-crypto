import {fromArrayBuffer, toArrayBuffer, wipe} from '../core/bytes'
import {CryptoError, isCryptoError, native} from '../core/errors'
import {utf8} from '../encoding/utf8'
import type {NitroCrypto} from '../specs/nitro-crypto.nitro'

/** The word counts BIP-39 defines: 128 to 256 bits of entropy. */
export const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24] as const

export type MnemonicLength = (typeof MNEMONIC_LENGTHS)[number]

export type MnemonicCheck =
  | {readonly valid: true; readonly words: number}
  | {readonly valid: false; readonly reason: 'INVALID_MNEMONIC' | 'MNEMONIC_CHECKSUM'; readonly words: number}

export type MnemonicTools = {
  /**
   * A fresh English mnemonic of `words` words (12 by default) from the operating system's CSPRNG, for the user to
   * write down. It is the one secret the engine hands out: it keeps no copy, and the app owns this string from here,
   * so show it once and store it only where the platform protects it. `createEphemeralWallet({mnemonic})` restores
   * the wallet from it.
   */
  readonly generate: (words?: MnemonicLength) => string
  /** Checks a mnemonic against the English list and its checksum, after the same normalization a wallet applies. */
  readonly validate: (mnemonic: string) => MnemonicCheck
}

/** A word count BIP-39 defines, 12 when left out; anything else is `INVALID_ARGUMENT`. */
export const wordCount = (words: number | undefined): MnemonicLength => {
  const count = words ?? 12

  if (!MNEMONIC_LENGTHS.includes(count as MnemonicLength)) {
    throw new CryptoError('INVALID_ARGUMENT', `A mnemonic has ${MNEMONIC_LENGTHS.join(', ')} words.`)
  }

  return count as MnemonicLength
}

const ASCII = /^[\u0000-\u007f]*$/

/**
 * NFKD, as BIP-39 requires of both the mnemonic and the passphrase. ASCII is already NFKD; anything else needs
 * `String.prototype.normalize`, and without one the seed would silently differ from every other wallet's, so that
 * is `UNSUPPORTED` rather than a guess.
 */
export const nfkd = (text: string): string => {
  if (ASCII.test(text)) {
    return text
  }

  if (typeof String.prototype.normalize !== 'function' || 'é' !== 'é'.normalize('NFKD')) {
    throw new CryptoError('UNSUPPORTED', 'This JavaScript runtime cannot NFKD-normalize a non-ASCII passphrase.')
  }

  return text.normalize('NFKD')
}

/** What users type and what BIP-39 hashes: NFKD, lowercase, single spaces, no padding. */
export const normalizeMnemonic = (mnemonic: string): string => nfkd(mnemonic).trim().toLowerCase().split(/\s+/u).join(' ')

export const countWords = (normalized: string): number => (normalized === '' ? 0 : normalized.split(' ').length)

/** Hands `text` to `use` as UTF-8 bytes, and overwrites them afterwards. */
export const withSecretBytes = async <T>(text: string, use: (bytes: ArrayBuffer) => Promise<T>): Promise<T> => {
  const bytes = utf8.encode(text)

  try {
    return await use(toArrayBuffer(bytes))
  } finally {
    wipe(bytes)
  }
}

export const createMnemonicTools = (host: NitroCrypto): MnemonicTools =>
  Object.freeze({
    generate: (words?: MnemonicLength): string => {
      // A view over the buffer the host returned: overwriting it overwrites the engine's hand-off copy too.
      const bytes = fromArrayBuffer(native(() => host.generateMnemonic(wordCount(words))))

      try {
        return utf8.decode(bytes)
      } finally {
        wipe(bytes)
      }
    },
    validate: (mnemonic: string): MnemonicCheck => {
      const normalized = normalizeMnemonic(mnemonic)
      const words = countWords(normalized)
      const bytes = utf8.encode(normalized)

      try {
        native(() => host.validateMnemonic(toArrayBuffer(bytes)))

        return {valid: true, words}
      } catch (error) {
        if (isCryptoError(error, 'INVALID_MNEMONIC') || isCryptoError(error, 'MNEMONIC_CHECKSUM')) {
          return {reason: error.code, valid: false, words}
        }

        throw error
      } finally {
        wipe(bytes)
      }
    },
  })
