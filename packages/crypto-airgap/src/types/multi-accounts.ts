import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {defineURType} from '../registry'
import {
  compact,
  optional,
  readArray,
  readMap,
  readTagged,
  readText,
  readUint,
  required,
  UINT32_MAX,
  writeMap,
  writeTagged,
} from '../schema'
import {CRYPTO_HDKEY, type HDKey} from './hdkey'

/**
 * The accounts of one signer, on any number of chains (`crypto-multi-accounts`, tag 1103, from Keystone's registry
 * rather than Blockchain Commons'): what Keystone shares with Solana, Ethereum and other wallets to pair, one public
 * key per account, each with the path it was derived at.
 */
export type MultiAccounts = {
  /** The fingerprint of the signer's master key: what its requests are addressed to. */
  readonly masterFingerprint: number
  readonly keys: readonly HDKey[]
  /** The signer's name for people, such as "Keystone". */
  readonly device?: string
  readonly deviceId?: string
  readonly version?: string
}

/** Enough for every account a pairing could reasonably carry, few enough that a hostile one is cheap to refuse. */
const MAX_KEYS = 256

const toCbor = (accounts: MultiAccounts): CborValue => {
  if (!Number.isInteger(accounts.masterFingerprint) || accounts.masterFingerprint < 1) {
    throw new AirgapError('INVALID_ARGUMENT', 'A master fingerprint is a 32-bit integer other than 0.')
  }

  if (accounts.keys.length === 0 || accounts.keys.length > MAX_KEYS) {
    throw new AirgapError('INVALID_ARGUMENT', 'An account list has from 1 to 256 keys.')
  }

  return writeMap([
    [1, accounts.masterFingerprint],
    [2, accounts.keys.map(key => writeTagged(303, CRYPTO_HDKEY.toCbor(key)))],
    [3, accounts.device],
    [4, accounts.deviceId],
    [5, accounts.version],
  ])
}

const fromCbor = (item: CborValue): MultiAccounts => {
  const map = readMap(item, 'An account list')
  const keys = readArray(required(map, 2, 'An account list`s keys'), 'An account list`s keys', MAX_KEYS)

  return compact({
    device: optional(map, 3, value => readText(value, 'A device name')),
    deviceId: optional(map, 4, value => readText(value, 'A device id')),
    keys: Object.freeze(keys.map(key => CRYPTO_HDKEY.fromCbor(readTagged(key, 303, 'An account key')))),
    masterFingerprint: readUint(required(map, 1, 'A master fingerprint'), 'A master fingerprint', UINT32_MAX),
    version: optional(map, 5, value => readText(value, 'A device version')),
  })
}

/** `crypto-multi-accounts`: one signer's public accounts on several chains, to pair a watch-only wallet with. */
export const CRYPTO_MULTI_ACCOUNTS = defineURType({fromCbor, tag: 1103, toCbor, type: 'crypto-multi-accounts'})
