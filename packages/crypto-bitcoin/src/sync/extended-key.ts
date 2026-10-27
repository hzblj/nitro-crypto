import {base58check, type ExtendedPublicKey} from '@hzblj/nitro-crypto/adapter'

import type {Hash} from '../address'
import {type BitcoinNetworkName, NETWORKS} from '../networks'
import {SyncError} from './errors'
import type {ScriptType} from './script-types'

/** Mainnet, or any test network (testnet, signet and regtest share their extended keys' prefixes). */
export type ExtendedKeyNetwork = 'mainnet' | 'test'

export type ParsedExtendedKey = {
  readonly extendedKey: ExtendedPublicKey
  readonly network: ExtendedKeyNetwork
  /** `xpub`, `tpub`, `zpub` or `vpub`: the prefix the text had. */
  readonly prefix: string
  /** The script type its SLIP-132 prefix names (`zpub`, `vpub`: P2WPKH), or `undefined` for `xpub` and `tpub`. */
  readonly scriptType: ScriptType | undefined
}

type Version = {
  readonly prefix: string
  readonly network: ExtendedKeyNetwork
  readonly scriptType: ScriptType | undefined
  /** Read, but not for an account this package can follow: P2SH-wrapped SegWit and multisig. */
  readonly unsupported?: string
}

/** BIP-32's and SLIP-132's public versions. */
const PUBLIC: ReadonlyMap<number, Version> = new Map([
  [0x0488b21e, {network: 'mainnet', prefix: 'xpub', scriptType: undefined}],
  [0x043587cf, {network: 'test', prefix: 'tpub', scriptType: undefined}],
  [0x04b24746, {network: 'mainnet', prefix: 'zpub', scriptType: 'p2wpkh'}],
  [0x045f1cf6, {network: 'test', prefix: 'vpub', scriptType: 'p2wpkh'}],
  [
    0x049d7cb2,
    {network: 'mainnet', prefix: 'ypub', scriptType: undefined, unsupported: 'P2SH-wrapped SegWit (BIP-49)'},
  ],
  [0x044a5262, {network: 'test', prefix: 'upub', scriptType: undefined, unsupported: 'P2SH-wrapped SegWit (BIP-49)'}],
  [0x0295b43f, {network: 'mainnet', prefix: 'Ypub', scriptType: undefined, unsupported: 'P2SH-wrapped multisig'}],
  [0x024289ef, {network: 'test', prefix: 'Upub', scriptType: undefined, unsupported: 'P2SH-wrapped multisig'}],
  [0x02aa7ed3, {network: 'mainnet', prefix: 'Zpub', scriptType: undefined, unsupported: 'P2WSH multisig'}],
  [0x02575483, {network: 'test', prefix: 'Vpub', scriptType: undefined, unsupported: 'P2WSH multisig'}],
] as const)

/** The private ones: refused on sight. */
const PRIVATE = new Set([
  0x0488ade4, 0x04358394, 0x049d7878, 0x044a4e28, 0x04b2430c, 0x045f18bc, 0x0295b005, 0x024285b5, 0x02aa7a99,
  0x02575048,
])

/** Version, depth, parent fingerprint, child number, chain code, key. */
const LENGTH = 78

const invalid = (message: string) => new SyncError('INVALID_EXTENDED_KEY', message)

/**
 * An extended public key from its text: `xpub`, `tpub`, or SLIP-132's `zpub` and `vpub` (P2WPKH accounts, as
 * Electrum, Sparrow and most mobile wallets export them). The checksum is the engine's SHA-256 (`crypto.hash.sha256`).
 * Private keys (`xprv`, `zprv`, ...) are `PRIVATE_KEY_MATERIAL`; `ypub`, `Zpub` and the other wrapped or multisig
 * forms are `UNSUPPORTED`; anything else is `INVALID_EXTENDED_KEY`. Messages never quote the text.
 */
export const parseExtendedKey = (text: string, sha256: Hash): ParsedExtendedKey => {
  if (typeof text !== 'string') {
    throw invalid('An extended public key is text.')
  }

  let payload: Uint8Array

  try {
    payload = base58check.decode(text.trim(), sha256)
  } catch (error) {
    throw new SyncError('INVALID_EXTENDED_KEY', 'The text is not Base58Check, or its checksum does not match.', {
      cause: error,
    })
  }

  if (payload.length !== LENGTH) {
    throw invalid('An extended key is 78 bytes.')
  }

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
  const version = view.getUint32(0, false)
  const key = payload.subarray(45, 78)

  if (PRIVATE.has(version) || key[0] === 0x00) {
    throw new SyncError('PRIVATE_KEY_MATERIAL', 'This is an extended private key: share the account`s public one.')
  }

  const known = PUBLIC.get(version)

  if (!known) {
    throw invalid('The extended key has a version no Bitcoin wallet writes.')
  }

  if (known.unsupported) {
    throw new SyncError(
      'UNSUPPORTED',
      `A ${known.prefix} is a ${known.unsupported} account, which this version does not follow.`
    )
  }

  if (key[0] !== 0x02 && key[0] !== 0x03) {
    throw invalid('An extended public key carries a compressed public key.')
  }

  const depth = payload[4] ?? 0
  const parentFingerprint = view.getUint32(5, false)
  const childNumber = view.getUint32(9, false)

  if (depth === 0 && (parentFingerprint !== 0 || childNumber !== 0)) {
    throw invalid('A master key has no parent and no index.')
  }

  return Object.freeze({
    extendedKey: Object.freeze({
      chainCode: payload.slice(13, 45),
      childNumber,
      depth,
      parentFingerprint,
      publicKey: key.slice(),
    }),
    network: known.network,
    prefix: known.prefix,
    scriptType: known.scriptType,
  })
}

/**
 * The text of an extended public key on `network`: `xpub` or `tpub`, or with `scriptType: 'p2wpkh'` SLIP-132's
 * `zpub` or `vpub`, as wallets that import by prefix expect.
 */
export const formatExtendedKey = (
  key: ExtendedPublicKey,
  options: {readonly network: BitcoinNetworkName; readonly scriptType?: ScriptType},
  sha256: Hash
): string => {
  const network = NETWORKS[options.network]

  if (!network) {
    throw new SyncError('INVALID_ARGUMENT', 'A network is mainnet, testnet, signet or regtest.')
  }

  const keyNetwork: ExtendedKeyNetwork = network.coinType === 0 ? 'mainnet' : 'test'
  const slip132 = options.scriptType === 'p2wpkh' ? 'p2wpkh' : undefined
  const version = [...PUBLIC].find(
    ([, candidate]) => candidate.network === keyNetwork && candidate.scriptType === slip132 && !candidate.unsupported
  )?.[0]

  if (version === undefined) {
    throw new SyncError('UNSUPPORTED', 'There is no extended key prefix for this script type.')
  }

  const {chainCode, childNumber, depth, parentFingerprint, publicKey} = key

  if (publicKey?.length !== 33 || chainCode?.length !== 32 || !Number.isInteger(depth) || depth < 0 || depth > 255) {
    throw new SyncError(
      'INVALID_ARGUMENT',
      'An extended public key has a 33-byte key, a 32-byte chain code and a depth.'
    )
  }

  const payload = new Uint8Array(LENGTH)
  const view = new DataView(payload.buffer)
  view.setUint32(0, version, false)
  payload[4] = depth
  view.setUint32(5, parentFingerprint >>> 0, false)
  view.setUint32(9, childNumber >>> 0, false)
  payload.set(chainCode, 13)
  payload.set(publicKey, 45)

  return base58check.encode(payload, sha256)
}
