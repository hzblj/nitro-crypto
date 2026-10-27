import {CryptoError} from '@hzblj/nitro-crypto/adapter'

import type {BitcoinAccountType} from './address'
import type {BitcoinNetwork} from './networks'

export type BitcoinAccountRequest =
  /**
   * BIP-84 for P2WPKH, `m/84'/{coin}'/{account}'/{change}/{index}`, and BIP-86 for P2TR, `m/86'/…`: coin 0 on mainnet
   * and 1 on test networks, change 0 for receiving addresses and 1 for change. Each defaults to 0.
   */
  | {
      /** `p2wpkh` (native SegWit, the default) or `p2tr` (Taproot, BIP-86). */
      readonly addressType?: BitcoinAccountType
      readonly account?: number
      readonly change?: 0 | 1
      readonly index?: number
    }
  /** Any BIP-32 path, with the address type the account has there: P2WPKH unless `addressType` says `p2tr`. */
  | {readonly addressType?: BitcoinAccountType; readonly path: string}

/** The BIP-43 purpose of each type's standard paths: 84 for P2WPKH (BIP-84), 86 for P2TR (BIP-86). */
export const PURPOSES: Readonly<Record<BitcoinAccountType, number>> = Object.freeze({p2tr: 86, p2wpkh: 84})

/** The address type a request or a watch-only account asks for: `p2wpkh` unless stated. Throws `INVALID_ARGUMENT`. */
export const accountType = (type: unknown = 'p2wpkh'): BitcoinAccountType => {
  if (type !== 'p2wpkh' && type !== 'p2tr') {
    throw new CryptoError('INVALID_ARGUMENT', 'A Bitcoin account`s address type is p2wpkh or p2tr.')
  }

  return type
}

const MAX_INDEX = 0x7fffffff

const index = (value: number | undefined, name: string): number => {
  const resolved = value ?? 0

  if (!Number.isInteger(resolved) || resolved < 0 || resolved > MAX_INDEX) {
    throw new CryptoError('INVALID_ARGUMENT', `The ${name} index is an integer from 0 to 2^31 - 1.`)
  }

  return resolved
}

export const derivationPath = (request: BitcoinAccountRequest, network: BitcoinNetwork): string => {
  const purpose = PURPOSES[accountType(request.addressType)]

  if ('path' in request) {
    return request.path
  }

  const change = request.change ?? 0

  if (change !== 0 && change !== 1) {
    throw new CryptoError('INVALID_ARGUMENT', 'The change index is 0 (receiving) or 1 (change).')
  }

  return `m/${purpose}'/${network.coinType}'/${index(request.account, 'account')}'/${change}/${index(request.index, 'address')}`
}

const PATH = /^m(\/\d+'?)*$/

/** A BIP-32 path as this package writes them (`m/84'/1'/0'/0/0`), each index below 2^31. Throws `INVALID_PATH`. */
export const checkPath = (path: string): string => {
  if (
    typeof path !== 'string' ||
    !PATH.test(path) ||
    path
      .split('/')
      .slice(1)
      .some(step => Number.parseInt(step, 10) > MAX_INDEX)
  ) {
    throw new CryptoError('INVALID_PATH', "A path is `m` and indexes below 2^31, each with `'` when hardened.")
  }

  return path
}
