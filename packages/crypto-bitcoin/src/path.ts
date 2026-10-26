import {CryptoError} from '@hzblj/nitro-crypto/adapter'

import type {BitcoinNetwork} from './networks'

export type BitcoinAccountRequest =
  /**
   * BIP-84, `m/84'/{coin}'/{account}'/{change}/{index}`: coin 0 on mainnet and 1 on test networks, change 0 for
   * receiving addresses and 1 for change. Each defaults to 0.
   */
  | {readonly account?: number; readonly change?: 0 | 1; readonly index?: number}
  /** Any BIP-32 path. The address is still P2WPKH: this adapter derives no other type. */
  | {readonly path: string}

const MAX_INDEX = 0x7fffffff

const index = (value: number | undefined, name: string): number => {
  const resolved = value ?? 0

  if (!Number.isInteger(resolved) || resolved < 0 || resolved > MAX_INDEX) {
    throw new CryptoError('INVALID_ARGUMENT', `The ${name} index is an integer from 0 to 2^31 - 1.`)
  }

  return resolved
}

export const derivationPath = (request: BitcoinAccountRequest, network: BitcoinNetwork): string => {
  if ('path' in request) {
    return request.path
  }

  const change = request.change ?? 0

  if (change !== 0 && change !== 1) {
    throw new CryptoError('INVALID_ARGUMENT', 'The change index is 0 (receiving) or 1 (change).')
  }

  return `m/84'/${network.coinType}'/${index(request.account, 'account')}'/${change}/${index(request.index, 'address')}`
}
