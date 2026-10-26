import type {CborValue} from '../cbor'
import {AirgapError} from '../errors'
import {defineURType} from '../registry'
import {compact, optional, readMap, readUint, writeMap} from '../schema'

/** The coin a key is for (BCR-2020-007, `crypto-coin-info`, tag 305): a SLIP-44 coin type and a network. */
export type CoinInfo = {
  /** SLIP-44: 0 for Bitcoin (the default), 60 for Ethereum, 501 for Solana. */
  readonly type: number
  /** 0 for mainnet (the default), 1 for a test network. */
  readonly network: number
}

const MAX_COIN_TYPE = 0x7fffffff

const toCbor = (info: CoinInfo): CborValue => {
  if (!Number.isInteger(info.type) || info.type < 0 || info.type > MAX_COIN_TYPE) {
    throw new AirgapError('INVALID_ARGUMENT', 'A coin type is an integer from 0 to 2^31 - 1.')
  }

  if (!Number.isInteger(info.network) || info.network < 0 || info.network > MAX_COIN_TYPE) {
    throw new AirgapError('INVALID_ARGUMENT', 'A network is a non-negative integer.')
  }

  // Defaults are left out, as the schema's `.default` allows and every encoder does.
  return writeMap([
    [1, info.type === 0 ? undefined : info.type],
    [2, info.network === 0 ? undefined : info.network],
  ])
}

const fromCbor = (item: CborValue): CoinInfo => {
  const map = readMap(item, 'A coin info')

  return compact({
    network: optional(map, 2, value => readUint(value, 'A coin info`s network', MAX_COIN_TYPE)) ?? 0,
    type: optional(map, 1, value => readUint(value, 'A coin type', MAX_COIN_TYPE)) ?? 0,
  })
}

/** `crypto-coin-info`: which coin, and which network, a key is for. */
export const CRYPTO_COIN_INFO = defineURType({fromCbor, tag: 305, toCbor, type: 'crypto-coin-info'})
