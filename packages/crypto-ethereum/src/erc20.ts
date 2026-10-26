import {bytes, CryptoError, hex} from '@hzblj/nitro-crypto/adapter'

import {validateAddress} from './address'
import {bytesToUint, checkUint, word} from './integer'
import type {Hex, Keccak256} from './types'

/** The ERC-20 calls a wallet makes, as ABI-encoded call data and decoded results. */
export type Erc20 = {
  /** `transfer(address,uint256)`: the `data` of a transaction to the token contract, with `value` 0. */
  readonly transferData: (to: string, amount: bigint) => Hex
  /** `balanceOf(address)`: the `data` of an `eth_call` to the token contract. */
  readonly balanceOfData: (owner: string) => Hex
  /** A `uint256` result of an `eth_call`, such as a balance. Throws `INVALID_ENCODING` for fewer than 32 bytes. */
  readonly decodeUint256: (result: Hex) => bigint
}

/** The first four bytes of Keccak-256 of each signature. */
const TRANSFER = Uint8Array.of(0xa9, 0x05, 0x9c, 0xbb)
const BALANCE_OF = Uint8Array.of(0x70, 0xa0, 0x82, 0x31)

export const createErc20 = (keccak256: Keccak256): Erc20 => {
  const address = (value: string) => {
    const validation = validateAddress(typeof value === 'string' ? value : '', keccak256)

    if (!validation.valid) {
      throw new CryptoError('INVALID_ADDRESS', validation.reason)
    }

    return word(hex.decode(validation.normalized))
  }
  const call = (...parts: Uint8Array[]) => hex.encode(bytes.concat(...parts), {prefix: true}) as Hex

  return Object.freeze({
    balanceOfData: (owner: string) => call(BALANCE_OF, address(owner)),
    decodeUint256: (result: Hex) => {
      const raw = hex.decode(result)

      if (raw.length < 32) {
        throw new CryptoError(
          'INVALID_ENCODING',
          'A uint256 result is 32 bytes. An empty one means no contract answered at that address.'
        )
      }

      return bytesToUint(raw.subarray(0, 32))
    },
    transferData: (to: string, amount: bigint) => call(TRANSFER, address(to), word(checkUint(amount, 'amount'))),
  })
}
