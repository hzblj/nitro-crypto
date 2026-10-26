import {bytes, utf8} from '@hzblj/nitro-crypto/adapter'

import type {Keccak256, SignableMessage} from './types'

const PREFIX = '\u0019Ethereum Signed Message:\n'

/**
 * EIP-191 version 0x45, `personal_sign`: Keccak-256 of the prefix, the message's length in bytes as decimal text,
 * and the message. Text is signed as its UTF-8 bytes, as wallets and viem do.
 */
export const hashMessage = (message: SignableMessage, keccak256: Keccak256): Uint8Array => {
  const body = typeof message === 'string' ? utf8.encode(message) : message

  return keccak256(bytes.concat(utf8.encode(`${PREFIX}${body.length}`), body))
}
