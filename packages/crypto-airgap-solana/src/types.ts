import {
  AirgapError,
  type CborValue,
  CRYPTO_KEYPATH,
  compact,
  defineURType,
  type Keypath,
  optional,
  protocolError,
  type RequestId,
  readBytes,
  readMap,
  readRequestId,
  readTagged,
  readText,
  readUint,
  required,
  writeMap,
  writeRequestId,
  writeTagged,
} from '@hzblj/crypto-airgap'

/** What `sign-data` is: a transaction's message (1), or an arbitrary message (2). */
export type SolSignType = 'transaction' | 'message'

const SIGN_TYPES: readonly SolSignType[] = ['transaction', 'message']

/**
 * `sol-sign-request` (tag 1101, Keystone's registry; the schema OneKey documents too): what to sign, with which key.
 * For a transaction, `signData` is its compiled message: the bytes the key signs.
 */
export type SolSignRequest = {
  readonly requestId?: RequestId
  readonly signData: Uint8Array
  readonly derivationPath: Keypath
  /** The signing key's 32-byte public key (its address, decoded), for the signer to check it holds it. */
  readonly address?: Uint8Array
  readonly origin?: string
  readonly signType: SolSignType
}

/** `sol-signature` (tag 1102): the 64-byte Ed25519 signature, and the id of the request it answers. */
export type SolSignature = {
  readonly requestId?: RequestId
  readonly signature: Uint8Array
}

/** The network refuses transactions over 1232 bytes; messages to sign get the same generous bound. */
const MAX_SIGN_DATA = 64 * 1024

export const SOL_SIGN_REQUEST = defineURType({
  fromCbor: (item: CborValue): SolSignRequest => {
    const map = readMap(item, 'A Solana sign request')
    const signData = readBytes(required(map, 2, 'The data to sign'), 'The data to sign')
    const signType = SIGN_TYPES[readUint(required(map, 6, 'A sign type'), 'A sign type', 2) - 1]

    if (!signType) {
      throw protocolError('A sign type is 1 (transaction) or 2 (message).')
    }

    if (signData.length === 0 || signData.length > MAX_SIGN_DATA) {
      throw protocolError('The data to sign is from 1 byte to 64 KiB.')
    }

    return compact({
      address: optional(map, 4, value => readBytes(value, 'An address', 32)),
      derivationPath: CRYPTO_KEYPATH.fromCbor(
        readTagged(required(map, 3, 'A derivation path'), 304, 'A derivation path')
      ),
      origin: optional(map, 5, value => readText(value, 'An origin')),
      requestId: optional(map, 1, value => readRequestId(value)),
      signData,
      signType,
    })
  },
  tag: 1101,
  toCbor: (request: SolSignRequest): CborValue => {
    if (request.signData.length === 0 || request.signData.length > MAX_SIGN_DATA) {
      throw new AirgapError('INVALID_ARGUMENT', 'The data to sign is from 1 byte to 64 KiB.')
    }

    if (request.address && request.address.length !== 32) {
      throw new AirgapError('INVALID_ARGUMENT', 'An address is 32 bytes.')
    }

    return writeMap([
      [1, request.requestId && writeRequestId(request.requestId)],
      [2, request.signData],
      [3, writeTagged(304, CRYPTO_KEYPATH.toCbor(request.derivationPath))],
      [4, request.address],
      [5, request.origin],
      [6, SIGN_TYPES.indexOf(request.signType) + 1],
    ])
  },
  type: 'sol-sign-request',
})

export const SOL_SIGNATURE = defineURType({
  fromCbor: (item: CborValue): SolSignature => {
    const map = readMap(item, 'A Solana signature')

    return compact({
      requestId: optional(map, 1, value => readRequestId(value)),
      signature: readBytes(required(map, 2, 'A signature'), 'A signature', 64),
    })
  },
  tag: 1102,
  toCbor: (signature: SolSignature): CborValue => {
    if (signature.signature.length !== 64) {
      throw new AirgapError('INVALID_ARGUMENT', 'An Ed25519 signature is 64 bytes.')
    }

    return writeMap([
      [1, signature.requestId && writeRequestId(signature.requestId)],
      [2, signature.signature],
    ])
  },
  type: 'sol-signature',
})
