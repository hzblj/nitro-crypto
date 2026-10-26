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

/**
 * What `sign-data` holds (ERC-4527's `data-type`): an RLP legacy transaction (1), EIP-712 typed data as JSON (2), a
 * message for `personal_sign` (3), or an EIP-2718 typed transaction (4).
 */
export type EthDataType = 'legacy-transaction' | 'typed-data' | 'personal-message' | 'typed-transaction'

const DATA_TYPES: readonly EthDataType[] = ['legacy-transaction', 'typed-data', 'personal-message', 'typed-transaction']

/** ERC-4527 `eth-sign-request` (tag 401): what to sign, with which key, for which chain. */
export type EthSignRequest = {
  /** Repeated by the answer: what ties it to this request. */
  readonly requestId?: RequestId
  readonly signData: Uint8Array
  readonly dataType: EthDataType
  /** The EIP-155 chain id; 1 when absent, as the schema's default says. */
  readonly chainId?: number
  /** The key to sign with: its path, and the fingerprint of the master key it starts from. */
  readonly derivationPath: Keypath
  /** The address of that key, 20 bytes, for the signer to check it holds it. */
  readonly address?: Uint8Array
  /** Who asks, for people: the wallet's name. */
  readonly origin?: string
}

/** ERC-4527 `eth-signature` (tag 402): 65 bytes, `r || s || v`, and the id of the request it answers. */
export type EthSignature = {
  readonly requestId?: RequestId
  readonly signature: Uint8Array
  /** The signer, for people: its device's name. */
  readonly origin?: string
}

/** Far more than any transaction or message a signer shows, small enough to refuse a hostile one cheaply. */
const MAX_SIGN_DATA = 128 * 1024

export const ETH_SIGN_REQUEST = defineURType({
  fromCbor: (item: CborValue): EthSignRequest => {
    const map = readMap(item, 'An Ethereum sign request')
    const dataType = DATA_TYPES[readUint(required(map, 3, 'A data type'), 'A data type', 4) - 1]
    const signData = readBytes(required(map, 2, 'The data to sign'), 'The data to sign')

    if (!dataType) {
      throw protocolError('A data type is 1 to 4.')
    }

    if (signData.length === 0 || signData.length > MAX_SIGN_DATA) {
      throw protocolError('The data to sign is from 1 byte to 128 KiB.')
    }

    return compact({
      address: optional(map, 6, value => readBytes(value, 'An address', 20)),
      chainId: optional(map, 4, value => readUint(value, 'A chain id')),
      dataType,
      derivationPath: CRYPTO_KEYPATH.fromCbor(
        readTagged(required(map, 5, 'A derivation path'), 304, 'A derivation path')
      ),
      origin: optional(map, 7, value => readText(value, 'An origin')),
      requestId: optional(map, 1, value => readRequestId(value)),
      signData,
    })
  },
  tag: 401,
  toCbor: (request: EthSignRequest): CborValue => {
    if (request.signData.length === 0 || request.signData.length > MAX_SIGN_DATA) {
      throw new AirgapError('INVALID_ARGUMENT', 'The data to sign is from 1 byte to 128 KiB.')
    }

    if (request.address && request.address.length !== 20) {
      throw new AirgapError('INVALID_ARGUMENT', 'An address is 20 bytes.')
    }

    if (request.chainId !== undefined && (!Number.isSafeInteger(request.chainId) || request.chainId < 1)) {
      throw new AirgapError('INVALID_ARGUMENT', 'A chain id is a positive integer.')
    }

    return writeMap([
      [1, request.requestId && writeRequestId(request.requestId)],
      [2, request.signData],
      [3, DATA_TYPES.indexOf(request.dataType) + 1],
      [4, request.chainId],
      [5, writeTagged(304, CRYPTO_KEYPATH.toCbor(request.derivationPath))],
      [6, request.address],
      [7, request.origin],
    ])
  },
  type: 'eth-sign-request',
})

export const ETH_SIGNATURE = defineURType({
  fromCbor: (item: CborValue): EthSignature => {
    const map = readMap(item, 'An Ethereum signature')

    return compact({
      origin: optional(map, 3, value => readText(value, 'An origin')),
      requestId: optional(map, 1, value => readRequestId(value)),
      signature: readBytes(required(map, 2, 'A signature'), 'A signature', 65),
    })
  },
  tag: 402,
  toCbor: (signature: EthSignature): CborValue => {
    if (signature.signature.length !== 65) {
      throw new AirgapError('INVALID_ARGUMENT', 'An Ethereum signature is 65 bytes, r || s || v.')
    }

    return writeMap([
      [1, signature.requestId && writeRequestId(signature.requestId)],
      [2, signature.signature],
      [3, signature.origin],
    ])
  },
  type: 'eth-signature',
})
