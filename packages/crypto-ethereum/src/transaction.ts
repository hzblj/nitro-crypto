import {bytes, CryptoError, hex, type RecoverableSignature, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type Address, checksumAddress, validateAddress} from './address'
import {
  authorizationTuple,
  type EthereumAuthorization,
  readAuthorization,
  readInteger,
  type SignedEthereumAuthorization,
} from './authorization'
import {chainMismatch, type EthereumNetwork, networkChainId} from './config'
import {checkUint, MAX_UINT64} from './integer'
import {type RlpItem, rlpDecode, rlpEncode, rlpInteger} from './rlp'
import {signatureFields} from './signature'
import type {Hex, Keccak256} from './types'

/** The transaction types this adapter signs, by viem's names: 0, 1, 2 and 4 in EIP-2718's numbering. */
export type EthereumTransactionType = 'legacy' | 'eip2930' | 'eip1559' | 'eip7702'

/**
 * EIP-2930's access list: the addresses and storage slots a transaction declares it touches, which then cost less
 * gas to touch (and more to declare). From `eth_createAccessList`, or none.
 */
export type EthereumAccessList = readonly {
  /** Any case; a mixed-case address must carry a valid EIP-55 checksum. */
  readonly address: string
  /** 32-byte slot keys, as `0x` hex or bytes. */
  readonly storageKeys: readonly (Hex | Uint8Array)[]
}[]

type CommonRequest = {
  /**
   * The recipient or the contract called; any case, and a mixed-case address must carry a valid EIP-55 checksum.
   * `null` creates a contract, with the init code in `data` (required): the key is never left out, so a forgotten
   * recipient is an error and not a deployment.
   */
  readonly to: string | null
  /** Wei, 0 when left out. */
  readonly value?: bigint
  /** Call data (an ERC-20 transfer is `erc20.transferData(…)` here, with `value` 0), or init code. Empty by default. */
  readonly data?: Hex | Uint8Array
  /** The sender's transaction count, from `eth_getTransactionCount(address, 'pending')`. At most 2^64 - 1. */
  readonly nonce: number | bigint
  /** The gas limit: 21000 for a plain transfer, `eth_estimateGas` for anything else. */
  readonly gas: bigint
  /**
   * The EIP-155 chain id the signature binds to. The adapter's network when left out; any other is `CHAIN_MISMATCH`,
   * so a transaction for one network is never signed by an adapter configured for another.
   */
  readonly chainId?: number
}

type DynamicFee = {
  /** The most the sender pays per gas, base fee and tip together. */
  readonly maxFeePerGas: bigint
  /** The tip to the block producer per gas, at most `maxFeePerGas`. */
  readonly maxPriorityFeePerGas: bigint
  /** EIP-2930's access list; none when left out. */
  readonly accessList?: EthereumAccessList
}

/**
 * A legacy (type 0) transaction, always with EIP-155 replay protection: its signature binds the chain id, and an
 * unprotected one (valid on every chain) is never signed or read here.
 */
export type LegacyTransactionRequest = CommonRequest & {
  readonly type: 'legacy'
  /** Wei per gas. */
  readonly gasPrice: bigint
}

/** An EIP-2930 (type 1) transaction: a legacy gas price, and an access list. */
export type Eip2930TransactionRequest = CommonRequest & {
  readonly type: 'eip2930'
  /** Wei per gas. */
  readonly gasPrice: bigint
  /** None when left out. */
  readonly accessList?: EthereumAccessList
}

/** An EIP-1559 (type 2) transaction: what a wallet sends by default, and what a request without `type` is. */
export type Eip1559TransactionRequest = CommonRequest & DynamicFee & {readonly type?: 'eip1559'}

/**
 * An EIP-7702 (type 4) transaction: EIP-1559 fees, and the authorizations it carries, each delegating an account's
 * code to a contract (`account.signAuthorization`). It always has a recipient: it cannot create a contract.
 */
export type Eip7702TransactionRequest = Omit<CommonRequest, 'to'> &
  DynamicFee & {
    readonly type: 'eip7702'
    /** The recipient or the contract called, often the authorizing account itself. */
    readonly to: string
    /** At least one authorization, each for the adapter's chain id or 0. */
    readonly authorizationList: readonly EthereumAuthorization[]
  }

/**
 * A transaction to sign: legacy (type 0, with EIP-155), EIP-2930 (type 1), EIP-1559 (type 2, the default when `type`
 * is left out) or EIP-7702 (type 4). Amounts are in wei. EIP-4844 blob transactions are not supported.
 */
export type EthereumTransactionRequest =
  | LegacyTransactionRequest
  | Eip2930TransactionRequest
  | Eip1559TransactionRequest
  | Eip7702TransactionRequest

/** An access list as `parseTransaction` returns it. */
export type ParsedAccessList = readonly {readonly address: Address; readonly storageKeys: readonly Hex[]}[]

type ParsedCommon = {
  readonly chainId: number
  readonly nonce: bigint
  readonly gas: bigint
  /** `null` for a contract creation. */
  readonly to: Address | null
  readonly value: bigint
  readonly data: Hex
}

type ParsedDynamicFee = {
  readonly maxFeePerGas: bigint
  readonly maxPriorityFeePerGas: bigint
  readonly accessList: ParsedAccessList
}

/**
 * An unsigned transaction read back by `parseTransaction`: every field present, addresses EIP-55, data as hex. It is
 * a request too: serializing it gives back the bytes it was read from.
 */
export type ParsedEthereumTransaction =
  | (ParsedCommon & {readonly type: 'legacy'; readonly gasPrice: bigint})
  | (ParsedCommon & {readonly type: 'eip2930'; readonly gasPrice: bigint; readonly accessList: ParsedAccessList})
  | (ParsedCommon & ParsedDynamicFee & {readonly type: 'eip1559'})
  | (Omit<ParsedCommon, 'to'> &
      ParsedDynamicFee & {
        readonly type: 'eip7702'
        readonly to: Address
        readonly authorizationList: readonly SignedEthereumAuthorization[]
      })

/** A signed transaction, ready for `eth_sendRawTransaction`. */
export type SignedEthereumTransaction = {
  /** The raw transaction: an RLP list for a legacy one, the EIP-2718 envelope (type byte, then RLP) otherwise. */
  readonly serialized: Hex
  /** Keccak-256 of `serialized`: the transaction hash an explorer and `eth_getTransactionReceipt` know it by. */
  readonly hash: Hex
  /** The signature in it: `r || s` and the y parity. What an air-gapped signer sends back (ERC-4527). */
  readonly signature: RecoverableSignature
}

const TYPE_BYTES = {eip1559: 0x02, eip2930: 0x01, eip7702: 0x04} as const

const TYPES: readonly string[] = ['legacy', 'eip2930', 'eip1559', 'eip7702']

/** What only an EIP-4844 blob transaction has. */
const BLOB_FIELDS = ['blobs', 'blobVersionedHashes', 'maxFeePerBlobGas', 'sidecars'] as const

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

const blobsUnsupported = () =>
  new CryptoError('UNSUPPORTED', 'EIP-4844 blob transactions (type 3) are not supported by this adapter.')

/** A request checked and encoded: its type, its unsigned fields in RLP order, and the chain id they bind. */
type Encoded = {readonly type: EthereumTransactionType; readonly fields: readonly RlpItem[]; readonly chainId: number}

const recipient = (to: unknown, type: EthereumTransactionType, data: Uint8Array, keccak256: Keccak256) => {
  if (to === null) {
    if (type === 'eip7702') {
      throw invalid('An EIP-7702 transaction has a recipient: it cannot create a contract.')
    }

    if (data.length === 0) {
      throw invalid('A contract creation (to: null) carries the init code in data.')
    }

    return new Uint8Array(0)
  }

  if (typeof to !== 'string') {
    throw new CryptoError(
      'INVALID_ADDRESS',
      'A transaction names its recipient in to, or to: null to create a contract.'
    )
  }

  const validation = validateAddress(to, keccak256)

  if (!validation.valid) {
    throw new CryptoError('INVALID_ADDRESS', validation.reason)
  }

  return hex.decode(validation.normalized)
}

const bytesField = (value: unknown, name: string): Uint8Array => {
  if (value === undefined) {
    return new Uint8Array(0)
  }

  if (value instanceof Uint8Array) {
    return value
  }

  if (typeof value !== 'string') {
    throw invalid(`The ${name} is hex or bytes.`)
  }

  return hex.decode(value)
}

const accessListField = (list: unknown, keccak256: Keccak256): RlpItem[] => {
  if (list === undefined) {
    return []
  }

  if (!Array.isArray(list)) {
    throw invalid('An access list is a list of {address, storageKeys}.')
  }

  return list.map((entry: unknown) => {
    const {address, storageKeys} = (typeof entry === 'object' && entry !== null ? entry : {}) as {
      address?: unknown
      storageKeys?: unknown
    }
    const validation = validateAddress(typeof address === 'string' ? address : '', keccak256)

    if (!validation.valid) {
      throw new CryptoError('INVALID_ADDRESS', `An access list address is not valid. ${validation.reason}`)
    }

    if (!Array.isArray(storageKeys)) {
      throw invalid('An access list entry`s storageKeys is a list.')
    }

    return [
      hex.decode(validation.normalized),
      storageKeys.map((key: unknown) => {
        const raw = bytesField(key, 'storage key')

        if (raw.length !== 32) {
          throw invalid('A storage key is 32 bytes.')
        }

        return raw
      }),
    ]
  })
}

const resolveType = (request: Readonly<Record<string, unknown>>): EthereumTransactionType => {
  const type = request.type ?? 'eip1559'

  if (type === 'eip4844' || BLOB_FIELDS.some(field => request[field] !== undefined)) {
    throw blobsUnsupported()
  }

  if (typeof type !== 'string' || !TYPES.includes(type)) {
    throw new CryptoError(
      'UNSUPPORTED',
      'The transaction type is not one this adapter signs: legacy, eip2930, eip1559 or eip7702.'
    )
  }

  return type as EthereumTransactionType
}

/** The fee fields of `type`, and none of another type's: a mix is a request built for something else. */
const feeFields = (request: Readonly<Record<string, unknown>>, type: EthereumTransactionType): RlpItem[] => {
  if (type === 'legacy' || type === 'eip2930') {
    if (request.maxFeePerGas !== undefined || request.maxPriorityFeePerGas !== undefined) {
      throw invalid(
        'A legacy or EIP-2930 transaction pays a gasPrice: maxFeePerGas and maxPriorityFeePerGas are EIP-1559`s.'
      )
    }

    return [rlpInteger(checkUint(request.gasPrice, 'gas price'))]
  }

  if (request.gasPrice !== undefined) {
    throw invalid('An EIP-1559 or EIP-7702 transaction pays maxFeePerGas and maxPriorityFeePerGas, not a gasPrice.')
  }

  const maxFeePerGas = checkUint(request.maxFeePerGas, 'max fee per gas')
  const maxPriorityFeePerGas = checkUint(request.maxPriorityFeePerGas, 'max priority fee per gas')

  if (maxPriorityFeePerGas > maxFeePerGas) {
    throw invalid('The max priority fee per gas cannot exceed the max fee per gas.')
  }

  return [rlpInteger(maxPriorityFeePerGas), rlpInteger(maxFeePerGas)]
}

/** Checks `request` for `network` and lays out its unsigned fields, in RLP order, as its type has them. */
const encodeRequest = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): Encoded => {
  if (typeof request !== 'object' || request === null) {
    throw invalid('A transaction request is an object.')
  }

  const fields = request as unknown as Readonly<Record<string, unknown>>
  const type = resolveType(fields)
  const chainId = networkChainId(fields.chainId, network, 'The transaction')

  if (type === 'legacy' && fields.accessList !== undefined) {
    throw invalid('A legacy transaction has no access list: an access list needs type eip2930 or later.')
  }

  if (type !== 'eip7702' && fields.authorizationList !== undefined) {
    throw invalid('An authorization list needs type eip7702.')
  }

  const data = bytesField(fields.data, 'data')
  const common = [
    // EIP-2681 caps the nonce at 2^64 - 1.
    rlpInteger(checkUint(fields.nonce, 'nonce', MAX_UINT64)),
    ...feeFields(fields, type),
    rlpInteger(checkUint(fields.gas, 'gas limit')),
    recipient(fields.to, type, data, keccak256),
    rlpInteger(checkUint(fields.value ?? 0n, 'value')),
    data,
  ]

  if (type === 'legacy') {
    return {chainId, fields: common, type}
  }

  const typed = [rlpInteger(BigInt(chainId)), ...common, accessListField(fields.accessList, keccak256)]

  if (type !== 'eip7702') {
    return {chainId, fields: typed, type}
  }

  const list = fields.authorizationList

  if (!Array.isArray(list) || list.length === 0) {
    throw invalid('An EIP-7702 transaction carries at least one authorization.')
  }

  return {
    chainId,
    fields: [
      ...typed,
      list.map((authorization: EthereumAuthorization) => authorizationTuple(authorization, network, keccak256)),
    ],
    type,
  }
}

/**
 * What is signed: EIP-155's `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])` for a legacy transaction,
 * `type || rlp(fields)` for a typed one.
 */
const unsignedPayload = ({chainId, fields, type}: Encoded): Uint8Array =>
  type === 'legacy'
    ? rlpEncode([...fields, rlpInteger(BigInt(chainId)), new Uint8Array(0), new Uint8Array(0)])
    : bytes.concat(Uint8Array.of(TYPE_BYTES[type]), rlpEncode(fields))

/** What is broadcast: a legacy transaction's v is `chainId * 2 + 35 + y parity` (EIP-155), a typed one's the parity. */
const signedPayload = ({chainId, fields, type}: Encoded, signature: RecoverableSignature): Uint8Array => {
  const [parity, r, s] = signatureFields(signature)

  return type === 'legacy'
    ? rlpEncode([...fields, rlpInteger(BigInt(chainId) * 2n + 35n + BigInt(signature.recovery)), r, s])
    : bytes.concat(Uint8Array.of(TYPE_BYTES[type]), rlpEncode([...fields, parity, r, s]))
}

const signed = (encoded: Encoded, signature: RecoverableSignature, keccak256: Keccak256): SignedEthereumTransaction => {
  const serialized = signedPayload(encoded, signature)

  return Object.freeze({
    hash: hex.encode(keccak256(serialized), {prefix: true}) as Hex,
    serialized: hex.encode(serialized, {prefix: true}) as Hex,
    signature: Object.freeze({recovery: signature.recovery, signature: signature.signature.slice()}),
  })
}

/**
 * A transaction's raw bytes on `network`: unsigned without a signature (its Keccak-256 is what a key signs), ready to
 * broadcast with one.
 */
export const serializeTransaction = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256,
  signature?: RecoverableSignature
): Hex => {
  const encoded = encodeRequest(request, network, keccak256)

  return hex.encode(signature ? signedPayload(encoded, signature) : unsignedPayload(encoded), {prefix: true}) as Hex
}

/** Signs the Keccak-256 of the unsigned transaction with `key`, and returns the signed transaction and its hash. */
export const signTransaction = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256,
  key: Secp256k1Key
): SignedEthereumTransaction => {
  const encoded = encodeRequest(request, network, keccak256)

  return signed(encoded, key.sign(keccak256(unsignedPayload(encoded))), keccak256)
}

/** The Keccak-256 a transaction's signature is over: of its unsigned form. */
export const transactionDigest = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): Uint8Array => keccak256(unsignedPayload(encodeRequest(request, network, keccak256)))

/**
 * The signed transaction of `request` and a signature made elsewhere (an air-gapped signer, a hardware wallet). The
 * signature is not checked here: recover its signer with the chain's `recoverTransactionAddress` first.
 */
export const assembleTransaction = (
  request: EthereumTransactionRequest,
  signature: RecoverableSignature,
  network: EthereumNetwork,
  keccak256: Keccak256
): SignedEthereumTransaction => signed(encodeRequest(request, network, keccak256), signature, keccak256)

const readTo = (item: RlpItem | undefined, keccak256: Keccak256): Address | null => {
  if (!(item instanceof Uint8Array) || (item.length !== 20 && item.length !== 0)) {
    throw invalid('The recipient is 20 bytes, or empty for a contract creation.')
  }

  return item.length === 0 ? null : checksumAddress(item, keccak256)
}

const readData = (item: RlpItem | undefined): Hex => {
  if (!(item instanceof Uint8Array)) {
    throw invalid('The transaction`s data is a byte string.')
  }

  return hex.encode(item, {prefix: true}) as Hex
}

const readAccessList = (item: RlpItem | undefined, keccak256: Keccak256): ParsedAccessList => {
  if (!Array.isArray(item)) {
    throw invalid('The access list is a list.')
  }

  return Object.freeze(
    item.map(entry => {
      const [address, keys] = Array.isArray(entry) && entry.length === 2 ? entry : []

      if (!(address instanceof Uint8Array) || address.length !== 20 || !Array.isArray(keys)) {
        throw invalid('An access list entry is a 20-byte address and a list of storage keys.')
      }

      return Object.freeze({
        address: checksumAddress(address, keccak256),
        storageKeys: Object.freeze(
          keys.map(key => {
            if (!(key instanceof Uint8Array) || key.length !== 32) {
              throw invalid('A storage key is 32 bytes.')
            }

            return hex.encode(key, {prefix: true}) as Hex
          })
        ),
      })
    })
  )
}

/** How many unsigned fields each typed envelope has. */
const FIELD_COUNTS = {eip1559: 9, eip2930: 8, eip7702: 10} as const

const typeOf = (first: number | undefined): EthereumTransactionType => {
  if (first === undefined) {
    throw invalid('A transaction is at least one byte.')
  }

  if (first >= 0xc0) {
    return 'legacy'
  }

  // EIP-2718: a typed transaction starts with its type, 0x00 to 0x7f; a legacy one with an RLP list, 0xc0 and up.
  if (first >= 0x80) {
    throw invalid('These bytes are not a transaction: neither a type byte nor an RLP list.')
  }

  if (first === 0x03) {
    throw blobsUnsupported()
  }

  const type = (['eip2930', 'eip1559', 'eip7702'] as const).find(name => TYPE_BYTES[name] === first)

  if (!type) {
    throw new CryptoError('UNSUPPORTED', 'The transaction type is not one this adapter reads: 0, 1, 2 or 4.')
  }

  return type
}

const readFields = (raw: Uint8Array, type: EthereumTransactionType): RlpItem[] => {
  const fields = rlpDecode(type === 'legacy' ? raw : raw.subarray(1))
  const count = type === 'legacy' ? 9 : FIELD_COUNTS[type]

  if (!Array.isArray(fields)) {
    throw invalid('A transaction is an RLP list.')
  }

  if (type === 'legacy' && fields.length === 6) {
    throw invalid(
      'A legacy transaction without EIP-155 replay protection is not read here: it is valid on every chain.'
    )
  }

  // A legacy transaction is nine fields signed or not: unsigned, the last two (r and s) are empty.
  const [r, s] = fields.slice(7)
  const isSigned =
    type === 'legacy'
      ? fields.length === 9 && r instanceof Uint8Array && s instanceof Uint8Array && r.length + s.length > 0
      : fields.length === count + 3

  if (isSigned) {
    throw invalid('The transaction is already signed.')
  }

  if (fields.length !== count) {
    throw invalid(`An unsigned ${type} transaction has ${count} fields.`)
  }

  return fields
}

/**
 * The request in an unsigned transaction, as `serializeTransaction` writes it: what an air-gapped signer reads before
 * it shows and signs. Legacy (EIP-155), EIP-2930, EIP-1559 and EIP-7702. Strict: canonical RLP and integers, nothing
 * after the fields, and this network's chain id (`CHAIN_MISMATCH` otherwise); a signed transaction, an unprotected
 * legacy one, a blob transaction and anything this package would serialize differently are refused. Serializing the
 * result gives back the same bytes.
 */
export const parseTransaction = (
  serialized: Hex | Uint8Array,
  network: EthereumNetwork,
  keccak256: Keccak256
): ParsedEthereumTransaction => {
  const raw = typeof serialized === 'string' ? hex.decode(serialized) : serialized
  const type = typeOf(raw[0])
  const fields = readFields(raw, type)

  // Legacy: [nonce, gasPrice, gas, to, value, data, chainId, 0, 0]. Typed: [chainId, nonce, fees…, gas, to, value,
  // data, accessList, (authorizationList)].
  const [chainIdField, ...rest] = type === 'legacy' ? [fields[6], ...fields.slice(0, 6)] : fields
  const chainId = readInteger(chainIdField, 'chain id', 8)

  if (chainId !== BigInt(network.chainId)) {
    throw chainMismatch(network, 'The transaction')
  }

  const [nonce, ...afterNonce] = rest
  const dynamic = type === 'eip1559' || type === 'eip7702'
  const fees = dynamic
    ? {
        maxFeePerGas: readInteger(afterNonce[1], 'max fee per gas'),
        maxPriorityFeePerGas: readInteger(afterNonce[0], 'max priority fee per gas'),
      }
    : {gasPrice: readInteger(afterNonce[0], 'gas price')}
  const [gas, to, value, data, accessList, authorizationList] = afterNonce.slice(dynamic ? 2 : 1)
  const common = {
    chainId: network.chainId,
    data: readData(data),
    gas: readInteger(gas, 'gas limit'),
    nonce: readInteger(nonce, 'nonce', 8),
    to: readTo(to, keccak256),
    type,
    value: readInteger(value, 'value'),
    ...fees,
  }
  const withLists =
    type === 'legacy'
      ? common
      : {
          ...common,
          accessList: readAccessList(accessList, keccak256),
          ...(type === 'eip7702'
            ? {
                authorizationList: Object.freeze(
                  (Array.isArray(authorizationList) ? authorizationList : [undefined]).map(item =>
                    readAuthorization(item, network, keccak256)
                  )
                ),
              }
            : {}),
        }
  const request = withLists as ParsedEthereumTransaction

  // What the request writes back must be these bytes: any field this package would write differently is refused.
  if (!bytes.equal(unsignedPayload(encodeRequest(request, network, keccak256)), raw)) {
    throw invalid('The transaction does not serialize back to itself.')
  }

  return Object.freeze(request)
}
