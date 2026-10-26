import {bytes, CryptoError, hex, type RecoverableSignature, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {type Address, checksumAddress, validateAddress} from './address'
import type {EthereumNetwork} from './config'
import {bytesToUint, checkUint, MAX_UINT64} from './integer'
import {type RlpItem, rlpDecode, rlpEncode, rlpInteger} from './rlp'
import type {Hex, Keccak256} from './types'

/** EIP-2718's type byte for an EIP-1559 transaction. */
const EIP1559 = 0x02

/**
 * An EIP-1559 (type 2) transaction to sign: a transfer of `value`, a contract call with `data`, or both. Amounts are
 * in wei. Contract creation (no `to`) and access lists are not supported.
 */
export type EthereumTransactionRequest = {
  /** The recipient or the contract called. Any case; a mixed-case address must carry a valid EIP-55 checksum. */
  readonly to: string
  /** Wei, 0 when left out. */
  readonly value?: bigint
  /** Call data, empty when left out: an ERC-20 transfer is `erc20.transferData(…)` here, with `value` 0. */
  readonly data?: Hex | Uint8Array
  /** The sender's transaction count, from `eth_getTransactionCount(address, 'pending')`. */
  readonly nonce: number | bigint
  /** The gas limit: 21000 for a plain transfer, `eth_estimateGas` for a call. */
  readonly gas: bigint
  /** The most the sender pays per gas, base fee and tip together. */
  readonly maxFeePerGas: bigint
  /** The tip to the block producer per gas, at most `maxFeePerGas`. */
  readonly maxPriorityFeePerGas: bigint
  /**
   * The EIP-155 chain id the signature binds to. The adapter's network when left out; any other value is refused,
   * so a transaction for one network is never signed by an adapter configured for another.
   */
  readonly chainId?: number
}

/** A signed transaction, ready for `eth_sendRawTransaction`. */
export type SignedEthereumTransaction = {
  /** The EIP-2718 envelope, `0x02` followed by the RLP of the signed fields. */
  readonly serialized: Hex
  /** Keccak-256 of `serialized`: the transaction hash an explorer and `eth_getTransactionReceipt` know it by. */
  readonly hash: Hex
  /** The signature in it: `r || s` and the y parity. What an air-gapped signer sends back (ERC-4527). */
  readonly signature: RecoverableSignature
}

/** The nine fields of an unsigned EIP-1559 transaction, in RLP order, checked and encoded. */
const transactionFields = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): RlpItem[] => {
  const chainId = request.chainId ?? network.chainId

  if (chainId !== network.chainId) {
    throw new CryptoError(
      'INVALID_ARGUMENT',
      `This adapter signs for chain id ${network.chainId} (${network.name}), not ${String(chainId)}.`
    )
  }

  const to = validateAddress(typeof request.to === 'string' ? request.to : '', keccak256)

  if (!to.valid) {
    throw new CryptoError('INVALID_ADDRESS', to.reason)
  }

  const maxFeePerGas = checkUint(request.maxFeePerGas, 'max fee per gas')
  const maxPriorityFeePerGas = checkUint(request.maxPriorityFeePerGas, 'max priority fee per gas')

  if (maxPriorityFeePerGas > maxFeePerGas) {
    throw new CryptoError('INVALID_ARGUMENT', 'The max priority fee per gas cannot exceed the max fee per gas.')
  }

  const data = request.data ?? new Uint8Array(0)

  return [
    rlpInteger(BigInt(chainId)),
    // EIP-2681 caps the nonce at 2^64 - 1.
    rlpInteger(checkUint(request.nonce, 'nonce', MAX_UINT64)),
    rlpInteger(maxPriorityFeePerGas),
    rlpInteger(maxFeePerGas),
    rlpInteger(checkUint(request.gas, 'gas limit')),
    hex.decode(to.normalized),
    rlpInteger(checkUint(request.value ?? 0n, 'value')),
    typeof data === 'string' ? hex.decode(data) : data,
    [],
  ]
}

/** The signature's three fields: y parity, then `r` and `s` as integers (no leading zeros). */
const signatureFields = ({recovery, signature}: RecoverableSignature): RlpItem[] => {
  if (signature.length !== 64 || (recovery !== 0 && recovery !== 1)) {
    throw new CryptoError('INVALID_SIGNATURE', 'An EIP-1559 signature is 64 bytes, r || s, with a y parity of 0 or 1.')
  }

  const integer = (part: Uint8Array) => {
    const start = part.findIndex(byte => byte !== 0)

    return start === -1 ? new Uint8Array(0) : part.slice(start)
  }

  return [rlpInteger(BigInt(recovery)), integer(signature.subarray(0, 32)), integer(signature.subarray(32))]
}

const envelope = (fields: readonly RlpItem[]) => bytes.concat(Uint8Array.of(EIP1559), rlpEncode(fields))

/**
 * The EIP-2718 envelope of an EIP-1559 transaction: `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
 * maxFeePerGas, gas, to, value, data, accessList])`, and with a signature, `yParity, r, s` after them. Unsigned, it
 * is what is signed (its Keccak-256); signed, what is broadcast.
 */
export const serializeTransaction = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256,
  signature?: RecoverableSignature
): Hex => {
  const fields = transactionFields(request, network, keccak256)

  return hex.encode(envelope(signature ? [...fields, ...signatureFields(signature)] : fields), {prefix: true}) as Hex
}

/** Signs the Keccak-256 of the unsigned envelope with `key`, and returns the signed envelope and its hash. */
export const signTransaction = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256,
  key: Secp256k1Key
): SignedEthereumTransaction => {
  const fields = transactionFields(request, network, keccak256)

  return signed(fields, key.sign(keccak256(envelope(fields))), keccak256)
}

const signed = (fields: readonly RlpItem[], signature: RecoverableSignature, keccak256: Keccak256) => {
  const serialized = envelope([...fields, ...signatureFields(signature)])

  return Object.freeze({
    hash: hex.encode(keccak256(serialized), {prefix: true}) as Hex,
    serialized: hex.encode(serialized, {prefix: true}) as Hex,
    signature: Object.freeze({recovery: signature.recovery, signature: signature.signature.slice()}),
  })
}

/** The Keccak-256 an EIP-1559 transaction's signature is over: of its unsigned envelope. */
export const transactionDigest = (
  request: EthereumTransactionRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): Uint8Array => keccak256(envelope(transactionFields(request, network, keccak256)))

/**
 * The signed transaction of `request` and a signature made elsewhere (an air-gapped signer, a hardware wallet). The
 * signature is not checked here: recover its signer with the chain's `recoverTransactionAddress` first.
 */
export const assembleTransaction = (
  request: EthereumTransactionRequest,
  signature: RecoverableSignature,
  network: EthereumNetwork,
  keccak256: Keccak256
): SignedEthereumTransaction => signed(transactionFields(request, network, keccak256), signature, keccak256)

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

/** An RLP integer field: a byte string, canonical (no leading zero), of at most `maxBytes`. */
const readInteger = (item: RlpItem | undefined, name: string, maxBytes = 32): bigint => {
  if (!(item instanceof Uint8Array) || item.length > maxBytes || item[0] === 0) {
    throw invalid(`The ${name} is not a canonical integer of at most ${maxBytes * 8} bits.`)
  }

  return bytesToUint(item)
}

/**
 * The request in an unsigned EIP-1559 envelope (`0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas,
 * to, value, data, accessList])`), as `serializeTransaction` writes it: what an air-gapped signer reads before it
 * shows and signs. Strict: canonical RLP and integers, a recipient (no contract creation), an empty access list,
 * nothing after the nine fields, and this network's chain id. Serializing the result gives back the same bytes.
 */
export const parseTransaction = (
  serialized: Hex | Uint8Array,
  network: EthereumNetwork,
  keccak256: Keccak256
): EthereumTransactionRequest & {readonly chainId: number; readonly to: Address; readonly data: Hex} => {
  const raw = typeof serialized === 'string' ? hex.decode(serialized) : serialized

  if (raw[0] !== EIP1559) {
    throw invalid('Only EIP-1559 (type 2) transactions are read here.')
  }

  const fields = rlpDecode(raw.subarray(1))

  if (!Array.isArray(fields) || fields.length !== 9) {
    throw invalid(
      Array.isArray(fields) && fields.length === 12
        ? 'The transaction is already signed.'
        : 'An unsigned EIP-1559 transaction has nine fields.'
    )
  }

  const [chainIdField, nonce, tip, maxFee, gas, to, value, data, accessList] = fields
  const chainId = readInteger(chainIdField, 'chain id', 8)

  if (chainId !== BigInt(network.chainId)) {
    throw invalid(`The transaction is for chain id ${chainId}, not ${network.chainId} (${network.name}).`)
  }

  if (!(to instanceof Uint8Array) || to.length !== 20) {
    throw invalid('The transaction has no 20-byte recipient: contract creation is not supported.')
  }

  if (!(data instanceof Uint8Array)) {
    throw invalid('The transaction`s data is a byte string.')
  }

  if (!Array.isArray(accessList) || accessList.length !== 0) {
    throw invalid('Transactions with an access list are not supported.')
  }

  const request = {
    chainId: network.chainId,
    data: hex.encode(data, {prefix: true}) as Hex,
    gas: readInteger(gas, 'gas limit'),
    maxFeePerGas: readInteger(maxFee, 'max fee per gas'),
    maxPriorityFeePerGas: readInteger(tip, 'max priority fee per gas'),
    nonce: readInteger(nonce, 'nonce', 8),
    to: checksumAddress(to, keccak256),
    value: readInteger(value, 'value'),
  }

  // What the request writes back must be these bytes: any field this package would write differently is refused.
  if (!bytes.equal(envelope(transactionFields(request, network, keccak256)), raw)) {
    throw invalid('The transaction does not serialize back to itself.')
  }

  return Object.freeze(request)
}
