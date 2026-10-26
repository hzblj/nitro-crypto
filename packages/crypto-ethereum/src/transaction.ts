import {bytes, CryptoError, hex, type RecoverableSignature, type Secp256k1Key} from '@hzblj/nitro-crypto/adapter'

import {validateAddress} from './address'
import type {EthereumNetwork} from './config'
import {checkUint, MAX_UINT64} from './integer'
import {type RlpItem, rlpEncode, rlpInteger} from './rlp'
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
  const signature = key.sign(keccak256(envelope(fields)))
  const signed = envelope([...fields, ...signatureFields(signature)])

  return {
    hash: hex.encode(keccak256(signed), {prefix: true}) as Hex,
    serialized: hex.encode(signed, {prefix: true}) as Hex,
  }
}
