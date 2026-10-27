import {bytes, CryptoError, hex, type RecoverableSignature, type RecoveryId} from '@hzblj/nitro-crypto/adapter'

import {type Address, checksumAddress, validateAddress} from './address'
import {chainMismatch, type EthereumNetwork} from './config'
import {bytesToUint, checkUint, MAX_UINT64, word} from './integer'
import {type RlpItem, rlpEncode, rlpInteger} from './rlp'
import {signatureFields, toRecoverable} from './signature'
import type {Hex, Keccak256} from './types'

/** EIP-7702's magic byte for an authorization's digest. */
const MAGIC = 0x05

/**
 * An EIP-7702 authorization to sign: the account delegates its code to the contract at `address`, so that the
 * contract's code runs as the account, with its balance and its storage. Whoever controls that contract controls the
 * account: a wallet shows this with the gravity of handing over the key. Delegating to the zero address clears a
 * delegation.
 */
export type EthereumAuthorizationRequest = {
  /** The contract the account delegates to. Any case; a mixed-case address must carry a valid EIP-55 checksum. */
  readonly address: string
  /**
   * The account's nonce when the authorization is processed. An account that also sends the type 4 transaction
   * carrying it uses the transaction's nonce plus one: the transaction's own nonce is spent first.
   */
  readonly nonce: number | bigint
  /**
   * The chain it is valid on: the adapter's when left out, and no other. 0 makes it valid on every chain, with every
   * chain's balance of the account behind it: refused (`CHAIN_MISMATCH`) unless `allowAllChains` is `true` as well.
   */
  readonly chainId?: number | bigint
  /** Allows chain id 0. Set it only after the user has seen that the delegation applies on every EVM chain. */
  readonly allowAllChains?: boolean
}

/** A signed EIP-7702 authorization: what a type 4 transaction carries in its authorization list. */
export type SignedEthereumAuthorization = {
  /** The contract delegated to, EIP-55 checksummed. */
  readonly address: Address
  readonly chainId: number
  readonly nonce: bigint
  /** `r || s` and the y parity. */
  readonly signature: RecoverableSignature
}

/**
 * An authorization in a transaction's list, signed by this account or by another (a sponsor sends the transaction,
 * the authorizing account need not). Its chain id is the adapter's or 0.
 */
export type EthereumAuthorization = {
  readonly address: string
  readonly chainId: number | bigint
  readonly nonce: number | bigint
  /** The engine's form, or 65 bytes (hex or raw) with v as 0/1 or 27/28. */
  readonly signature: RecoverableSignature | Hex | Uint8Array
}

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

const delegate = (address: unknown, keccak256: Keccak256): Address => {
  const validation = validateAddress(typeof address === 'string' ? address : '', keccak256)

  if (!validation.valid) {
    throw new CryptoError('INVALID_ADDRESS', validation.reason)
  }

  return validation.normalized
}

/** The chain id of an authorization: the network's, or 0 when `allowAllChains` allows it. */
const authorizationChainId = (value: unknown, network: EthereumNetwork, allowAllChains: boolean): number => {
  if (value === undefined) {
    return network.chainId
  }

  const chainId =
    typeof value === 'bigint' ? value : typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) : -1n

  if (chainId < 0n) {
    throw invalid('The chain id of an authorization is a non-negative integer.')
  }

  if (chainId === 0n) {
    if (!allowAllChains) {
      throw new CryptoError(
        'CHAIN_MISMATCH',
        'An authorization for chain id 0 is valid on every chain: pass allowAllChains: true to sign one.'
      )
    }

    return 0
  }

  if (chainId !== BigInt(network.chainId)) {
    throw chainMismatch(network, 'The authorization')
  }

  return network.chainId
}

type AuthorizationFields = {readonly address: Address; readonly chainId: number; readonly nonce: bigint}

const checkRequest = (
  request: EthereumAuthorizationRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): AuthorizationFields => {
  if (typeof request !== 'object' || request === null) {
    throw invalid('An authorization is an object: address, nonce, and chainId when not the adapter`s.')
  }

  return {
    address: delegate(request.address, keccak256),
    chainId: authorizationChainId(request.chainId, network, request.allowAllChains === true),
    // EIP-7702 caps an authorization's nonce at 2^64 - 1.
    nonce: checkUint(request.nonce, 'authorization nonce', MAX_UINT64),
  }
}

const digest = ({address, chainId, nonce}: AuthorizationFields, keccak256: Keccak256) =>
  keccak256(
    bytes.concat(Uint8Array.of(MAGIC), rlpEncode([rlpInteger(BigInt(chainId)), hex.decode(address), rlpInteger(nonce)]))
  )

/**
 * The EIP-7702 digest an account signs to delegate: `keccak256(0x05 || rlp([chainId, address, nonce]))`, after the
 * request's checks (chain id bound to the network, 0 only with `allowAllChains`).
 */
export const hashAuthorization = (
  request: EthereumAuthorizationRequest,
  network: EthereumNetwork,
  keccak256: Keccak256
): Uint8Array => digest(checkRequest(request, network, keccak256), keccak256)

/** Signs `request` with `sign`, which signs a digest (the engine's key). */
export const signAuthorization = (
  request: EthereumAuthorizationRequest,
  network: EthereumNetwork,
  keccak256: Keccak256,
  sign: (digest: Uint8Array) => RecoverableSignature
): SignedEthereumAuthorization => {
  const fields = checkRequest(request, network, keccak256)
  const signature = sign(digest(fields, keccak256))

  return Object.freeze({
    ...fields,
    signature: Object.freeze({recovery: signature.recovery, signature: signature.signature.slice()}),
  })
}

/**
 * The fields of an authorization from a transaction's list, or of one to recover, checked: its chain id is the
 * network's or 0 (it is already signed, so 0 needs no opt-in here). Its signature is the caller's to read.
 */
const authorizationFields = (
  authorization: EthereumAuthorization,
  network: EthereumNetwork,
  keccak256: Keccak256
): AuthorizationFields => {
  if (typeof authorization !== 'object' || authorization === null) {
    throw invalid('An authorization is an object: address, chainId, nonce and signature.')
  }

  if (authorization.chainId === undefined) {
    throw invalid('A signed authorization carries its chain id.')
  }

  return checkRequest({...authorization, allowAllChains: true}, network, keccak256)
}

/** The digest an authorization's signature is over. */
export const authorizationDigest = (
  authorization: EthereumAuthorization,
  network: EthereumNetwork,
  keccak256: Keccak256
): Uint8Array => digest(authorizationFields(authorization, network, keccak256), keccak256)

/** An authorization as a type 4 transaction lists it: `[chainId, address, nonce, yParity, r, s]`. */
export const authorizationTuple = (
  authorization: EthereumAuthorization,
  network: EthereumNetwork,
  keccak256: Keccak256
): RlpItem[] => {
  const {address, chainId, nonce} = authorizationFields(authorization, network, keccak256)

  return [
    rlpInteger(BigInt(chainId)),
    hex.decode(address),
    rlpInteger(nonce),
    ...signatureFields(toRecoverable(authorization.signature)),
  ]
}

/** An RLP integer field: a byte string, canonical (no leading zero), of at most `maxBytes`. */
export const readInteger = (item: RlpItem | undefined, name: string, maxBytes = 32): bigint => {
  if (!(item instanceof Uint8Array) || item.length > maxBytes || item[0] === 0) {
    throw invalid(`The ${name} is not a canonical integer of at most ${maxBytes * 8} bits.`)
  }

  return bytesToUint(item)
}

/** One `[chainId, address, nonce, yParity, r, s]` tuple of a type 4 transaction, read strictly. */
export const readAuthorization = (
  item: RlpItem | undefined,
  network: EthereumNetwork,
  keccak256: Keccak256
): SignedEthereumAuthorization => {
  if (!Array.isArray(item) || item.length !== 6) {
    throw invalid('An authorization in the list is six fields: chainId, address, nonce, yParity, r, s.')
  }

  const [chainIdField, addressField, nonceField, parity, r, s] = item
  const chainId = readInteger(chainIdField, 'authorization chain id')

  if (chainId !== 0n && chainId !== BigInt(network.chainId)) {
    throw chainMismatch(network, 'An authorization in the transaction')
  }

  if (!(addressField instanceof Uint8Array) || addressField.length !== 20) {
    throw invalid('An authorization`s address is 20 bytes.')
  }

  const recovery = readInteger(parity, 'authorization y parity', 1)

  if (recovery > 1n) {
    throw invalid('An authorization`s y parity is 0 or 1.')
  }

  const signature = bytes.concat(word(readInteger(r, 'authorization r')), word(readInteger(s, 'authorization s')))

  return Object.freeze({
    address: checksumAddress(addressField, keccak256),
    chainId: Number(chainId),
    nonce: readInteger(nonceField, 'authorization nonce', 8),
    signature: Object.freeze({recovery: Number(recovery) as RecoveryId, signature}),
  })
}
