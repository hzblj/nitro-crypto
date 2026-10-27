/**
 * `@hzblj/crypto-ethereum/viem`: an account whose key the engine holds, as a viem `LocalAccount`, so a viem wallet
 * client (and anything built on one) signs with it. viem is an optional peer dependency, needed by this entry only:
 * the package's main entry never imports it.
 */
import {CryptoError, hex, type RecoverableSignature} from '@hzblj/nitro-crypto/adapter'
import {
  type CustomSource,
  getTransactionType,
  keccak256,
  type LocalAccount,
  type NonceManager,
  type SignableMessage,
  type SignedAuthorization,
  type TransactionSerializable,
  type TypedDataDefinition as ViemTypedDataDefinition,
} from 'viem'
import {toAccount} from 'viem/accounts'

import type {EthereumAccount} from './account'
import type {EthereumAuthorization} from './authorization'
import type {EthereumNetwork} from './config'
import {word} from './integer'
import {type EthereumTransactionRequest, serializeTransaction} from './transaction'
import type {TypedDataDefinition} from './typed-data'
import type {Hex} from './types'

export type ViemAccountOptions = {
  /** viem's nonce manager, as `privateKeyToAccount` takes one: nonces handed out locally instead of fetched. */
  readonly nonceManager?: NonceManager
  /**
   * Signs EIP-7702 authorizations for chain id 0, valid on every chain. Off by default: viem's
   * `signAuthorization({chainId: 0})` is refused with `CHAIN_MISMATCH` unless this is `true`.
   */
  readonly allowAllChains?: boolean
}

/**
 * A viem account backed by the engine: `type: 'local'`, `source: 'nitro-crypto'`, and no `sign` (raw-hash signing,
 * `eth_sign`), which its type says too.
 */
export type NitroViemAccount = LocalAccount<'nitro-crypto'> & {readonly sign?: undefined}

const unsupported = (message: string) => new CryptoError('UNSUPPORTED', message)

const invalid = (message: string) => new CryptoError('INVALID_ARGUMENT', message)

/** viem's form of a signature: `r` and `s` as 32-byte hex, v as 27/28, and the y parity. */
const toViemSignature = ({recovery, signature}: RecoverableSignature) => ({
  r: hex.encode(signature.subarray(0, 32), {prefix: true}) as Hex,
  s: hex.encode(signature.subarray(32, 64), {prefix: true}) as Hex,
  v: BigInt(27 + recovery),
  yParity: recovery,
})

/** A 32-byte word from viem's hex (`r`, `s`), trimmed or not. */
const toWord = (value: unknown, name: string): Uint8Array => {
  const integer =
    typeof value === 'string' && /^0x[0-9a-fA-F]{0,64}$/.test(value) ? BigInt(`0x0${value.slice(2)}`) : -1n

  if (integer < 0n) {
    throw invalid(`An authorization's ${name} is hex of at most 32 bytes.`)
  }

  return word(integer)
}

/** viem's y parity, or a v of 0/1 or 27/28. */
const toRecovery = ({v, yParity}: {readonly v?: bigint; readonly yParity?: number}): 0 | 1 => {
  if (yParity === 0 || yParity === 1) {
    return yParity
  }

  if (yParity === undefined && (v === 0n || v === 27n || v === 1n || v === 28n)) {
    return v === 0n || v === 27n ? 0 : 1
  }

  throw invalid('An authorization in the list is signed: r, s and a y parity of 0 or 1 (or v).')
}

const fromViemAuthorization = (authorization: SignedAuthorization): EthereumAuthorization => {
  const {chainId, nonce, r, s} = authorization
  const address = authorization.address ?? (authorization as {contractAddress?: string}).contractAddress

  return {
    address,
    chainId,
    nonce,
    signature: {
      recovery: toRecovery(authorization),
      signature: new Uint8Array([...toWord(r, 'r'), ...toWord(s, 's')]),
    },
  }
}

/**
 * viem's `TransactionSerializable` as this adapter's request, with viem's defaults (a missing nonce, gas or fee is 0,
 * a missing `to` creates a contract). What viem would sign differently, or this adapter does not sign, is refused:
 * a blob transaction or a chain's own type (`UNSUPPORTED`), a legacy one without a chain id (viem would sign it
 * without EIP-155 replay protection), and an EIP-7702 one without a recipient.
 */
const fromViemTransaction = (transaction: TransactionSerializable): EthereumTransactionRequest => {
  let type: string

  try {
    type = getTransactionType(transaction)
  } catch {
    throw invalid('The transaction names no fees: gasPrice, or maxFeePerGas and maxPriorityFeePerGas.')
  }

  if (type === 'eip4844') {
    throw unsupported('EIP-4844 blob transactions (type 3) are not supported by this adapter.')
  }

  const {chainId, data, gas, nonce, to, value} = transaction
  const common = {chainId, data, gas: gas ?? 0n, nonce: nonce ?? 0, to: to ?? null, value}
  const fees = {
    maxFeePerGas: transaction.maxFeePerGas ?? 0n,
    maxPriorityFeePerGas: transaction.maxPriorityFeePerGas ?? 0n,
  }

  // viem's serializer throws for EIP-1559 fees on a gas price transaction, and ignores a gas price on an EIP-1559
  // one (a node's eth_fillTransaction may add it): the same here.
  if (
    (type === 'legacy' || type === 'eip2930') &&
    (transaction.maxFeePerGas !== undefined || transaction.maxPriorityFeePerGas !== undefined)
  ) {
    throw invalid(
      'A legacy or EIP-2930 transaction pays a gasPrice: maxFeePerGas and maxPriorityFeePerGas are EIP-1559`s.'
    )
  }

  switch (type) {
    case 'legacy':
      if (chainId === undefined) {
        throw invalid(
          'A legacy transaction without a chainId has no EIP-155 replay protection: this account does not sign one.'
        )
      }

      return {...common, gasPrice: transaction.gasPrice ?? 0n, type}
    case 'eip2930':
      return {...common, accessList: transaction.accessList, gasPrice: transaction.gasPrice ?? 0n, type}
    case 'eip1559':
      return {...common, ...fees, accessList: transaction.accessList, type}
    case 'eip7702':
      if (!to) {
        throw invalid('An EIP-7702 transaction has a recipient: it cannot create a contract.')
      }

      return {
        ...common,
        ...fees,
        accessList: transaction.accessList,
        authorizationList: (transaction.authorizationList ?? []).map(fromViemAuthorization),
        to,
        type,
      }
    default:
      throw unsupported(
        'The transaction type is not one this adapter signs: legacy, eip2930, eip1559 or eip7702. A chain`s own types (OP Stack deposits, CIP-64, zkSync EIP-712) are not supported.'
      )
  }
}

const viemKeccak256 = (data: Uint8Array): Uint8Array => keccak256(data, 'bytes')

const sameBytes = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()

/**
 * The account as a viem `LocalAccount` (through viem's `toAccount`): `address`, `publicKey`, `signMessage`,
 * `signTransaction`, `signTypedData` and `signAuthorization`, each signing in the engine with the account's checks,
 * and byte for byte what viem's `privateKeyToAccount` signs for the same key.
 *
 * ```ts
 * const client = createWalletClient({account: toViemAccount(account), chain: sepolia, transport: http()})
 * await client.sendTransaction({to, value})
 * ```
 *
 * - **No `sign({hash})`.** viem's raw-hash signing is `eth_sign`: a hash shows nothing of what it commits to (a
 *   transaction, a permit, an authorization), so a wallet cannot show the user what they sign. It is the classic
 *   phishing vector, and this account does not offer it. viem features that require it (some smart account owners)
 *   do not work with this account.
 * - **Chain ids.** Everything is bound to the account's network: a transaction, typed data domain or authorization
 *   for another chain id is `CHAIN_MISMATCH`. Use a client whose chain is the account's.
 * - **Custom serializers.** A chain with its own serializer (OP Stack chains such as Base and Optimism, Celo,
 *   zkSync) passes it to `signTransaction`. The account signs only what this adapter serializes, so it calls the
 *   serializer and requires the same bytes: unsigned before the key signs, and signed before the result is returned.
 *   Standard types on OP Stack chains pass. A chain's own transaction types (deposits, CIP-64, zkSync's EIP-712
 *   transactions), and anything else the serializer writes differently, are `UNSUPPORTED`.
 * - **Refused**, as the account refuses them: EIP-4844 blob transactions, a legacy transaction without a chain id
 *   (viem would sign it without replay protection), and authorizations for chain id 0 unless `allowAllChains` is set.
 */
export const toViemAccount = (account: EthereumAccount, options: ViemAccountOptions = {}): NitroViemAccount => {
  const network: EthereumNetwork = account.network

  const signTransaction: CustomSource['signTransaction'] = async (transaction, signOptions) => {
    const serializer = signOptions?.serializer
    const request = fromViemTransaction(transaction as TransactionSerializable)

    if (serializer) {
      const unsigned = await serializer(transaction)

      if (!sameBytes(unsigned, serializeTransaction(request, network, viemKeccak256))) {
        throw unsupported('The chain`s serializer writes this transaction differently than this adapter signs it.')
      }
    }

    const signed = await account.signTransaction(request)

    if (serializer) {
      const theirs = await serializer(transaction, toViemSignature(signed.signature))

      if (!sameBytes(theirs, signed.serialized)) {
        throw unsupported('The chain`s serializer writes this signed transaction differently than this adapter.')
      }
    }

    return signed.serialized
  }

  const signTypedData: CustomSource['signTypedData'] = async parameters => {
    const {domain, message, primaryType, types} = parameters as ViemTypedDataDefinition

    return account.signTypedData({
      domain,
      message: message ?? {},
      primaryType,
      types,
    } as TypedDataDefinition)
  }

  const viemAccount = toAccount({
    address: account.address,
    nonceManager: options.nonceManager,
    signAuthorization: async request => {
      const address = request.address ?? request.contractAddress
      const signed = await account.signAuthorization({
        address,
        allowAllChains: options.allowAllChains === true,
        chainId: request.chainId,
        nonce: request.nonce,
      })

      return {address, chainId: signed.chainId, nonce: request.nonce, ...toViemSignature(signed.signature)}
    },
    signMessage: async ({message}: {message: SignableMessage}) =>
      account.signMessage({
        message:
          typeof message === 'string'
            ? message
            : typeof message.raw === 'string'
              ? hex.decode(message.raw)
              : message.raw,
      }),
    signTransaction,
    signTypedData,
  })

  return {...viemAccount, publicKey: account.publicKey, sign: undefined, source: 'nitro-crypto' as const}
}
