import {CryptoError} from '@hzblj/nitro-crypto/adapter'

export type EthereumConfig<Id extends string = 'ethereum'> = {
  /** The id it registers under: give each EVM network its own (`base`, `sepolia`) to register several. */
  readonly id?: Id
  /** For people. Defaults to "Ethereum". */
  readonly name?: string
  /**
   * The EIP-155 chain id. Accounts are the same address on every EVM network; the chain id says which network an
   * account is presented on, and is what later transaction signing binds to. Defaults to 1, Ethereum mainnet.
   */
  readonly chainId?: number
}

export type EthereumNetwork = {readonly chainId: number; readonly name: string}

export const resolveConfig = <Id extends string>(config: EthereumConfig<Id>) => {
  const chainId = config.chainId ?? 1

  if (!Number.isSafeInteger(chainId) || chainId < 1) {
    throw new CryptoError('INVALID_CONFIG', 'An EVM chain id is a positive integer.')
  }

  const name = config.name ?? 'Ethereum'

  if (name.trim() === '') {
    throw new CryptoError('INVALID_CONFIG', 'An Ethereum adapter needs a name.')
  }

  return {id: (config.id ?? 'ethereum') as Id, network: Object.freeze({chainId, name})}
}

/**
 * The chain id a request names, bound to the network: left out, it is the network's; any other is `CHAIN_MISMATCH`,
 * so an adapter configured for one network never signs for another. The message names the adapter's chain id, never
 * the request's.
 */
export const networkChainId = (value: unknown, network: EthereumNetwork, subject: string): number => {
  if (value === undefined) {
    return network.chainId
  }

  const chainId =
    typeof value === 'bigint' ? value : typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) : -1n

  if (chainId < 0n) {
    throw new CryptoError('INVALID_ARGUMENT', `The chain id of ${subject} is a non-negative integer.`)
  }

  if (chainId !== BigInt(network.chainId)) {
    throw chainMismatch(network, subject)
  }

  return network.chainId
}

export const chainMismatch = (network: EthereumNetwork, subject: string) =>
  new CryptoError(
    'CHAIN_MISMATCH',
    `${subject} is for another chain than this adapter's, chain id ${network.chainId} (${network.name}).`
  )
