import {createRequestId} from '@hzblj/crypto-airgap'
import {ethereumAirgap} from '@hzblj/crypto-airgap-ethereum'
import type {EthereumChain, EthereumTransactionRequest, Hex} from '@hzblj/crypto-ethereum'

import {NETWORKS} from '../config'
import {formatUnits} from '../utils'
import {getJson, NetworkError, rpc, rpcBatch} from './http'
import {AIRGAP_ORIGIN} from './origin'
import type {ActivityItem, ChainService, SendRequest, TransactionStatus} from './types'

const network = NETWORKS.ethereum
const GWEI = 1_000_000_000n
/** Sepolia's suggested tip is often a few wei; a gwei gets a transaction into the next blocks for a negligible fee. */
const MIN_TIP = GWEI

const toQuantity = (value: bigint): Hex => `0x${value.toString(16)}`

type Block = {readonly baseFeePerGas?: Hex}
type Receipt = {readonly status: Hex} | null

type ExplorerAddress = {readonly hash: string} | null
type ExplorerTransaction = {
  readonly hash: string
  readonly from: ExplorerAddress
  readonly to: ExplorerAddress
  readonly value: string
  readonly timestamp: string | null
  readonly status: 'ok' | 'error' | null
}
type ExplorerTransfer = {
  readonly transaction_hash: string
  readonly log_index: number
  readonly from: ExplorerAddress
  readonly to: ExplorerAddress
  readonly timestamp: string | null
  readonly token: {readonly address_hash: string; readonly symbol: string | null; readonly decimals: string | null}
  readonly total: {readonly value: string; readonly decimals: string | null}
}
type Page<T> = {readonly items: readonly T[]}

/** Blockscout answers 404 for an address it has never seen: no history, not an error. */
const explorerPage = async <T>(path: string): Promise<readonly T[]> => {
  try {
    return (await getJson<Page<T>>(`${network.indexer}${path}`)).items
  } catch (error) {
    if (error instanceof NetworkError && /not found/i.test(error.message)) {
      return []
    }
    throw error
  }
}

const same = (a: string | undefined, b: string) => a?.toLowerCase() === b.toLowerCase()

const directionOf = (address: string, from: ExplorerAddress, to: ExplorerAddress): ActivityItem['direction'] => {
  if (same(from?.hash, address)) {
    return same(to?.hash, address) ? 'self' : 'out'
  }
  return 'in'
}

const timeOf = (timestamp: string | null) => (timestamp ? Date.parse(timestamp) : undefined)

const statusOf = (status: ExplorerTransaction['status']): TransactionStatus =>
  status === 'ok' ? 'confirmed' : status === 'error' ? 'failed' : 'pending'

const activity = async (address: string): Promise<ActivityItem[]> => {
  const [transactions, transfers] = await Promise.all([
    explorerPage<ExplorerTransaction>(`/addresses/${address}/transactions`),
    explorerPage<ExplorerTransfer>(`/addresses/${address}/token-transfers?type=ERC-20`),
  ])
  const statuses = new Map(transactions.map(transaction => [transaction.hash, statusOf(transaction.status)]))
  const withTransfers = new Set(transfers.map(transfer => transfer.transaction_hash))

  const tokens = transfers.map((transfer): ActivityItem => {
    const listed = network.tokens.find(token => same(token.contract, transfer.token.address_hash))
    const direction = directionOf(address, transfer.from, transfer.to)

    return {
      amount: BigInt(transfer.total.value),
      asset: listed ?? {
        decimals: Number(transfer.token.decimals ?? transfer.total.decimals ?? 18),
        symbol: transfer.token.symbol ?? 'ERC-20',
      },
      chain: 'ethereum',
      counterparty: (direction === 'in' ? transfer.from?.hash : transfer.to?.hash) ?? undefined,
      direction,
      hash: transfer.transaction_hash,
      id: `ethereum:${transfer.transaction_hash}:${transfer.log_index}`,
      status: statuses.get(transfer.transaction_hash) ?? 'confirmed',
      timestamp: timeOf(transfer.timestamp),
    }
  })

  // A token transfer's own transaction moves no ether: list the token, not a "0 ETH" beside it.
  const coins = transactions
    .filter(transaction => transaction.value !== '0' || !withTransfers.has(transaction.hash))
    .map((transaction): ActivityItem => {
      const direction = directionOf(address, transaction.from, transaction.to)

      return {
        amount: BigInt(transaction.value),
        asset: network.native,
        chain: 'ethereum',
        counterparty: (direction === 'in' ? transaction.from?.hash : transaction.to?.hash) ?? undefined,
        direction,
        hash: transaction.hash,
        id: `ethereum:${transaction.hash}`,
        status: statusOf(transaction.status),
        timestamp: timeOf(transaction.timestamp),
      }
    })

  return [...coins, ...tokens]
}

const prepare = async (chain: EthereumChain, address: string, {amount, asset, to}: SendRequest) => {
  const recipient = chain.validateAddress(to)

  if (!recipient.valid) {
    throw new NetworkError(recipient.reason)
  }

  const token = asset.contract
  const [nonce, block, tip, balance, tokenBalance] = (await rpcBatch(network.endpoint, [
    {method: 'eth_getTransactionCount', params: [address, 'pending']},
    {method: 'eth_getBlockByNumber', params: ['latest', false]},
    {method: 'eth_maxPriorityFeePerGas', params: []},
    {method: 'eth_getBalance', params: [address, 'latest']},
    ...(token ? [{method: 'eth_call', params: [{data: chain.erc20.balanceOfData(address), to: token}, 'latest']}] : []),
  ])) as [Hex, Block, Hex, Hex, Hex | undefined]

  const ether = BigInt(balance)
  const held = token ? chain.erc20.decodeUint256(tokenBalance ?? '0x') : ether
  const baseFee = BigInt(block.baseFeePerGas ?? '0x0')
  const maxPriorityFeePerGas = BigInt(tip) > MIN_TIP ? BigInt(tip) : MIN_TIP
  // Twice the base fee rides out six full blocks of increases; the unused part is never charged.
  const maxFeePerGas = baseFee * 2n + maxPriorityFeePerGas
  const sending = amount === 'max' ? (token ? held : 0n) : amount
  const data = token ? chain.erc20.transferData(recipient.normalized, sending) : undefined
  const estimate = BigInt(
    await rpc<Hex>(network.endpoint, 'eth_estimateGas', [
      {data, from: address, to: token ?? recipient.normalized, value: token ? '0x0' : toQuantity(0n)},
    ])
  )
  // A token transfer's cost depends on storage the estimate cannot see coming; a fifth more covers it.
  const gas = token ? (estimate * 6n) / 5n : estimate
  const fee = gas * maxFeePerGas
  const value = token ? 0n : amount === 'max' ? ether - fee : sending

  if (value < 0n || (!token && value + fee > ether)) {
    throw new NetworkError(
      `Not enough ETH: this needs ${formatUnits(value + fee, 18)} ETH with the fee, the wallet has ${formatUnits(ether, 18)}.`
    )
  }
  if (token && (sending > held || fee > ether)) {
    throw new NetworkError(
      sending > held
        ? `Not enough ${asset.symbol}: the wallet has ${formatUnits(held, asset.decimals)}.`
        : `The fee is paid in ETH: this needs ${formatUnits(fee, 18)} ETH, the wallet has ${formatUnits(ether, 18)}.`
    )
  }

  const request: EthereumTransactionRequest = {
    data,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    nonce: BigInt(nonce),
    to: token ?? recipient.normalized,
    value,
  }

  return {
    amount: token ? sending : value,
    details: [
      {label: 'Network', value: `${network.testnet}, chain id ${chain.network.chainId}`},
      {label: 'Nonce', value: BigInt(nonce).toString()},
      {label: 'Gas limit', value: gas.toString()},
      {label: 'Max fee per gas', value: `${formatUnits(maxFeePerGas, 9, 3)} gwei`},
      {label: 'Transaction type', value: 'EIP-1559'},
    ],
    fee,
    request,
  }
}

export const ethereumService = (
  chain: EthereumChain,
  random: (length: number) => Uint8Array
): ChainService<'ethereum'> => {
  const airgap = ethereumAirgap(chain)

  return {
    activity,
    airgapQuote: async (account, send) => {
      const {request: transaction, ...quote} = await prepare(chain, account.address, send)
      const request = {account, origin: AIRGAP_ORIGIN, requestId: createRequestId(random), transaction}

      return {
        ...quote,
        complete: async answer => {
          const response = airgap.decodeSignResponse(answer, {request})

          if (response.kind !== 'transaction') {
            throw new NetworkError('The signer answered with a message signature, not a transaction.')
          }

          return rpc<Hex>(network.endpoint, 'eth_sendRawTransaction', [response.transaction.serialized])
        },
        request: airgap.encodeSignRequest(request),
      }
    },
    holdings: async address => {
      const results = (await rpcBatch(network.endpoint, [
        {method: 'eth_getBalance', params: [address, 'latest']},
        ...network.tokens.map(token => ({
          method: 'eth_call',
          params: [{data: chain.erc20.balanceOfData(address), to: token.contract}, 'latest'],
        })),
      ])) as Hex[]

      return [
        {asset: network.native, balance: BigInt(results[0] ?? '0x0')},
        ...network.tokens.map((asset, index) => ({
          asset,
          balance: chain.erc20.decodeUint256(results[index + 1] ?? '0x'),
        })),
      ]
    },
    quote: async (account, send) => {
      const {request, ...quote} = await prepare(chain, account.address, send)

      return {
        ...quote,
        send: async () => {
          const signed = await account.signTransaction(request)

          return rpc<Hex>(network.endpoint, 'eth_sendRawTransaction', [signed.serialized])
        },
      }
    },
    status: async hash => {
      const receipt = await rpc<Receipt>(network.endpoint, 'eth_getTransactionReceipt', [hash])

      if (!receipt) {
        return 'pending'
      }
      return receipt.status === '0x1' ? 'confirmed' : 'failed'
    },
  }
}
