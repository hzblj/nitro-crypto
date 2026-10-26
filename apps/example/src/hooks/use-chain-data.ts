import {useEffect, useMemo} from 'react'
import {findAsset, NETWORKS} from '../config'
import {type ChainId, walletServices} from '../core'
import {type ActivityItem, fetchPrices, type Holding, serviceFor} from '../services'
import {type PendingTransaction, useWalletStore} from '../store'
import {usdValue} from '../utils'
import {useRemote} from './use-remote'
import {useAccounts} from './use-wallet'

const EMPTY: readonly ActivityItem[] = []

/** What one chain's address holds: its coin first, then its tokens. */
export const useHoldings = (chain: ChainId) => {
  const address = useAccounts()?.[chain].address

  return useRemote<Holding[]>(address ? `holdings:${chain}:${address}` : null, () => {
    const services = walletServices()
    return services && address ? serviceFor(services, chain).holdings(address) : Promise.resolve([])
  })
}

export const useActivity = (chain: ChainId) => {
  const address = useAccounts()?.[chain].address

  return useRemote<ActivityItem[]>(address ? `activity:${chain}:${address}` : null, () => {
    const services = walletServices()
    return services && address ? serviceFor(services, chain).activity(address) : Promise.resolve([])
  })
}

/** Mainnet prices, refreshed every two minutes at most: CoinGecko's free tier is rate limited. */
export const usePrices = () => useRemote('prices', fetchPrices, 120_000)

export type ChainSummary = {
  readonly chain: ChainId
  readonly holdings: readonly Holding[] | undefined
  /** The chain's coin, in its smallest unit. */
  readonly balance: bigint | undefined
  /** Every holding at mainnet prices. */
  readonly usd: number | undefined
  readonly loading: boolean
  readonly error: string | undefined
}

type Prices = Readonly<Record<string, number>> | undefined

const summarize = (
  chain: ChainId,
  holdings: readonly Holding[] | undefined,
  prices: Prices,
  loading: boolean,
  error: string | undefined
): ChainSummary => {
  const usd = holdings?.reduce<number | undefined>((total, {asset, balance}) => {
    const value = usdValue(balance, asset.decimals, prices?.[asset.priceId])
    return value === undefined || total === undefined ? total : total + value
  }, 0)

  return {
    balance: holdings?.find(holding => holding.asset.id === NETWORKS[chain].native.id)?.balance,
    chain,
    error,
    holdings,
    loading,
    usd: prices ? usd : undefined,
  }
}

/** Every chain's holdings and their total at mainnet prices: the home screen. */
export const usePortfolio = () => {
  const ethereum = useHoldings('ethereum')
  const bitcoin = useHoldings('bitcoin')
  const solana = useHoldings('solana')
  const prices = usePrices()

  const chains = useMemo(
    () => [
      summarize('ethereum', ethereum.data, prices.data, ethereum.loading, ethereum.error),
      summarize('bitcoin', bitcoin.data, prices.data, bitcoin.loading, bitcoin.error),
      summarize('solana', solana.data, prices.data, solana.loading, solana.error),
    ],
    [
      bitcoin.data,
      bitcoin.error,
      bitcoin.loading,
      ethereum.data,
      ethereum.error,
      ethereum.loading,
      prices.data,
      solana.data,
      solana.error,
      solana.loading,
    ]
  )
  const total = useMemo(
    () =>
      chains.every(chain => chain.usd !== undefined)
        ? chains.reduce((sum, chain) => sum + (chain.usd ?? 0), 0)
        : undefined,
    [chains]
  )

  return {
    chains,
    loading: chains.some(chain => chain.loading) || prices.loading,
    prices: prices.data,
    refresh: () => Promise.all([ethereum.refresh(), bitcoin.refresh(), solana.refresh(), prices.refresh()]),
    total,
  }
}

/** A transaction this device broadcast, as a history row until the network's history lists it. */
const pendingItem = (transaction: PendingTransaction): ActivityItem => {
  const asset = findAsset(transaction.assetId) ?? NETWORKS[transaction.chain].native

  return {
    amount: transaction.amount,
    asset,
    chain: transaction.chain,
    counterparty: transaction.to,
    direction: 'out',
    hash: transaction.hash,
    id: `pending:${transaction.hash}`,
    status: 'pending',
  }
}

const newestFirst = (a: ActivityItem, b: ActivityItem) =>
  (b.timestamp ?? Number.MAX_SAFE_INTEGER) - (a.timestamp ?? Number.MAX_SAFE_INTEGER)

/**
 * Every chain's history, newest first, with what this device sent and no explorer lists yet on top. A sent
 * transaction that shows up in the network's history stops being pending here.
 */
export const useAllActivity = () => {
  const ethereum = useActivity('ethereum')
  const bitcoin = useActivity('bitcoin')
  const solana = useActivity('solana')
  const pending = useWalletStore.use.pending()
  const settlePending = useWalletStore.use.settlePending()

  const fetched = useMemo(
    () => [...(ethereum.data ?? EMPTY), ...(bitcoin.data ?? EMPTY), ...(solana.data ?? EMPTY)],
    [ethereum.data, bitcoin.data, solana.data]
  )
  const listed = useMemo(() => new Set(fetched.map(item => item.hash)), [fetched])

  useEffect(() => {
    const settled = pending.filter(transaction => listed.has(transaction.hash)).map(transaction => transaction.hash)
    if (settled.length > 0) {
      settlePending(settled)
    }
  }, [listed, pending, settlePending])

  const items = useMemo(
    () => [
      ...pending.filter(transaction => !listed.has(transaction.hash)).map(pendingItem),
      ...[...fetched].sort(newestFirst),
    ],
    [fetched, listed, pending]
  )
  const errors = useMemo(
    () => [ethereum.error, bitcoin.error, solana.error].filter((error): error is string => error !== undefined),
    [ethereum.error, bitcoin.error, solana.error]
  )

  return {
    errors,
    items,
    loading: ethereum.loading || bitcoin.loading || solana.loading,
    refresh: () => Promise.all([ethereum.refresh(), bitcoin.refresh(), solana.refresh()]),
  }
}
