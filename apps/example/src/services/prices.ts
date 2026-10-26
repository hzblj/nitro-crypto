import {NETWORKS} from '../config'
import {getJson} from './http'

/** Dollars per coin, by CoinGecko id. */
export type Prices = Readonly<Record<string, number>>

const IDS = [
  ...new Set(
    Object.values(NETWORKS).flatMap(network => [network.native, ...network.tokens].map(asset => asset.priceId))
  ),
]

/**
 * Mainnet prices for the testnet coins: what the balances would be worth there, so the dashboard reads like a real
 * wallet's. Testnet coins themselves are worth nothing, and the screen says so.
 */
export const fetchPrices = async (): Promise<Prices> => {
  const answer = await getJson<Record<string, {usd?: number}>>(
    `https://api.coingecko.com/api/v3/simple/price?ids=${IDS.join(',')}&vs_currencies=usd`
  )

  return Object.fromEntries(
    Object.entries(answer).flatMap(([id, quote]) => (quote.usd === undefined ? [] : [[id, quote.usd]]))
  )
}
