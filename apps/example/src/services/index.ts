import type {ChainId, WalletCrypto} from '../core'
import {bitcoinService} from './bitcoin'
import {ethereumService} from './ethereum'
import {solanaService} from './solana'
import type {ChainService} from './types'

export type Services = {
  readonly ethereum: ChainService<'ethereum'>
  readonly bitcoin: ChainService<'bitcoin'>
  readonly solana: ChainService<'solana'>
}

/** Each chain's network access, over the adapters the engine bound: they build and sign, these talk to the network. */
export const createServices = (crypto: WalletCrypto): Services => ({
  bitcoin: bitcoinService(crypto.chains.bitcoin),
  ethereum: ethereumService(crypto.chains.ethereum, crypto.random),
  solana: solanaService(crypto.chains.solana, crypto.random),
})

/** The service for a chain the caller holds as a union: one cast, here, instead of one per call site. */
export const serviceFor = <Id extends ChainId>(services: Services, chain: Id) =>
  services[chain] as unknown as ChainService<Id>

export {NetworkError} from './http'
export {AIRGAP_ORIGIN} from './origin'
export {fetchPrices, type Prices} from './prices'
export type {
  ActivityItem,
  AirgapQuote,
  ChainService,
  Holding,
  Quote,
  SendRequest,
  TransactionStatus,
  WatchAccount,
} from './types'
