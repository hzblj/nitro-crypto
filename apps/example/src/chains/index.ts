import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {solanaAdapter} from '@hzblj/crypto-solana'

import {tronAdapter} from './tron'

/**
 * The chains the example registers: the three published adapters, and TRON from this app's own source. The app's
 * engine (src/crypto.ts) and its tests (test/) take the same list.
 */
export const createAdapters = () => [ethereumAdapter(), bitcoinAdapter(), solanaAdapter(), tronAdapter()] as const

export type {TronAccount} from './tron'
