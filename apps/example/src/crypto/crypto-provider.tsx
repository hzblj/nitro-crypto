import {
  type AccountOf,
  type ChainsOf,
  type CryptoEngine,
  CryptoError,
  createCryptoEngine,
  type EphemeralWallet,
  isCryptoError,
  type WalletOptions,
} from '@hzblj/nitro-crypto'
import {createContext, type ReactNode, useCallback, useContext, useMemo, useRef, useState} from 'react'

import {createAdapters} from '../chains'

type Chains = ChainsOf<ReturnType<typeof createAdapters>>
export type AppCrypto = CryptoEngine<Chains>
export type ChainId = keyof Chains & string
export type AppWallet = EphemeralWallet<Chains>
export type AppAccount<Id extends ChainId> = AccountOf<Chains[Id]>

export type WalletSummary = {
  readonly createdAt: Date
  readonly fingerprint: number
  readonly origin: AppWallet['origin']
  readonly words: number
}

/** One engine for the app: created once, on first use, so a missing native module is a message and not a crash. */
const createEngine = (): {crypto: AppCrypto} | {error: CryptoError} => {
  try {
    return {crypto: createCryptoEngine({adapters: createAdapters()})}
  } catch (error) {
    return {error: isCryptoError(error) ? error : new CryptoError('NATIVE_UNAVAILABLE', undefined, {cause: error})}
  }
}

/**
 * The account each chain shows as "number n": the convention its wallets use for a list of accounts. Ethereum wallets
 * count addresses (`m/44'/60'/0'/0/n`), Bitcoin's receiving addresses of the first account; Solana's and TRON's count
 * accounts. Each screen shows the resulting path, so nothing about it is hidden.
 */
export const requestFor = (chain: ChainId, n: number) => {
  switch (chain) {
    case 'ethereum':
    case 'bitcoin':
      return {index: n}
    default:
      return {account: n}
  }
}

type CryptoContextValue = {
  readonly crypto: AppCrypto | null
  readonly error: CryptoError | null
  readonly wallet: WalletSummary | null
  /** Seeds and keys alive in the engine, read on every change the app makes. */
  readonly liveHandles: number
  readonly createWallet: (options?: WalletOptions) => Promise<void>
  /** Disposes the wallet; returns how many native secrets were zeroized. */
  readonly deleteWallet: () => number
  /** The `n`th account of `chain`, derived once per wallet and then cached. */
  readonly account: <Id extends ChainId>(chain: Id, n: number) => Promise<AppAccount<Id>>
}

const CryptoContext = createContext<CryptoContextValue | null>(null)

export const CryptoProvider = ({children}: {children: ReactNode}) => {
  const engine = useMemo(createEngine, [])
  const crypto = 'crypto' in engine ? engine.crypto : null
  const engineError = 'error' in engine ? engine.error : null
  const wallet = useRef<AppWallet | null>(null)
  const accounts = useRef(new Map<string, Promise<unknown>>())
  const [summary, setSummary] = useState<WalletSummary | null>(null)
  const [liveHandles, setLiveHandles] = useState(() => crypto?.liveHandles() ?? 0)
  const refresh = useCallback(() => setLiveHandles(crypto?.liveHandles() ?? 0), [crypto])

  const deleteWallet = useCallback(() => {
    const before = crypto?.liveHandles() ?? 0
    wallet.current?.dispose()
    wallet.current = null
    accounts.current.clear()
    setSummary(null)
    refresh()
    return before - (crypto?.liveHandles() ?? 0)
  }, [crypto, refresh])

  const createWallet = useCallback(
    async (options?: WalletOptions) => {
      if (!crypto) {
        throw engineError ?? new CryptoError('NATIVE_UNAVAILABLE')
      }
      const created = await crypto.createEphemeralWallet(options)
      // Whichever wallet is current once this one exists goes, zeroized: two creations in flight (a double tap) each
      // replace the one before, and none is left behind in the engine.
      wallet.current?.dispose()
      accounts.current.clear()
      wallet.current = created
      setSummary({
        createdAt: new Date(),
        fingerprint: created.fingerprint,
        origin: created.origin,
        words: created.words,
      })
      refresh()
    },
    [crypto, engineError, refresh]
  )

  const account = useCallback(
    <Id extends ChainId>(chain: Id, n: number): Promise<AppAccount<Id>> => {
      const current = wallet.current
      if (!current) {
        return Promise.reject(new CryptoError('DISPOSED', 'Create a demo wallet first.'))
      }
      const key = `${chain}:${n}`
      let cached = accounts.current.get(key)
      if (!cached) {
        // Every chain's request takes the counting field `requestFor` picks for it.
        cached = current.deriveAccount({chain, ...requestFor(chain, n)} as Parameters<AppWallet['deriveAccount']>[0])
        cached.then(refresh, () => accounts.current.delete(key))
        accounts.current.set(key, cached)
      }
      return cached as Promise<AppAccount<Id>>
    },
    [refresh]
  )

  const value = useMemo<CryptoContextValue>(
    () => ({
      account,
      createWallet,
      crypto,
      deleteWallet,
      error: engineError,
      liveHandles,
      wallet: summary,
    }),
    [account, createWallet, crypto, deleteWallet, engineError, liveHandles, summary]
  )

  return <CryptoContext.Provider value={value}>{children}</CryptoContext.Provider>
}

export const useCrypto = (): CryptoContextValue => {
  const value = useContext(CryptoContext)
  if (!value) {
    throw new Error('useCrypto needs a CryptoProvider')
  }
  return value
}
