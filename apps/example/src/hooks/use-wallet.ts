import {useEffect, useMemo} from 'react'
import {AppState} from 'react-native'
import {initializeWallet, lockWallet, type WalletAccounts, walletServices} from '../core'
import {type AutoLock, useSessionStore, useWalletStore, type WalletRecord} from '../store'

/** How long each auto-lock setting lets the app sit in the background before the keys go. */
export const AUTO_LOCK_MS: Readonly<Record<AutoLock, number>> = {
  'five-minutes': 5 * 60_000,
  immediately: 0,
  minute: 60_000,
}

/**
 * Mounted once, at the root: decides where the app starts, follows its foreground state, and locks the wallet after
 * the time away its auto-lock setting allows.
 */
export const useWalletLifecycle = () => {
  useEffect(() => {
    initializeWallet()
  }, [])

  useEffect(() => {
    let backgroundAt: number | null = null
    const subscription = AppState.addEventListener('change', next => {
      useSessionStore.getState().setAppState(next)
      const {autoLock} = useWalletStore.getState()

      if (next === 'background') {
        backgroundAt = Date.now()
        if (autoLock === 'immediately') {
          lockWallet('timeout')
        }
      }
      if (next === 'active') {
        const away = backgroundAt === null ? 0 : Date.now() - backgroundAt
        backgroundAt = null
        if (away > AUTO_LOCK_MS[autoLock]) {
          lockWallet('timeout')
        }
      }
    })

    return () => subscription.remove()
  }, [])
}

export const useWalletStatus = () => useSessionStore.use.status()

/** The unlocked wallet's accounts; `null` while it is locked or absent. */
export const useAccounts = (): WalletAccounts | null => useSessionStore.use.accounts() as WalletAccounts | null

export const useRecord = (): WalletRecord | null => useWalletStore.use.record() as WalletRecord | null

/** The accounts, the record and the network services together, for screens that exist only while unlocked. */
export const useUnlockedWallet = () => {
  const accounts = useAccounts()
  const record = useRecord()

  return useMemo(() => {
    const services = walletServices()
    return accounts && record && services ? {accounts, record, services} : null
  }, [accounts, record])
}
