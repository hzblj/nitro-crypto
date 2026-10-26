import type {AppStateStatus} from 'react-native'
import type {StateCreator} from 'zustand'

import type {WalletAccounts} from '../../core'

export type WalletStatus = 'loading' | 'unavailable' | 'empty' | 'locked' | 'unlocked'

/** Why the wallet is locked: opened from cold, locked after time away, or by hand (no prompt follows that). */
export type LockReason = 'launch' | 'timeout' | 'manual'

export type LockSlice = {
  status: WalletStatus
  lockReason: LockReason
  /** What went wrong the last time it tried to unlock, for the lock screen. */
  problem: string | null
  /** The Keychain no longer has the phrase: only the written copy restores the wallet. */
  lost: boolean
  /** The unlocked wallet's accounts; `null` whenever the keys are not in the engine. */
  accounts: WalletAccounts | null
  setUnavailable: (problem: string) => void
  setEmpty: () => void
  setLocked: (reason: LockReason, problem?: string, lost?: boolean) => void
  setUnlocked: (accounts: WalletAccounts) => void
}

export type AppSlice = {
  appState: AppStateStatus
  /** System prompts (Face ID, the passcode) open now: they make the app inactive without leaving it. */
  prompting: number
  setAppState: (appState: AppStateStatus) => void
  beginPrompt: () => void
  endPrompt: () => void
}

export type SessionStore = LockSlice & AppSlice

type Creator<Slice> = StateCreator<SessionStore, [['zustand/immer', never]], [], Slice>

export type CreateLockSlice = Creator<LockSlice>
export type CreateAppSlice = Creator<AppSlice>
