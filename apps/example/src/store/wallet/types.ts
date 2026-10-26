import type {StateCreator} from 'zustand'

import type {ChainId} from '../../core'

/**
 * How the stored recovery phrase is guarded:
 * - `biometrics`: the Keychain (Keystore on Android) item itself requires Face ID or a fingerprint to be read;
 * - `passcode`: the item is readable while the device is unlocked, and the app asks for the device passcode first;
 * - `none`: a device without either (a simulator), where only the Keychain's this-device-only rule applies.
 */
export type Protection = 'biometrics' | 'passcode' | 'none'

/** What is known about the wallet without unlocking it: nothing secret. The phrase itself is in the Keychain. */
export type WalletRecord = {
  readonly createdAt: Date
  /** The seed's BIP-32 fingerprint, hex: how an unlocked wallet proves it is this one. */
  readonly fingerprint: string
  readonly words: number
  readonly origin: 'created' | 'imported'
  readonly protection: Protection
  /** "Face ID", "Touch ID", "Biometrics", "Passcode", "None": what the screens call it. */
  readonly method: string
}

/** How long the app may sit in the background before the keys are wiped from the engine. */
export type AutoLock = 'immediately' | 'minute' | 'five-minutes'

/** A transaction this device broadcast, shown in the history until the network's own history lists it. */
export type PendingTransaction = {
  readonly chain: ChainId
  readonly hash: string
  readonly assetId: string
  readonly amount: bigint
  readonly to: string
  readonly sentAt: Date
}

export type RecordSlice = {
  record: WalletRecord | null
  setRecord: (record: WalletRecord) => void
}

export type SettingsSlice = {
  autoLock: AutoLock
  setAutoLock: (autoLock: AutoLock) => void
}

export type PendingSlice = {
  pending: PendingTransaction[]
  addPending: (transaction: PendingTransaction) => void
  /** Drops the hashes the network's history now lists, or that settled. */
  settlePending: (hashes: readonly string[]) => void
}

export type WalletStore = RecordSlice &
  SettingsSlice &
  PendingSlice & {
    /** Back to a device without a wallet: the record, the settings and the pending transactions. */
    resetWallet: () => void
  }

type Creator<Slice> = StateCreator<WalletStore, [['zustand/immer', never]], [], Slice>

export type CreateRecordSlice = Creator<RecordSlice>
export type CreateSettingsSlice = Creator<SettingsSlice>
export type CreatePendingSlice = Creator<PendingSlice>
