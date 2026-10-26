import type {StateCreator} from 'zustand'

import type {PairedSigner, ScannedRequest} from '../../core'

export type SignerSlice = {
  /** A request this wallet scanned and read, between the scanner and the review screen. */
  incoming: ScannedRequest | null
  setIncoming: (request: ScannedRequest) => void
  clearIncoming: () => void
}

export type WatchSlice = {
  /** The signer a watch-only session paired with: its public keys and paths. */
  paired: PairedSigner | null
  setPaired: (signer: PairedSigner) => void
  unpair: () => void
}

export type AirgapStore = SignerSlice & WatchSlice

type Creator<Slice> = StateCreator<AirgapStore, [['zustand/immer', never]], [], Slice>

export type CreateSignerSlice = Creator<SignerSlice>
export type CreateWatchSlice = Creator<WatchSlice>
