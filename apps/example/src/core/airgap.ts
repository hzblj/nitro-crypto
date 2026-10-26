import {AirgapError, CRYPTO_HDKEY, CRYPTO_MULTI_ACCOUNTS, fromUR, type HDKey, toUR, type UR} from '@hzblj/crypto-airgap'
import {type BitcoinSignRequest, bitcoinAirgap} from '@hzblj/crypto-airgap-bitcoin'
import {type EthereumAirgapAccount, type EthereumSignRequest, ethereumAirgap} from '@hzblj/crypto-airgap-ethereum'
import {type SolanaAirgapAccount, type SolanaSignRequest, solanaAirgap} from '@hzblj/crypto-airgap-solana'
import type {BitcoinWatchRequest} from '@hzblj/crypto-bitcoin'
import type {ExtendedPublicKey} from '@hzblj/nitro-crypto'

import type {ChainAccount, WalletAccounts, WalletCrypto} from './chains'

/** What this wallet signs when it is the offline side: a PSBT, an ERC-4527 request, a Solana sign request. */
export const SIGN_REQUEST_TYPES = ['crypto-psbt', 'eth-sign-request', 'sol-sign-request'] as const

/**
 * What a watch-only wallet reads to pair with a signer: this wallet's accounts, or a hardware wallet's (Keystone and
 * OneKey share `crypto-multi-accounts`, an Ethereum account as `crypto-hdkey`, Bitcoin accounts as `crypto-account`).
 */
export const PAIRING_TYPES = ['crypto-multi-accounts', 'crypto-hdkey', 'crypto-account'] as const

/**
 * Who the pairing code is for: a watch-only Nitro Wallet (every chain), Sparrow and other Bitcoin coordinators (the
 * Bitcoin account, `crypto-account`), or MetaMask and other Ethereum wallets that take QR hardware wallets (the
 * Ethereum account, `crypto-hdkey`).
 */
export type PairingFormat = 'nitro' | 'sparrow' | 'metamask'

/** The name a pairing gives this wallet, which a watch-only wallet shows. */
const DEVICE = 'Nitro Wallet'

/** A request this wallet scanned, read for its own account on that chain: what the review screen shows. */
export type ScannedRequest =
  | {readonly chain: 'bitcoin'; readonly request: BitcoinSignRequest}
  | {readonly chain: 'ethereum'; readonly request: EthereumSignRequest}
  | {readonly chain: 'solana'; readonly request: SolanaSignRequest}

/** A signer a watch-only wallet paired with: public keys and paths only, as plain data. */
export type PairedSigner = {
  readonly fingerprint: number
  readonly device?: string
  readonly bitcoin?: BitcoinWatchRequest
  readonly ethereum?: EthereumAirgapAccount
  readonly solana?: SolanaAirgapAccount
}

const adapters = new WeakMap<WalletCrypto, ReturnType<typeof createAirgaps>>()

const createAirgaps = (crypto: WalletCrypto) => ({
  bitcoin: bitcoinAirgap(crypto.chains.bitcoin),
  ethereum: ethereumAirgap(crypto.chains.ethereum),
  solana: solanaAirgap(crypto.chains.solana),
})

/** Each chain's air-gap adapter, bound to the wallet engine's chains: once per engine. */
export const airgapsOf = (crypto: WalletCrypto) => {
  let airgaps = adapters.get(crypto)

  if (!airgaps) {
    airgaps = createAirgaps(crypto)
    adapters.set(crypto, airgaps)
  }

  return airgaps
}

/** The fingerprint the wallet record keeps as hex, as the number requests carry. */
export const fingerprintOf = (hex: string) => Number.parseInt(hex, 16)

/** The account an address belongs to: its path without `change/index` (`m/84'/1'/0'/0/0` is in `m/84'/1'/0'`). */
export const accountPathOf = (path: string) => path.split('/').slice(0, -2).join('/')

/** The wallet's keys a signature may need, derived on demand at the path a request names, once checked. */
export type AccountsAt = {
  readonly bitcoin: (path: string) => Promise<ChainAccount<'bitcoin'>>
  readonly ethereum: (path: string) => Promise<ChainAccount<'ethereum'>>
}

/**
 * The wallet as a signer shares it to pair, for the wallet `format` names. Its Bitcoin and Ethereum accounts go out as
 * extended public keys (`extendedPublicKey`, the account's public key and chain code), from which the other wallet
 * derives every address of the account; its Solana account (Ed25519, which has no public derivation) as one key.
 * Public keys only: nothing here can spend.
 */
export const pairingRequest = (
  crypto: WalletCrypto,
  accounts: WalletAccounts,
  fingerprint: number,
  format: PairingFormat,
  extendedPublicKey: (path: string) => ExtendedPublicKey
): UR => {
  const {bitcoin, ethereum, solana} = airgapsOf(crypto)
  const accountKey = (chain: 'bitcoin' | 'ethereum') => {
    const path = accountPathOf(accounts[chain].path)

    return {extendedKey: extendedPublicKey(path), fingerprint, path}
  }

  switch (format) {
    case 'sparrow':
      return bitcoin.encodeAccount({keys: [bitcoin.accountKey(accountKey('bitcoin'))], masterFingerprint: fingerprint})
    case 'metamask':
      return toUR(CRYPTO_HDKEY, ethereum.accountKey({...accountKey('ethereum'), name: DEVICE}))
    case 'nitro': {
      const keys: HDKey[] = [
        bitcoin.accountKey(accountKey('bitcoin')),
        ethereum.accountKey(accountKey('ethereum')),
        solana.pairingKey(accounts.solana, fingerprint),
      ]

      return toUR(CRYPTO_MULTI_ACCOUNTS, {device: DEVICE, keys, masterFingerprint: fingerprint})
    }
  }
}

/**
 * A scanned request, read and checked for this wallet's account on its chain: any address of the Bitcoin or Ethereum
 * account (a wallet paired with its extended key asks for any), the Solana account, the wallet's fingerprint, the
 * chain. Throws an `AirgapError` (`REQUEST_MISMATCH` for a request meant for another wallet).
 */
export const readSignRequest = (
  crypto: WalletCrypto,
  ur: UR,
  accounts: WalletAccounts,
  fingerprint: number
): ScannedRequest => {
  const {bitcoin, ethereum, solana} = airgapsOf(crypto)
  const inAccount = (chain: 'bitcoin' | 'ethereum') => ({accountPath: accountPathOf(accounts[chain].path), fingerprint})

  switch (ur.type) {
    case 'crypto-psbt':
      return {chain: 'bitcoin', request: bitcoin.decodeSignRequest(ur, inAccount('bitcoin'))}
    case 'eth-sign-request':
      return {chain: 'ethereum', request: ethereum.decodeSignRequest(ur, inAccount('ethereum'))}
    default: {
      const {address, path} = accounts.solana

      return {chain: 'solana', request: solana.decodeSignRequest(ur, {account: {address, fingerprint, path}})}
    }
  }
}

/**
 * Signs what the user agreed to, with the keys in the engine (each derived at the path the request names, which the
 * adapter checks against the request again), and returns the answer for the watch-only wallet.
 */
export const signScannedRequest = async (
  crypto: WalletCrypto,
  scanned: ScannedRequest,
  accounts: WalletAccounts,
  accountsAt: AccountsAt
): Promise<UR> => {
  const {bitcoin, ethereum, solana} = airgapsOf(crypto)

  switch (scanned.chain) {
    case 'bitcoin':
      return bitcoin.encodeSignResponse(await bitcoin.signRequest(scanned.request, accountsAt.bitcoin))
    case 'ethereum':
      return ethereum.encodeSignResponse(await ethereum.signRequest(scanned.request, accountsAt.ethereum))
    case 'solana': {
      const {request} = scanned
      const signature =
        request.kind === 'transaction'
          ? await accounts.solana.signTransactionMessage(request.message)
          : await accounts.solana.signMessage({message: request.message})

      return solana.encodeSignResponse({requestId: request.requestId, signature})
    }
  }
}

/** SLIP-44 coin types: what a shared key's path says its chain is. */
const COIN_TYPES = {bitcoin: [0, 1], ethereum: [60], solana: [501]} as const

const coinTypeOf = (key: HDKey) => {
  const step = key.origin?.components[1]

  return step && 'index' in step ? step.index : undefined
}

/** A watched Bitcoin account as the plain data the store keeps. */
const bitcoinWatch = ({
  fingerprint,
  path,
  publicKey,
}: {
  readonly fingerprint: number
  readonly path: string
  readonly publicKey: Uint8Array
}): BitcoinWatchRequest => ({fingerprint, path, publicKey})

/** The first key its chain's adapter can watch: a hardware wallet also shares keys of other networks and layouts. */
const firstWatched = <T>(keys: readonly HDKey[], watch: (key: HDKey) => T): T | undefined => {
  for (const key of keys) {
    try {
      return watch(key)
    } catch (error) {
      if (!(error instanceof AirgapError)) {
        throw error
      }
    }
  }

  return undefined
}

/** One key (`crypto-hdkey`, MetaMask's pairing) read as the accounts of a wallet with one key. */
const sharedKeys = (ur: UR) => {
  if (ur.type !== 'crypto-hdkey') {
    return fromUR(CRYPTO_MULTI_ACCOUNTS, ur)
  }

  const key = fromUR(CRYPTO_HDKEY, ur)
  const fingerprint = key.origin?.sourceFingerprint

  if (fingerprint === undefined) {
    throw new AirgapError('INVALID_PROTOCOL_DATA', 'The key does not say which wallet it is of.')
  }

  return {device: key.name, keys: [key], masterFingerprint: fingerprint}
}

/**
 * The signer a pairing code describes, as the accounts a watch-only wallet can ask it to sign for: each key checked by
 * its chain's adapter (its path, its network), an account's extended key watched at its first address. Keys this
 * wallet cannot watch (other chains, networks or layouts) are left out; a code with none is refused.
 */
export const readPairing = (crypto: WalletCrypto, ur: UR): PairedSigner => {
  const {bitcoin, ethereum, solana} = airgapsOf(crypto)

  if (ur.type === 'crypto-account') {
    const imported = bitcoin.decodeAccount(ur)
    const [account] = imported.accounts

    if (!account) {
      throw new AirgapError('REQUEST_MISMATCH', 'The code has no Bitcoin account this wallet can watch.')
    }

    return {bitcoin: bitcoinWatch(account), fingerprint: imported.masterFingerprint}
  }

  const shared = sharedKeys(ur)
  const keysOf = (chain: keyof typeof COIN_TYPES) =>
    shared.keys.filter(key => (COIN_TYPES[chain] as readonly number[]).includes(coinTypeOf(key) ?? -1))
  const fingerprint = shared.masterFingerprint
  const paired: PairedSigner = {
    bitcoin: firstWatched(keysOf('bitcoin'), key => bitcoinWatch(bitcoin.watchAccount(key, fingerprint))),
    device: shared.device,
    ethereum: firstWatched(keysOf('ethereum'), key => ethereum.watchAccount(key, fingerprint)),
    fingerprint,
    solana: firstWatched(keysOf('solana'), key => solana.watchAccount(key, fingerprint)),
  }

  if (!(paired.bitcoin || paired.ethereum || paired.solana)) {
    throw new AirgapError('REQUEST_MISMATCH', 'The code has no account of a chain this wallet has.')
  }

  return paired
}
