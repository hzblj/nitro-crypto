import type {AccountOf, AccountRequest, KeySource} from '../adapters/contract'
import type {Registry} from '../adapters/registry'
import {CryptoError, native, nativeAsync} from '../core/errors'
import type {DerivationScheme, NitroCrypto, NitroSeed} from '../specs/nitro-crypto.nitro'
import {isScheme, type KeyOf, type SchemeCurve, type SigningKey, wrapKey} from './keys'
import {countWords, type MnemonicLength, nfkd, normalizeMnemonic, withSecretBytes, wordCount} from './mnemonic'

export type WalletOptions =
  /**
   * A fresh mnemonic of `words` words (12 by default), generated and kept inside the engine: a wallet nobody can
   * back up. For one the user writes down, generate the words with `crypto.mnemonic.generate()` and pass them here.
   */
  | {readonly passphrase?: string; readonly words?: MnemonicLength}
  /**
   * A known mnemonic: one `crypto.mnemonic.generate()` returned, a wallet being restored, or a published test vector.
   * It crosses into the engine as bytes this package overwrites afterwards; the string itself stays the app's.
   */
  | {readonly mnemonic: string; readonly passphrase?: string}

/**
 * A wallet that lives in memory only: a BIP-39 seed held by the engine and the keys derived from it. Nothing is
 * persisted, so it is gone after `dispose()`, a reload or a restart. The engine never reads its mnemonic back: a
 * wallet the user can restore starts from words `crypto.mnemonic.generate()` returned.
 */
export type EphemeralWallet<Chains> = {
  /** The BIP-32 fingerprint of the seed's master key: a public name for the wallet. */
  readonly fingerprint: number
  readonly origin: 'generated' | 'mnemonic'
  readonly words: number
  readonly disposed: boolean
  /** An account on a registered chain, by that chain's adapter. */
  readonly deriveAccount: <Id extends keyof Chains & string>(
    request: AccountRequest<Chains, Id>
  ) => Promise<AccountOf<Chains[Id]>>
  /** A key at any path, for what no adapter covers. It belongs to the wallet, like an account's key. */
  readonly deriveKey: KeySource['deriveKey']
  /** Zeroizes the seed and every key derived from it. Idempotent. */
  readonly dispose: () => void
}

const disposed = () => new CryptoError('DISPOSED', 'This wallet has been disposed.')

const createSeed = async (host: NitroCrypto, options: WalletOptions) => {
  const passphrase = nfkd(options.passphrase ?? '')

  if ('mnemonic' in options) {
    const mnemonic = normalizeMnemonic(options.mnemonic)
    const seed = await withSecretBytes(mnemonic, words =>
      withSecretBytes(passphrase, secret => nativeAsync(() => host.seedFromMnemonic(words, secret)))
    )

    return {origin: 'mnemonic' as const, seed, words: countWords(mnemonic)}
  }

  const words = wordCount(options.words)
  const seed = await withSecretBytes(passphrase, secret => nativeAsync(() => host.generateSeed(words, secret)))

  return {origin: 'generated' as const, seed, words}
}

/** The seed, and every key handed out from it, so disposing the wallet reaches all of them. */
type WalletState = {readonly seed: NitroSeed; readonly keys: Set<SigningKey>; disposed: boolean}

const createKeySource = (state: WalletState, fingerprint: number): KeySource => ({
  deriveKey: <S extends DerivationScheme>(scheme: S, path: string): KeyOf<SchemeCurve[S]> => {
    if (state.disposed) {
      throw disposed()
    }

    if (!isScheme(scheme)) {
      throw new CryptoError('INVALID_ARGUMENT', 'A derivation scheme is bip32 or slip10.')
    }

    const key = wrapKey(
      native(() => state.seed.deriveKey(scheme, path)),
      {onDispose: () => state.keys.delete(key), path}
    )
    state.keys.add(key)

    // The engine derives secp256k1 keys for bip32 and Ed25519 keys for slip10, which is what `SchemeCurve` states.
    return key as KeyOf<SchemeCurve[S]>
  },
  fingerprint,
})

export const createEphemeralWallet = async <Chains>(
  host: NitroCrypto,
  registry: Registry<Chains>,
  options: WalletOptions = {}
): Promise<EphemeralWallet<Chains>> => {
  const {origin, seed, words} = await createSeed(host, options)
  // Read while the seed is live: once disposed, Nitro detaches the object.
  const fingerprint = seed.fingerprint
  const state: WalletState = {disposed: false, keys: new Set(), seed}
  const source = createKeySource(state, fingerprint)

  return Object.freeze({
    deriveAccount: async <Id extends keyof Chains & string>({chain, ...request}: AccountRequest<Chains, Id>) => {
      if (state.disposed) {
        throw disposed()
      }

      // The registry holds each client under its adapter's id; the request type is that adapter's own.
      const client = registry.client(chain)

      return client.deriveAccount(source, request as never) as Promise<AccountOf<Chains[Id]>>
    },
    deriveKey: source.deriveKey,
    dispose: () => {
      if (state.disposed) {
        return
      }

      state.disposed = true

      for (const key of [...state.keys]) {
        key.dispose()
      }

      seed.dispose()
    },
    get disposed() {
      return state.disposed
    },
    fingerprint,
    origin,
    words,
  })
}
