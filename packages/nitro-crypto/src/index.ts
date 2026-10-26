import type {AnyAdapter, ChainsOf} from './adapters/contract'
import {type CryptoEngine, type CryptoEngineOptions, createEngine} from './engine/create-engine'
import {nitroHost} from './host/nitro'

/**
 * The engine, on the device's native module, with the chains `adapters` registers. Create it once and share it:
 * every engine talks to the same native module.
 *
 * ```ts
 * const crypto = createCryptoEngine({adapters: [ethereumAdapter(), solanaAdapter()]})
 * const wallet = await crypto.createEphemeralWallet()
 * const account = await wallet.deriveAccount({account: 0, chain: 'ethereum'})
 * ```
 */
export const createCryptoEngine = <const Adapters extends readonly AnyAdapter[] = readonly []>(
  options: CryptoEngineOptions<Adapters> = {}
): CryptoEngine<ChainsOf<Adapters>> => createEngine(nitroHost(), options)

export type {
  AccountOf,
  AccountRequest,
  AdapterInfo,
  AnyAdapter,
  ChainAdapter,
  ChainClient,
  ChainsOf,
} from './adapters/contract'
export {CRYPTO_ERROR_CODES, CryptoError, type CryptoErrorCode, isCryptoError} from './core/errors'
export {bytes} from './core/public-bytes'
export * from './encoding'
export type {CryptoEngine, CryptoEngineOptions} from './engine/create-engine'
export {type Bip32Primitives, type ExtendedPublicKey} from './engine/extended-key'
export {CAPABILITIES, type Capability, type EngineInfo, SUPPORTED_ABI_VERSION} from './engine/info'
export type {Ed25519Key, KeyFactory, KeyOf, Secp256k1Key, SigningKey} from './engine/keys'
export {MNEMONIC_LENGTHS, type MnemonicCheck, type MnemonicLength} from './engine/mnemonic'
export type {
  Ed25519Primitives,
  Hashes,
  Hmacs,
  Primitives,
  PublicKeyFormat,
  RecoverableSignature,
  RecoveryId,
  Secp256k1Primitives,
} from './engine/primitives'
export type {EphemeralWallet, WalletOptions} from './engine/wallet'
export type {Curve, DerivationScheme, HashAlgorithm, HmacAlgorithm} from './specs/nitro-crypto.nitro'
export {VERSION} from './version'
