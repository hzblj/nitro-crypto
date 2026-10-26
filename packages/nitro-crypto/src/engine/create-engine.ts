import type {AdapterContext, AdapterInfo, AnyAdapter, ChainsOf} from '../adapters/contract'
import {createRegistry} from '../adapters/registry'
import type {NitroCrypto} from '../specs/nitro-crypto.nitro'
import {type EngineInfo, readEngineInfo} from './info'
import {createKeyFactory, type KeyFactory} from './keys'
import {createMnemonicTools, type MnemonicTools} from './mnemonic'
import {createPrimitives, type Primitives} from './primitives'
import {createEphemeralWallet, type EphemeralWallet, type WalletOptions} from './wallet'

export type CryptoEngineOptions<Adapters extends readonly AnyAdapter[]> = {
  /** The chains this engine serves. Each is registered once, validated, and typed by its id in `chains`. */
  readonly adapters?: Adapters
}

export type CryptoEngine<Chains> = Primitives & {
  readonly info: EngineInfo
  readonly adapters: readonly AdapterInfo[]
  /** Every registered chain by id, each typed as its adapter's client. */
  readonly chains: Chains
  readonly keys: KeyFactory
  readonly mnemonic: MnemonicTools
  /** A wallet in memory only. See `EphemeralWallet`. */
  readonly createEphemeralWallet: (options?: WalletOptions) => Promise<EphemeralWallet<Chains>>
  /** Seeds and keys alive in the engine: a leak check for tests and the example's diagnostics. */
  readonly liveHandles: () => number
}

/**
 * An engine over a host: the native module on a device, the WebAssembly build in tests. Everything above the host
 * is the same code, which is what lets the TypeScript tests stand for the device.
 */
export const createEngine = <const Adapters extends readonly AnyAdapter[] = readonly []>(
  host: NitroCrypto,
  options: CryptoEngineOptions<Adapters> = {}
): CryptoEngine<ChainsOf<Adapters>> => {
  const info = readEngineInfo(host)
  const primitives = createPrimitives(host)
  const context: AdapterContext = Object.freeze({...primitives, engine: info})
  const registry = createRegistry((options.adapters ?? []) as Adapters, context)

  return Object.freeze({
    ...primitives,
    adapters: registry.adapters,
    chains: registry.chains,
    createEphemeralWallet: (walletOptions?: WalletOptions) => createEphemeralWallet(host, registry, walletOptions),
    info,
    keys: createKeyFactory(host),
    liveHandles: () => host.liveHandles,
    mnemonic: createMnemonicTools(host),
  })
}
