import type {ExtendedPublicKey} from '../engine/extended-key'
import type {Capability, EngineInfo} from '../engine/info'
import type {KeyOf, SchemeCurve} from '../engine/keys'
import type {Primitives} from '../engine/primitives'
import type {Curve, DerivationScheme} from '../specs/nitro-crypto.nitro'

/**
 * The contract between the engine and a chain. An adapter is plain TypeScript over the engine's primitives: it knows
 * a chain's paths, address formats and message formats, and nothing native. Adding a chain whose curves and hashes
 * the engine already has means writing one of these, and editing nothing else.
 */

/** What an adapter receives when it is registered: the engine's stateless primitives, and what the engine is. */
export type AdapterContext = Primitives & {readonly engine: EngineInfo}

/**
 * Keys for an account, from a wallet whose seed the adapter never sees. Keys derived here belong to the wallet:
 * disposing the wallet disposes them.
 */
export type KeySource = {
  /** The wallet's BIP-32 fingerprint. */
  readonly fingerprint: number
  readonly deriveKey: <S extends DerivationScheme>(scheme: S, path: string) => KeyOf<SchemeCurve[S]>
  /**
   * The BIP-32 extended public key at `path` (secp256k1, at least one step): what an account shares for a watch-only
   * wallet to follow it. Public; no private key leaves the engine (docs/adr/0007).
   */
  readonly extendedPublicKey: (path: string) => ExtendedPublicKey
}

/** The result of checking an address. Chains extend the valid branch with what they know (network, type). */
export type AddressValidation =
  | {readonly valid: true /** The canonical spelling: EIP-55 case, lowercase Bech32. */; readonly normalized: string}
  | {readonly valid: false; readonly reason: string}

/**
 * A chain bound to an engine. `deriveAccount` is the one way accounts come to exist; everything else a chain
 * offers (recovering a signer, checksumming an address) is its own business, typed by the adapter.
 */
export type ChainClient<Request = never, Account = unknown> = {
  readonly deriveAccount: (keys: KeySource, request: Request) => Promise<Account>
  readonly validateAddress: (address: string) => AddressValidation
}

/** A client whose request and account types are unknown: what the registry holds before inference narrows it. */
export type AnyChainClient = ChainClient<never, unknown>

export type AdapterFormats = {
  /** Address encodings the adapter produces or accepts, such as `eip55` or `bech32-p2wpkh`. */
  readonly address: readonly string[]
  /** Signature formats it produces, such as `eip191`. Empty when the adapter signs nothing yet. */
  readonly signature: readonly string[]
}

/** Feature flags, stated rather than implied: `{messageSigning: false}` is a promise not to pretend. */
export type AdapterFeatures = Readonly<Record<string, boolean>>

export type ChainAdapter<Id extends string = string, Client extends AnyChainClient = AnyChainClient> = {
  /** The key it is registered and addressed by: lowercase letters, digits and dashes (`ethereum`, `bitcoin-testnet`). */
  readonly id: Id
  /** For people: "Ethereum", "Bitcoin testnet". */
  readonly name: string
  /** The adapter package's version. */
  readonly version: string
  /** The curve its keys are on. */
  readonly curve: Curve
  /** Engine capabilities it needs; registration fails, naming them, when the engine lacks any. */
  readonly requires: readonly Capability[]
  readonly formats: AdapterFormats
  readonly features: AdapterFeatures
  /** Binds the adapter to an engine. Called once, when the engine is created. */
  readonly create: (context: AdapterContext) => Client
}

export type AnyAdapter = ChainAdapter<string, AnyChainClient>

/** What the registry reports about an adapter: everything but its implementation. */
export type AdapterInfo = Omit<AnyAdapter, 'create'>

/** The chains a list of adapters registers, by id, each with its own client type. */
export type ChainsOf<Adapters extends readonly AnyAdapter[]> = {
  readonly [Adapter in Adapters[number] as Adapter['id']]: ReturnType<Adapter['create']>
}

export type RequestOf<Client> = Client extends ChainClient<infer Request, unknown> ? Request : never

export type AccountOf<Client> = Client extends ChainClient<never, infer Account> ? Account : never

/** A request for an account on one chain: its id, and that adapter's own request fields. */
export type AccountRequest<Chains, Id extends keyof Chains> = {readonly chain: Id} & RequestOf<Chains[Id]>

/**
 * Declares an adapter. Returns it frozen and unchanged; the point is the inference: `Id` stays the literal id, and
 * `Client` the adapter's own client type, all the way to `crypto.chains` and `wallet.deriveAccount`.
 */
export const defineAdapter = <const Id extends string, Client extends AnyChainClient>(
  adapter: ChainAdapter<Id, Client>
): ChainAdapter<Id, Client> => Object.freeze({...adapter})
