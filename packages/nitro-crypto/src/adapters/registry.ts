import {CryptoError} from '../core/errors'
import type {AdapterContext, AdapterInfo, AnyAdapter, AnyChainClient, ChainsOf} from './contract'

const ID = /^[a-z][a-z0-9-]{0,63}$/
const CURVES = new Set(['secp256k1', 'ed25519'])

const invalid = (id: string, problem: string) => new CryptoError('INVALID_ADAPTER', `Adapter "${id}": ${problem}`)

const isStringList = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every(item => typeof item === 'string')

/** The contract, checked at runtime too: adapters arrive from other packages, and JavaScript callers. */
const assertAdapter = (adapter: AnyAdapter): void => {
  const id = typeof adapter?.id === 'string' ? adapter.id : String(adapter?.id)

  if (!ID.test(id)) {
    throw invalid(id, 'the id is lowercase letters, digits and dashes, starting with a letter.')
  }

  if (typeof adapter.name !== 'string' || adapter.name === '') {
    throw invalid(id, 'it needs a name.')
  }

  if (typeof adapter.version !== 'string' || adapter.version === '') {
    throw invalid(id, 'it needs a version.')
  }

  if (!CURVES.has(adapter.curve)) {
    throw invalid(id, 'the curve is secp256k1 or ed25519.')
  }

  if (!isStringList(adapter.requires)) {
    throw invalid(id, 'requires lists capability names.')
  }

  if (!isStringList(adapter.formats?.address) || !isStringList(adapter.formats?.signature)) {
    throw invalid(id, 'formats lists address and signature formats.')
  }

  if (typeof adapter.features !== 'object' || adapter.features === null) {
    throw invalid(id, 'features is an object of flags.')
  }

  if (typeof adapter.create !== 'function') {
    throw invalid(id, 'create binds it to an engine.')
  }
}

const assertUnique = (adapters: readonly AnyAdapter[]): void => {
  const seen = new Set<string>()

  for (const {id} of adapters) {
    if (seen.has(id)) {
      throw new CryptoError('DUPLICATE_ADAPTER', `Two adapters have the id "${id}". Give one another id.`)
    }

    seen.add(id)
  }
}

const assertCapabilities = (adapter: AnyAdapter, context: AdapterContext): void => {
  const missing = adapter.requires.filter(capability => !context.engine.has(capability))

  if (missing.length > 0) {
    throw new CryptoError(
      'MISSING_CAPABILITY',
      `Adapter "${adapter.id}" needs ${missing.join(', ')}, which engine ${context.engine.engineVersion} does not have.`
    )
  }
}

const bind = (adapter: AnyAdapter, context: AdapterContext): AnyChainClient => {
  const client = adapter.create(context)

  if (typeof client?.deriveAccount !== 'function' || typeof client.validateAddress !== 'function') {
    throw invalid(adapter.id, 'create must return a client with deriveAccount and validateAddress.')
  }

  return client
}

const describe = ({create: _, ...info}: AnyAdapter): AdapterInfo => Object.freeze(info)

export type Registry<Chains> = {
  readonly adapters: readonly AdapterInfo[]
  readonly chains: Chains
  /** A chain by id, or `UNKNOWN_CHAIN`: for ids that arrive as data. */
  readonly client: (id: string) => AnyChainClient
}

/**
 * Validates every adapter (shape, unique id, capabilities) before binding any, so a bad list fails as a whole and
 * names the culprit, rather than half-registering.
 */
export const createRegistry = <const Adapters extends readonly AnyAdapter[]>(
  adapters: Adapters,
  context: AdapterContext
): Registry<ChainsOf<Adapters>> => {
  adapters.forEach(assertAdapter)
  assertUnique(adapters)

  for (const adapter of adapters) {
    assertCapabilities(adapter, context)
  }

  const clients = new Map(adapters.map(adapter => [adapter.id, bind(adapter, context)] as const))

  return Object.freeze({
    adapters: Object.freeze(adapters.map(describe)),
    // Each id maps to the client its adapter's `create` returned, which is what `ChainsOf` states.
    chains: Object.freeze(Object.fromEntries(clients)) as ChainsOf<Adapters>,
    client: (id: string) => {
      const client = clients.get(id)

      if (!client) {
        throw new CryptoError('UNKNOWN_CHAIN', `No adapter is registered for "${id}".`)
      }

      return client
    },
  })
}
