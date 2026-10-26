import {CryptoError} from '../core/errors'
import type {NitroCrypto} from '../specs/nitro-crypto.nitro'

/** The C ABI version this facade speaks. A host reporting another is refused before anything else runs. */
export const SUPPORTED_ABI_VERSION = 1

/**
 * What an engine can do, named as the engine names it. Adapters list the ones they need (`requires`); the
 * registry refuses an adapter whose list the engine does not cover.
 */
export const CAPABILITIES = [
  'random',
  'sha256',
  'sha512',
  'keccak256',
  'ripemd160',
  'hmac-sha256',
  'hmac-sha512',
  'secp256k1-ecdsa',
  'secp256k1-recovery',
  'ed25519',
  'bip39',
  'bip32-secp256k1',
  'slip10-ed25519',
  'mnemonic-generate',
  'bip32-extended-public',
  'bip32-public-derivation',
] as const

export type Capability = (typeof CAPABILITIES)[number]

export type EngineInfo = {
  readonly abiVersion: number
  /** What the engine was built with, for people: "zig 0.16.0, libsecp256k1 0.8.0, ecmult window 8". */
  readonly build: string
  /** Capabilities this build has. Names a newer engine adds and this facade does not know are kept, as strings. */
  readonly capabilities: readonly string[]
  readonly engineVersion: string
  readonly has: (capability: Capability) => boolean
}

export const readEngineInfo = (host: NitroCrypto): EngineInfo => {
  const abiVersion = host.abiVersion

  if (abiVersion !== SUPPORTED_ABI_VERSION) {
    throw new CryptoError(
      'ABI_MISMATCH',
      `The native engine implements C ABI ${abiVersion}; this package speaks ABI ${SUPPORTED_ABI_VERSION}.`
    )
  }

  const capabilities = Object.freeze([...host.capabilities])
  const present = new Set(capabilities)

  return Object.freeze({
    abiVersion,
    build: host.buildInfo,
    capabilities,
    engineVersion: host.engineVersion,
    has: (capability: Capability) => present.has(capability),
  })
}
