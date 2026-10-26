import type {AnyAdapter, ChainsOf} from './adapters/contract'
import {type CryptoEngine, type CryptoEngineOptions, createEngine} from './engine/create-engine'
import {createWasmHost} from './host/wasm'
import type {NitroCrypto} from './specs/nitro-crypto.nitro'

/**
 * `@hzblj/nitro-crypto/testing`: the engine for tests that run without a device. The same Zig code the phones run,
 * compiled to WebAssembly, behind the same facade, so an app's or an adapter's tests in Node, Jest or Vitest check
 * what ships. It needs `WebAssembly` and `crypto.getRandomValues` (Node 19 and later have both).
 *
 * Not for production: there is no native memory here, only WebAssembly's, which JavaScript can read.
 */

let shared: NitroCrypto | undefined

/** The one WebAssembly engine of this process: seeds and keys from every test engine live in it. */
export const testHost = (): NitroCrypto => {
  shared ??= createWasmHost()

  return shared
}

export const createTestCryptoEngine = <const Adapters extends readonly AnyAdapter[] = readonly []>(
  options: CryptoEngineOptions<Adapters> = {}
): CryptoEngine<ChainsOf<Adapters>> => createEngine(testHost(), options)
