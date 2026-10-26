import {CryptoError, createCryptoEngine, isCryptoError} from '@hzblj/nitro-crypto'
import {createServices, type Services} from '../services'
import {createWalletAdapters, type WalletCrypto} from './chains'

type Engine = {readonly crypto: WalletCrypto; readonly services: Services} | {readonly error: CryptoError}

let engine: Engine | undefined

/** The wallet's engine, once per run: a missing native module is a message on screen, not a crash at import. */
export const walletEngine = (): Engine => {
  if (!engine) {
    try {
      const crypto = createCryptoEngine({adapters: createWalletAdapters()})
      engine = {crypto, services: createServices(crypto)}
    } catch (error) {
      engine = {
        error: isCryptoError(error) ? error : new CryptoError('NATIVE_UNAVAILABLE', undefined, {cause: error}),
      }
    }
  }
  return engine
}

export const walletCrypto = (): WalletCrypto | null => {
  const current = walletEngine()
  return 'crypto' in current ? current.crypto : null
}

/** Each chain's network access, bound to the engine's adapters. */
export const walletServices = (): Services | null => {
  const current = walletEngine()
  return 'services' in current ? current.services : null
}
