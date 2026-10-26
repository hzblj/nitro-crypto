import {NitroModules} from 'react-native-nitro-modules'

import {CryptoError, fromNativeError} from '../core/errors'
import type {NitroCrypto} from '../specs/nitro-crypto.nitro'

let engine: NitroCrypto | undefined

/**
 * The native engine, created on first use: importing the package touches no native code. When the module is not
 * linked (Expo Go, a build from before it was installed) that is `NATIVE_UNAVAILABLE`, not a crash at import.
 */
export const nitroHost = (): NitroCrypto => {
  if (!engine) {
    try {
      engine = NitroModules.createHybridObject<NitroCrypto>('NitroCrypto')
    } catch (error) {
      const mapped = fromNativeError(error)
      throw mapped.code === 'INVALID_ARGUMENT'
        ? new CryptoError('NATIVE_UNAVAILABLE', undefined, {cause: error})
        : mapped
    }
  }

  return engine
}
