import {VERSION as BITCOIN} from '@hzblj/crypto-bitcoin'
import {VERSION as ETHEREUM} from '@hzblj/crypto-ethereum'
import {VERSION as SOLANA} from '@hzblj/crypto-solana'
import {VERSION as NITRO_CRYPTO} from '@hzblj/nitro-crypto'
import expo from 'expo/package.json'
import reactNative from 'react-native/package.json'
import nitroModules from 'react-native-nitro-modules/package.json'

/** What this build of the example runs: the packages from this repository, and the platform under them. */
export const PACKAGE_VERSIONS = [
  {name: '@hzblj/nitro-crypto', version: NITRO_CRYPTO},
  {name: '@hzblj/crypto-ethereum', version: ETHEREUM},
  {name: '@hzblj/crypto-bitcoin', version: BITCOIN},
  {name: '@hzblj/crypto-solana', version: SOLANA},
] as const

export const PLATFORM_VERSIONS = [
  {name: 'Nitro Modules', version: nitroModules.version},
  {name: 'React Native', version: reactNative.version},
  {name: 'Expo', version: expo.version},
] as const
