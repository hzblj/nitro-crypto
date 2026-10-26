import type {ExpoConfig} from 'expo/config'

// Not "Nitro Crypto": the generated Xcode target would be `NitroCrypto`, the name of the package's pod.
const NAME = 'Crypto Example'
const BUNDLE_ID = 'com.hzblj.nitrocrypto.example'

export default {
  android: {
    package: BUNDLE_ID,
  },
  experiments: {
    typedRoutes: true,
  },
  ios: {
    bundleIdentifier: BUNDLE_ID,
    supportsTablet: true,
  },
  name: NAME,
  orientation: 'portrait',
  plugins: [
    'expo-router',
    // The example's icons (Material Symbols): every SVG in assets/icons becomes a native asset on both platforms, and
    // its name a type in native-icons.d.ts.
    ['@hzblj/kara-ui', {icons: {source: './assets/icons'}}],
    // The scene life cycle, which apps built with the iOS 27 SDK need or they stop at launch: Expo 57's template has
    // none, so React Native starts from Expo's scene delegate instead. Remove it with the move to Expo 58.
    ['expo-build-properties', {ios: {enableSceneSupport: true}}],
  ],
  scheme: 'nitro-crypto-example',
  slug: 'nitro-crypto-example',
  userInterfaceStyle: 'automatic',
  version: '1.0.0',
} satisfies ExpoConfig
