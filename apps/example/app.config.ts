import type {ExpoConfig} from 'expo/config'

// Not "Nitro Crypto": the generated Xcode target would be `NitroCrypto`, the name of the package's pod.
const NAME = 'Crypto Example'
const BUNDLE_ID = 'com.hzblj.nitrocrypto.example'
// The middle of the iOS icon's emerald: what the Android icon's wallet sits on.
const ICON_BACKGROUND = '#12a37f'
// Face ID guards the stored recovery phrase: expo-secure-store and expo-local-authentication each write this text.
const FACE_ID = 'Allow $(PRODUCT_NAME) to use Face ID to unlock your wallet and approve what it signs.'

export default {
  android: {
    adaptiveIcon: {
      backgroundColor: ICON_BACKGROUND,
      foregroundImage: './assets/adaptive-icon.png',
    },
    package: BUNDLE_ID,
  },
  experiments: {
    typedRoutes: true,
  },
  icon: './assets/icon.png',
  ios: {
    bundleIdentifier: BUNDLE_ID,
    // An Icon Composer document: iOS renders its Liquid Glass, dark and tinted appearances itself.
    icon: './assets/app.icon',
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
    // The wallet's recovery phrase lives in the Keychain (Keystore on Android), readable only after Face ID.
    ['expo-secure-store', {configureAndroidBackup: true, faceIDPermission: FACE_ID}],
    ['expo-local-authentication', {faceIDPermission: FACE_ID}],
  ],
  scheme: 'nitro-crypto-example',
  slug: 'nitro-crypto-example',
  userInterfaceStyle: 'automatic',
  version: '1.0.0',
} satisfies ExpoConfig
