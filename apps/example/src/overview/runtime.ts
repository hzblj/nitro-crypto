import * as Device from 'expo-device'
import {Platform} from 'react-native'

/** Where the example is running, as the Performance and Overview screens report it. */
export const runtime = () => {
  const os =
    Platform.OS === 'ios' ? `iOS ${Platform.Version}` : `Android ${Device.osVersion ?? ''} (API ${Platform.Version})`
  return {
    architectures: Device.supportedCpuArchitectures?.join(', ') ?? 'unknown',
    build: __DEV__ ? 'Debug' : 'Release',
    device: `${Device.modelName ?? 'Unknown device'}${Device.isDevice ? '' : ', simulated'}`,
    javascript: 'HermesInternal' in globalThis ? 'Hermes' : 'JavaScriptCore',
    os,
  }
}
