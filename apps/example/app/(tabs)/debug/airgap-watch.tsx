import {Stack} from 'expo-router'

import {WatchScreen} from '../../../src/features/debug/airgap'

export default function AirgapWatch() {
  return (
    <>
      <Stack.Screen options={{title: 'Watch-only wallet'}} />
      <WatchScreen />
    </>
  )
}
