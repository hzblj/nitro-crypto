import {Stack} from 'expo-router'

import {LoopbackScreen} from '../../../src/features/debug/airgap'

export default function AirgapLoopback() {
  return (
    <>
      <Stack.Screen options={{title: 'Air-gap loopback'}} />
      <LoopbackScreen />
    </>
  )
}
