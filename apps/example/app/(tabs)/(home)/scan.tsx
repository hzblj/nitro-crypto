import {Stack} from 'expo-router'

import {ScanScreen} from '../../../src/features/airgap'

export default function Scan() {
  return (
    <>
      <Stack.Screen options={{title: 'Scan to sign'}} />
      <ScanScreen />
    </>
  )
}
