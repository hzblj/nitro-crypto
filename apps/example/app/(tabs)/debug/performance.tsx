import {Stack} from 'expo-router'

import {PerformanceScreen} from '../../../src/features/debug/lab'

export default function Performance() {
  return (
    <>
      <Stack.Screen options={{title: 'Performance'}} />
      <PerformanceScreen />
    </>
  )
}
