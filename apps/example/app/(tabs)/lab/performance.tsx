import {Stack} from 'expo-router'

import {PerformanceScreen} from '../../../src/lab'

export default function Performance() {
  return (
    <>
      <Stack.Screen options={{title: 'Performance'}} />
      <PerformanceScreen />
    </>
  )
}
