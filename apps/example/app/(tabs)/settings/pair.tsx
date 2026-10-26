import {Stack} from 'expo-router'

import {PairScreen} from '../../../src/features/airgap'

export default function Pair() {
  return (
    <>
      <Stack.Screen options={{title: 'Pair with a wallet'}} />
      <PairScreen />
    </>
  )
}
