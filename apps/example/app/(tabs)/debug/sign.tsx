import {Stack} from 'expo-router'

import {SignScreen} from '../../../src/features/debug/sign'

export default function Sign() {
  return (
    <>
      <Stack.Screen options={{title: 'Sign and verify'}} />
      <SignScreen />
    </>
  )
}
