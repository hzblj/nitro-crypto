import {Stack} from 'expo-router'

import {SignMessageScreen} from '../../../src/features/sign-message'

export default function Sign() {
  return (
    <>
      <Stack.Screen options={{title: 'Sign a message'}} />
      <SignMessageScreen />
    </>
  )
}
