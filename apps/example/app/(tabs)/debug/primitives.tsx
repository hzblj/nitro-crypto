import {Stack} from 'expo-router'

import {PrimitivesScreen} from '../../../src/features/debug/lab'

export default function Primitives() {
  return (
    <>
      <Stack.Screen options={{title: 'Primitives'}} />
      <PrimitivesScreen />
    </>
  )
}
