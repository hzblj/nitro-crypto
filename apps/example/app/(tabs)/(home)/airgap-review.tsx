import {Stack} from 'expo-router'

import {ReviewScreen} from '../../../src/features/airgap'

export default function AirgapReview() {
  return (
    <>
      <Stack.Screen options={{title: 'Review'}} />
      <ReviewScreen />
    </>
  )
}
