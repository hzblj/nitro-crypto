import {Stack, useLocalSearchParams} from 'expo-router'

import {SendScreen} from '../../../src/features/send'

export default function Send() {
  const {asset} = useLocalSearchParams<{asset?: string}>()

  return (
    <>
      <Stack.Screen options={{title: 'Send'}} />
      <SendScreen initialAsset={asset} />
    </>
  )
}
