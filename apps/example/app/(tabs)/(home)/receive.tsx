import {Stack, useLocalSearchParams} from 'expo-router'
import {isChainId} from '../../../src/config'
import {ReceiveScreen} from '../../../src/features/receive'

export default function Receive() {
  const {chain} = useLocalSearchParams<{chain?: string}>()

  return (
    <>
      <Stack.Screen options={{title: 'Receive'}} />
      <ReceiveScreen initial={isChainId(chain) ? chain : undefined} />
    </>
  )
}
