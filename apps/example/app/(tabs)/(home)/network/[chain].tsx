import {Stack, useLocalSearchParams} from 'expo-router'
import {isChainId, NETWORKS} from '../../../../src/config'
import {NetworkScreen} from '../../../../src/features/network'

export default function Network() {
  const {chain} = useLocalSearchParams<{chain: string}>()
  const id = isChainId(chain) ? chain : 'ethereum'

  return (
    <>
      <Stack.Screen options={{title: NETWORKS[id].name}} />
      <NetworkScreen chain={id} />
    </>
  )
}
