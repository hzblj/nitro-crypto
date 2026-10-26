import {Stack} from 'expo-router'

import {TabStack} from '../../../src/components'
import {useWalletStatus} from '../../../src/hooks'

/** Everything past the home screen needs the unlocked wallet: locking or removing it closes those screens. */
export default function HomeLayout() {
  const status = useWalletStatus()

  return (
    <TabStack title="Nitro Wallet">
      <Stack.Screen name="index" />
      <Stack.Protected guard={status === 'unlocked'}>
        <Stack.Screen name="network/[chain]" />
        <Stack.Screen name="send" />
        <Stack.Screen name="receive" />
        <Stack.Screen name="sign" />
        <Stack.Screen name="transaction" />
        <Stack.Screen name="scan" />
        <Stack.Screen name="airgap-review" />
      </Stack.Protected>
    </TabStack>
  )
}
