import {Stack} from 'expo-router'

import {TabStack} from '../../../src/components'
import {useWalletStatus} from '../../../src/hooks'

/** The recovery phrase and pairing screens close the moment the wallet locks. */
export default function SettingsLayout() {
  const status = useWalletStatus()

  return (
    <TabStack title="Settings">
      <Stack.Screen name="index" />
      <Stack.Protected guard={status === 'unlocked'}>
        <Stack.Screen name="recovery-phrase" />
        <Stack.Screen name="pair" />
      </Stack.Protected>
    </TabStack>
  )
}
