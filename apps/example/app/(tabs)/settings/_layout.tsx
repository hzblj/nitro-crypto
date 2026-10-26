import {Stack} from 'expo-router'

import {TabStack} from '../../../src/components'
import {useWalletStatus} from '../../../src/hooks'

/** The recovery phrase screen closes the moment the wallet locks. */
export default function SettingsLayout() {
  const status = useWalletStatus()

  return (
    <TabStack title="Settings">
      <Stack.Screen name="index" />
      <Stack.Protected guard={status === 'unlocked'}>
        <Stack.Screen name="recovery-phrase" />
      </Stack.Protected>
    </TabStack>
  )
}
