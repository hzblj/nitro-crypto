import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'

import {LockOverlay} from '../src/features/lock'
import {useWalletLifecycle} from '../src/hooks'
import {Providers} from '../src/providers'

const RootStack = () => {
  const theme = useAppTheme()
  useWalletLifecycle()

  return (
    <>
      <Stack screenOptions={{contentStyle: {backgroundColor: theme.color('surface.base')}, headerShown: false}}>
        <Stack.Screen name="(tabs)" />
        <Stack.Screen name="onboarding" options={{presentation: 'modal'}} />
      </Stack>
      <LockOverlay />
    </>
  )
}

export default function RootLayout() {
  return (
    <Providers>
      <RootStack />
    </Providers>
  )
}
