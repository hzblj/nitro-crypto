import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'

import {Providers} from '../src/providers'

const RootStack = () => {
  const theme = useAppTheme()

  return (
    <Stack screenOptions={{contentStyle: {backgroundColor: theme.color('surface.base')}, headerShown: false}}>
      <Stack.Screen name="(tabs)" />
    </Stack>
  )
}

export default function RootLayout() {
  return (
    <Providers>
      <RootStack />
    </Providers>
  )
}
