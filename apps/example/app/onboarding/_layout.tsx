import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'

import {OnboardingProvider} from '../../src/features/onboarding'

/** A modal stack of its own: the phrase it holds is gone the moment it closes. */
export default function OnboardingLayout() {
  const theme = useAppTheme()

  return (
    <OnboardingProvider>
      <Stack
        screenOptions={{
          contentStyle: {backgroundColor: theme.color('surface.base')},
          headerBackButtonDisplayMode: 'minimal',
          headerLargeTitle: true,
        }}
      >
        <Stack.Screen name="create" options={{title: 'Recovery phrase'}} />
        <Stack.Screen name="import" options={{title: 'Import'}} />
        <Stack.Screen name="protect" options={{title: 'Protect'}} />
      </Stack>
    </OnboardingProvider>
  )
}
