import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'
import type {ReactNode} from 'react'

/**
 * Each tab is a stack of its own, under a native large title, with back buttons that are only the chevron. The bar keeps
 * the system's own appearance: set to `headerTransparent: false`, the iOS 26 bar went opaque and showed no title once
 * the large one had scrolled away.
 */
export const TabStack = ({children, title}: {children?: ReactNode; title: string}) => {
  const theme = useAppTheme()

  return (
    <Stack
      screenOptions={{
        contentStyle: {backgroundColor: theme.color('surface.base')},
        headerBackButtonDisplayMode: 'minimal',
        headerLargeTitle: true,
        title,
      }}
    >
      {children}
    </Stack>
  )
}
