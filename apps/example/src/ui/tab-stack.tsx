import {useAppTheme} from '@hzblj/kara-ui'
import {Stack} from 'expo-router'

/**
 * Each tab is a stack of its own, under a native large title. The bar keeps the system's own appearance: set to
 * `headerTransparent: false`, the iOS 26 bar went opaque and showed no title once the large one had scrolled away.
 */
export const TabStack = ({title}: {title: string}) => {
  const theme = useAppTheme()

  return (
    <Stack
      screenOptions={{
        contentStyle: {backgroundColor: theme.color('surface.base')},
        headerLargeTitle: true,
        title,
      }}
    />
  )
}
