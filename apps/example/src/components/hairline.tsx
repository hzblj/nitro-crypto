import {Box, type SpaceSize} from '@hzblj/kara-ui'
import {StyleSheet} from 'react-native'

/** A row separator in the React Native tier, where the native `Divider` has no host. `inset` clears a row's icon. */
export const Hairline = ({inset = 's0'}: {inset?: SpaceSize}) => (
  <Box bg="border.tertiary" h={StyleSheet.hairlineWidth} ml={inset} />
)
