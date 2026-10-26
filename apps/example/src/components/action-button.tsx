import {Box, type IconName, Pressable, RnIcon, RnText} from '@hzblj/kara-ui'

type ActionButtonProps = {
  disabled?: boolean
  icon: IconName
  label: string
  onPress: () => void
  testID?: string
}

/** A round icon over its label: the wallet's main actions, three to a row. */
export const ActionButton = ({disabled, icon, label, onPress, testID}: ActionButtonProps) => (
  <Pressable
    accessibilityLabel={label}
    align="center"
    disabled={disabled}
    flex={1}
    gap="s8"
    haptic
    onPress={onPress}
    opacity={disabled ? 'o40' : undefined}
    testID={testID}
  >
    <Box align="center" bg="fill.accent.base" borderRadius="full" h={56} justify="center" w={56}>
      <RnIcon color="content.accent" name={icon} size="s24" />
    </Box>
    <RnText variant="subheadlineMedium">{label}</RnText>
  </Pressable>
)

/** Actions side by side, evenly. */
export const ActionRow = ({children}: {children: React.ReactNode}) => (
  <Box gap="s8" row>
    {children}
  </Box>
)
