import {Box, type IconName, RnIcon, RnText} from '@hzblj/kara-ui'

export type NoticeTone = 'destructive' | 'neutral' | 'success' | 'warning'

const TONES = {
  destructive: {bg: 'fill.destructive.base', color: 'content.destructive', icon: 'error'},
  neutral: {bg: 'surface.primary', color: 'content.secondary', icon: 'info'},
  success: {bg: 'fill.success.base', color: 'content.success', icon: 'check-circle-filled'},
  warning: {bg: 'fill.accent.base', color: 'content.accent', icon: 'warning-filled'},
} as const satisfies Record<NoticeTone, {bg: string; color: string; icon: IconName}>

/** A short message in a tinted card: an error from the network, a warning before a secret is shown. */
export const Notice = ({
  testID,
  text,
  title,
  tone = 'neutral',
}: {
  testID?: string
  text: string
  title?: string
  tone?: NoticeTone
}) => (
  <Box align="flex-start" bg={TONES[tone].bg} borderRadius="large" gap="s12" p="s16" row testID={testID}>
    <RnIcon color={TONES[tone].color} name={TONES[tone].icon} size="s20" />
    <Box fill gap="s4">
      {title ? <RnText variant="subheadlineMedium">{title}</RnText> : null}
      <RnText color="content.secondary" variant="subheadline">
        {text}
      </RnText>
    </Box>
  </Box>
)
