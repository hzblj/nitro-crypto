import {Box, RnText} from '@hzblj/kara-ui'

export type PillTone = 'accent' | 'destructive' | 'neutral' | 'success'

const TONES = {
  accent: {bg: 'fill.accent.base', color: 'content.accent'},
  destructive: {bg: 'fill.destructive.base', color: 'content.destructive'},
  neutral: {bg: 'fill.tertiary', color: 'content.secondary'},
  success: {bg: 'fill.success.base', color: 'content.primary'},
} as const

/** A small tag: a capability, a format, a feature that is on or off. */
export const Pill = ({label, tone = 'neutral'}: {label: string; tone?: PillTone}) => (
  <Box bg={TONES[tone].bg} borderRadius="full" px="s8" py="s2">
    <RnText color={TONES[tone].color} variant="captionMedium">
      {label}
    </RnText>
  </Box>
)

export const Pills = ({labels, tone}: {labels: readonly string[]; tone?: PillTone}) => (
  <Box gap="s6" row wrap>
    {labels.map(label => (
      <Pill key={label} label={label} tone={tone} />
    ))}
  </Box>
)
