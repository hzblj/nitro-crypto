import {Box, Pressable, RnIcon, RnText} from '@hzblj/kara-ui'
import {openBrowserAsync} from 'expo-web-browser'
import {memo} from 'react'

import {Hairline, Pill} from '../../components'
import {NETWORKS} from '../../config'
import {type ActivityItem} from '../../services'
import {formatUnits, formatWhen, shortAddress} from '../../utils'

const VERBS = {in: 'Received', out: 'Sent', self: 'Moved'} as const

type ActivityRowProps = {
  readonly item: ActivityItem
  /** Rows draw their own part of the card, so a virtualized list can lay them out one by one. */
  readonly first?: boolean
  readonly last?: boolean
}

/**
 * One movement: what, with whom, when, how much. Pressing it opens the transaction in the network's explorer. Memoized:
 * a history refresh hands most rows the same item again.
 */
export const ActivityRow = memo(({first = true, item, last = true}: ActivityRowProps) => {
  const network = NETWORKS[item.chain]
  const incoming = item.direction === 'in'
  const counterparty = item.counterparty
    ? `${incoming ? 'from' : 'to'} ${shortAddress(item.counterparty)}`
    : `${network.name} ${network.testnet}`
  const amount = `${incoming ? '+' : item.direction === 'out' ? '−' : ''}${formatUnits(item.amount, item.asset.decimals)} ${item.asset.symbol}`

  return (
    <Box
      bg="surface.primary"
      borderBottomRadius={last ? 'large' : undefined}
      borderTopRadius={first ? 'large' : undefined}
      px="s16"
    >
      {first ? null : <Hairline inset="s48" />}
      <Pressable
        accessibilityHint="Opens it in the explorer"
        accessibilityLabel={`${VERBS[item.direction]} ${amount}, ${formatWhen(item.timestamp)}`}
        align="center"
        gap="s12"
        onPress={() => openBrowserAsync(network.explorer.tx(item.hash))}
        pressEffect="opacity"
        py="s12"
        row
        testID="activity-row"
      >
        <Box align="center" bg="fill.tertiary" borderRadius="full" h={40} justify="center" w={40}>
          <RnIcon
            color={incoming ? 'content.success' : 'content.primary'}
            name={incoming ? 'south-west' : 'north-east'}
            size="s20"
          />
        </Box>
        <Box fill gap="s2">
          <RnText numberOfLines={1} variant="body">{`${VERBS[item.direction]} ${item.asset.symbol}`}</RnText>
          <RnText color="content.secondary" numberOfLines={1} variant="footnote">
            {`${counterparty} · ${formatWhen(item.timestamp)}`}
          </RnText>
        </Box>
        <Box align="flex-end" gap="s4">
          <RnText
            color={incoming ? 'content.success' : 'content.primary'}
            monospacedDigit
            numberOfLines={1}
            variant="subheadlineMedium"
          >
            {amount}
          </RnText>
          {item.status === 'confirmed' ? (
            <RnText color="content.tertiary" variant="caption">
              {network.name}
            </RnText>
          ) : (
            <Pill
              label={item.status === 'pending' ? 'Pending' : 'Failed'}
              tone={item.status === 'pending' ? 'neutral' : 'destructive'}
            />
          )}
        </Box>
      </Pressable>
    </Box>
  )
})
