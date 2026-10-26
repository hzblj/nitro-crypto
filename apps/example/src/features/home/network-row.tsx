import {Box, Pressable, RnIcon, RnText, Skeleton} from '@hzblj/kara-ui'

import {TokenBadge} from '../../components'
import {NETWORKS} from '../../config'
import {type ChainSummary} from '../../hooks'
import type {Holding} from '../../services'
import {formatUnits, formatUsd, shortAddress} from '../../utils'

type NetworkRowProps = {
  readonly address: string
  readonly onPress: () => void
  readonly summary: ChainSummary
}

const heldAssets = (summary: ChainSummary): readonly Holding[] =>
  (summary.holdings ?? []).filter(({balance}) => balance > 0n)

const amount = ({asset, balance}: Holding): string => `${formatUnits(balance, asset.decimals, 5)} ${asset.symbol}`

/** What makes up the value, in one line: the first coin or token held and how many more, or the coin at zero. */
const heldLabel = (summary: ChainSummary): string => {
  const [first, ...rest] = heldAssets(summary)

  if (!first) {
    return `0 ${NETWORKS[summary.chain].native.symbol}`
  }

  return rest.length > 0 ? `${amount(first)} +${rest.length}` : amount(first)
}

/**
 * A network on the home screen: its coin, the account's address and curve, what the whole network is worth and what
 * makes that up. The value leads, so a network holding only tokens never reads as worth its coin's zero.
 */
export const NetworkRow = ({address, onPress, summary}: NetworkRowProps) => {
  const network = NETWORKS[summary.chain]
  const loaded = summary.balance !== undefined

  return (
    <Pressable
      accessibilityLabel={`${network.name}, ${loaded ? [formatUsd(summary.usd), ...heldAssets(summary).map(amount)].join(', ') : 'loading'}`}
      align="center"
      gap="s12"
      onPress={onPress}
      pressEffect="opacity"
      py="s12"
      row
      testID={`network-${summary.chain}`}
    >
      <TokenBadge symbol={network.native.symbol} />
      <Box fill gap="s2">
        <RnText numberOfLines={1} variant="headline">
          {network.name}
        </RnText>
        <RnText color="content.secondary" numberOfLines={1} variant="footnote">
          {`${shortAddress(address)} · ${network.curve}`}
        </RnText>
      </Box>
      <Box align="flex-end" gap="s2">
        {loaded ? (
          <>
            <RnText monospacedDigit variant="subheadlineMedium">
              {formatUsd(summary.usd)}
            </RnText>
            <RnText color="content.secondary" monospacedDigit numberOfLines={1} variant="footnote">
              {heldLabel(summary)}
            </RnText>
          </>
        ) : summary.error ? (
          <RnText color="content.destructive" variant="footnote">
            Offline
          </RnText>
        ) : (
          <Skeleton h={16} w={80} />
        )}
      </Box>
      <RnIcon color="content.tertiary" name="chevron-right" size="s20" />
    </Pressable>
  )
}
