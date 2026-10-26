import {Box, Pressable, RnIcon, RnText, Skeleton} from '@hzblj/kara-ui'

import {TokenBadge} from '../../components'
import {NETWORKS} from '../../config'
import {type ChainSummary} from '../../hooks'
import {formatUnits, formatUsd, shortAddress} from '../../utils'

type NetworkRowProps = {
  readonly address: string
  readonly onPress: () => void
  readonly summary: ChainSummary
}

/** A network on the home screen: its coin, the account's address and curve, and what the account holds. */
export const NetworkRow = ({address, onPress, summary}: NetworkRowProps) => {
  const network = NETWORKS[summary.chain]
  const {native} = network

  return (
    <Pressable
      accessibilityLabel={`${network.name}, ${summary.balance === undefined ? 'loading' : formatUnits(summary.balance, native.decimals)} ${native.symbol}`}
      align="center"
      gap="s12"
      onPress={onPress}
      pressEffect="opacity"
      py="s12"
      row
      testID={`network-${summary.chain}`}
    >
      <TokenBadge symbol={native.symbol} />
      <Box fill gap="s2">
        <RnText variant="headline">{network.name}</RnText>
        <RnText color="content.secondary" numberOfLines={1} variant="footnote">
          {`${shortAddress(address)} · ${network.curve}`}
        </RnText>
      </Box>
      <Box align="flex-end" gap="s2">
        {summary.balance === undefined ? (
          summary.error ? (
            <RnText color="content.destructive" variant="footnote">
              Offline
            </RnText>
          ) : (
            <Skeleton h={16} w={80} />
          )
        ) : (
          <>
            <RnText monospacedDigit variant="subheadlineMedium">
              {`${formatUnits(summary.balance, native.decimals, 5)} ${native.symbol}`}
            </RnText>
            <RnText color="content.secondary" monospacedDigit variant="footnote">
              {formatUsd(summary.usd)}
            </RnText>
          </>
        )}
      </Box>
      <RnIcon color="content.tertiary" name="chevron-right" size="s20" />
    </Pressable>
  )
}
