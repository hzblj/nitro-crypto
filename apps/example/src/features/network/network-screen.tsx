import {Box, Island, LabeledContent, Pressable, RnText, Skeleton} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {openBrowserAsync} from 'expo-web-browser'
import {Fragment} from 'react'
import {
  ActionButton,
  ActionRow,
  Card,
  Hairline,
  Notice,
  Page,
  RowDivider,
  Rows,
  Section,
  TokenBadge,
  Value,
} from '../../components'
import {NETWORKS} from '../../config'
import {type ChainId} from '../../core'
import {useActivity, useHoldings, usePrices, useUnlockedWallet} from '../../hooks'
import {type Holding} from '../../services'
import {formatUnits, formatUsd, usdValue} from '../../utils'
import {ActivityList, ActivityPlaceholder} from '../activity'

const HoldingRow = ({holding, onPress, price}: {holding: Holding; onPress: () => void; price: number | undefined}) => (
  <Pressable
    accessibilityLabel={`Send ${holding.asset.symbol}`}
    align="center"
    gap="s12"
    onPress={onPress}
    pressEffect="opacity"
    py="s12"
    row
    testID={`holding-${holding.asset.id}`}
  >
    <TokenBadge size={40} symbol={holding.asset.symbol} />
    <Box fill gap="s2">
      <RnText variant="body">{holding.asset.name}</RnText>
      <RnText color="content.secondary" variant="footnote">
        {holding.asset.contract ? `Token · ${holding.asset.symbol}` : `Native coin · ${holding.asset.symbol}`}
      </RnText>
    </Box>
    <Box align="flex-end" gap="s2">
      <RnText monospacedDigit variant="subheadlineMedium">
        {formatUnits(holding.balance, holding.asset.decimals)}
      </RnText>
      <RnText color="content.secondary" monospacedDigit variant="footnote">
        {formatUsd(usdValue(holding.balance, holding.asset.decimals, price))}
      </RnText>
    </Box>
  </Pressable>
)

/** The asset rows' shape while the balances load. */
const HoldingsPlaceholder = ({rows}: {rows: number}) => (
  <Box bg="surface.primary" borderRadius="large" gap="s20" p="s16">
    {Array.from({length: rows}, (_, row) => (
      <Box align="center" gap="s12" key={row} row>
        <Skeleton borderRadius="full" h={40} w={40} />
        <Box fill gap="s8">
          <Skeleton h={14} w="40%" />
          <Skeleton h={12} w="30%" />
        </Box>
        <Box align="flex-end" gap="s8">
          <Skeleton h={14} w={64} />
          <Skeleton h={12} w={44} />
        </Box>
      </Box>
    ))}
  </Box>
)

export const NetworkScreen = ({chain}: {chain: ChainId}) => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const network = NETWORKS[chain]
  const holdings = useHoldings(chain)
  const activity = useActivity(chain)
  const prices = usePrices()
  const account = wallet?.accounts[chain]

  if (!wallet || !account) {
    return null
  }

  const native = holdings.data?.find(holding => holding.asset.id === network.native.id)

  return (
    <Page onRefresh={() => Promise.all([holdings.refresh(), activity.refresh()])} testID={`network-screen-${chain}`}>
      <Box gap="s4">
        {native ? (
          <RnText monospacedDigit testID="network-balance" variant="headingL">
            {`${formatUnits(native.balance, network.native.decimals, 8)} ${network.native.symbol}`}
          </RnText>
        ) : (
          <Skeleton h={40} w="60%" />
        )}
        <RnText color="content.secondary" variant="subheadline">
          {`${network.testnet} · ${formatUsd(native ? usdValue(native.balance, network.native.decimals, prices.data?.[network.native.priceId]) : undefined)} at mainnet prices`}
        </RnText>
      </Box>
      <ActionRow>
        <ActionButton
          icon="north-east"
          label="Send"
          onPress={() => router.push({params: {asset: network.native.id}, pathname: '/send'})}
        />
        <ActionButton
          icon="south-west"
          label="Receive"
          onPress={() => router.push({params: {chain}, pathname: '/receive'})}
        />
        <ActionButton
          icon="water-drop"
          label="Faucet"
          onPress={() => openBrowserAsync(network.faucets[0]?.url ?? '')}
          testID="action-faucet"
        />
      </ActionRow>
      {holdings.error ? <Notice text={holdings.error} title="Balances did not load" tone="destructive" /> : null}
      <Section title="Assets">
        {holdings.data ? null : <HoldingsPlaceholder rows={network.tokens.length + 1} />}
        <Box bg="surface.primary" borderRadius="large" px="s16">
          {(holdings.data ?? []).map((holding, index) => (
            <Fragment key={holding.asset.id}>
              {index > 0 ? <Hairline inset="s48" /> : null}
              <HoldingRow
                holding={holding}
                onPress={() => router.push({params: {asset: holding.asset.id}, pathname: '/send'})}
                price={prices.data?.[holding.asset.priceId]}
              />
            </Fragment>
          ))}
        </Box>
      </Section>
      <Section
        caption="The private key never leaves the engine's native memory: JavaScript holds a handle, and every signature is made in Zig."
        title="Account"
      >
        <Card>
          <Value copyAs="address" label="Address" testID="network-address" value={account.address} />
          <Value label="Derivation path" value={account.path} />
        </Card>
        <Island>
          <Rows>
            <LabeledContent label="Network" value={`${network.name} ${network.testnet}`} />
            <RowDivider />
            <LabeledContent label="Curve" value={network.curve} />
            <RowDivider />
            <LabeledContent label="Node" value={network.endpoint.replace(/^https:\/\//, '').split('/')[0]} />
            <RowDivider />
            <LabeledContent
              icon="open-in-new"
              label="Open in explorer"
              onPress={() => openBrowserAsync(network.explorer.address(account.address))}
            />
          </Rows>
        </Island>
      </Section>
      <Section title="Activity">
        {activity.data && activity.data.length > 0 ? (
          <ActivityList items={activity.data.slice(0, 10)} />
        ) : activity.loading ? (
          <ActivityPlaceholder />
        ) : (
          <RnText color="content.secondary" variant="subheadline">
            {activity.error ?? 'No transactions yet.'}
          </RnText>
        )}
      </Section>
      <Section title="Faucets">
        <Island>
          <Rows>
            {network.faucets.map((entry, index) => (
              <Fragment key={entry.url}>
                {index > 0 ? <RowDivider /> : null}
                <LabeledContent icon="water-drop" label={entry.label} onPress={() => openBrowserAsync(entry.url)} />
              </Fragment>
            ))}
          </Rows>
        </Island>
      </Section>
    </Page>
  )
}
