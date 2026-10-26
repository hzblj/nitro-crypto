import {Box, EmptyState, Island, RnText, Skeleton} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {Fragment} from 'react'
import {ActionButton, ActionRow, Hairline, Page, Pill, Section} from '../../components'
import {useAllActivity, usePortfolio, useUnlockedWallet, useWalletStatus} from '../../hooks'
import {useSessionStore} from '../../store'
import {formatUsd} from '../../utils'
import {ActivityList, ActivityPlaceholder} from '../activity'
import {NetworkRow} from './network-row'
import {Welcome} from './welcome'

const Dashboard = () => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const portfolio = usePortfolio()
  const activity = useAllActivity()

  if (!wallet) {
    return null
  }

  return (
    <Page onRefresh={() => Promise.all([portfolio.refresh(), activity.refresh()])} testID="home">
      <Box gap="s4">
        <Box align="center" gap="s8" row>
          <RnText color="content.secondary" variant="subheadline">
            Total portfolio
          </RnText>
          <Pill label="Testnet" tone="accent" />
        </Box>
        {portfolio.total === undefined && portfolio.loading ? (
          <Skeleton h={48} testID="portfolio-total-loading" w="55%" />
        ) : (
          <RnText monospacedDigit testID="portfolio-total" variant="headingXl">
            {formatUsd(portfolio.total)}
          </RnText>
        )}
        <RnText color="content.secondary" variant="footnote">
          At mainnet prices. Testnet coins are worth nothing.
        </RnText>
      </Box>
      <ActionRow>
        <ActionButton icon="north-east" label="Send" onPress={() => router.push('/send')} testID="action-send" />
        <ActionButton
          icon="south-west"
          label="Receive"
          onPress={() => router.push('/receive')}
          testID="action-receive"
        />
        <ActionButton icon="signature" label="Sign" onPress={() => router.push('/sign')} testID="action-sign" />
        <ActionButton icon="qr-code-scanner" label="Scan" onPress={() => router.push('/scan')} testID="action-scan" />
      </ActionRow>
      <Section title="Networks">
        <Box bg="surface.primary" borderRadius="large" px="s16">
          {portfolio.chains.map((summary, index) => (
            <Fragment key={summary.chain}>
              {index > 0 ? <Hairline inset="s56" /> : null}
              <NetworkRow
                address={wallet.accounts[summary.chain].address}
                onPress={() => router.push({params: {chain: summary.chain}, pathname: '/network/[chain]'})}
                summary={summary}
              />
            </Fragment>
          ))}
        </Box>
      </Section>
      <Section title="Recent activity">
        {activity.items.length > 0 ? (
          <ActivityList items={activity.items.slice(0, 5)} />
        ) : activity.loading ? (
          <ActivityPlaceholder />
        ) : (
          <RnText color="content.secondary" variant="subheadline">
            Nothing yet. Receive some testnet coins from a faucet to begin.
          </RnText>
        )}
      </Section>
    </Page>
  )
}

/** The dashboard's shape while the app decides where it starts: a frame, not a spinner. */
const DashboardPlaceholder = () => (
  <Page>
    <Box gap="s8">
      <Skeleton h={14} w="30%" />
      <Skeleton h={48} w="55%" />
    </Box>
    <ActivityPlaceholder rows={3} />
  </Page>
)

/** The Wallet tab: the welcome without a wallet, the dashboard with one. A locked wallet is behind the lock screen. */
export const HomeScreen = () => {
  const status = useWalletStatus()
  const problem = useSessionStore.use.problem()

  switch (status) {
    case 'loading':
      return <DashboardPlaceholder />
    case 'unavailable':
      return (
        <Page>
          <Island>
            <EmptyState description={problem ?? undefined} icon="warning-filled" title="No native engine" />
          </Island>
        </Page>
      )
    case 'empty':
      return (
        <Page>
          <Welcome />
        </Page>
      )
    default:
      return <Dashboard />
  }
}
