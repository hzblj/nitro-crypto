import {Box, Chip, EmptyState, Island, RnText, useAppTheme} from '@hzblj/kara-ui'
import {SectionList} from '@legendapp/list/section-list'
import {useCallback, useMemo, useState} from 'react'
import {type SectionListRenderItemInfo, StyleSheet} from 'react-native'

import {Lead, Notice, Page} from '../../components'
import {NETWORKS} from '../../config'
import {CHAIN_IDS, type ChainId} from '../../core'
import {useAllActivity, useWalletStatus} from '../../hooks'
import {type ActivityItem} from '../../services'
import {ActivityPlaceholder} from './activity-list'
import {ActivityRow} from './activity-row'

const FILTERS: readonly (ChainId | 'all')[] = ['all', ...CHAIN_IDS]
/** A row: 40 points of icon or two lines of text, and 12 above and below. Legend List measures the real one. */
const ROW_HEIGHT = 68
const DAY_MS = 24 * 60 * 60 * 1000

type Day = {readonly title: string; readonly data: readonly ActivityItem[]}

const dayTitle = (timestamp: number | undefined, today: number): string => {
  if (timestamp === undefined) {
    return 'Pending'
  }

  const day = new Date(timestamp)
  day.setHours(0, 0, 0, 0)
  const ago = Math.round((today - day.getTime()) / DAY_MS)

  if (ago <= 0) {
    return 'Today'
  }
  if (ago === 1) {
    return 'Yesterday'
  }
  return day.toLocaleDateString(undefined, {day: 'numeric', month: 'long', weekday: 'long'})
}

/** Newest first already: consecutive items of one day make one section. */
const byDay = (items: readonly ActivityItem[]): Day[] => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const days: {title: string; data: ActivityItem[]}[] = []

  for (const item of items) {
    const title = dayTitle(item.timestamp, today.getTime())
    const last = days[days.length - 1]

    if (last?.title === title) {
      last.data.push(item)
    } else {
      days.push({data: [item], title})
    }
  }

  return days
}

const keyExtractor = (item: ActivityItem) => item.id

const renderItem = ({index, item, section}: SectionListRenderItemInfo<ActivityItem, Day>) => (
  <ActivityRow first={index === 0} item={item} last={index === section.data.length - 1} />
)

const renderSectionHeader = ({section}: {section: Day}) => (
  <RnText color="content.secondary" pb="s8" pt="s24" variant="footnoteMedium">
    {section.title.toUpperCase()}
  </RnText>
)

const Header = ({
  errors,
  filter,
  onFilter,
}: {
  errors: readonly string[]
  filter: ChainId | 'all'
  onFilter: (filter: ChainId | 'all') => void
}) => (
  <Box gap="s24" pt="s8">
    <Lead>Sent and received on Sepolia, Bitcoin testnet4 and Solana devnet. Tap a row to open it in the explorer.</Lead>
    <Box gap="s8" row wrap>
      {FILTERS.map(id => (
        <Chip
          key={id}
          label={id === 'all' ? 'All' : NETWORKS[id].name}
          onPress={() => onFilter(id)}
          selected={filter === id}
          testID={`filter-${id}`}
        />
      ))}
    </Box>
    {errors.map(error => (
      <Notice key={error} text={error} title="A network did not answer" tone="destructive" />
    ))}
  </Box>
)

/**
 * Every chain's history in one virtualized list, grouped by day: Legend List renders what is on screen and recycles
 * the rows, so a long history scrolls without dropping frames.
 */
export const ActivityScreen = () => {
  const theme = useAppTheme()
  const status = useWalletStatus()
  const {errors, items, loading, refresh} = useAllActivity()
  const [filter, setFilter] = useState<ChainId | 'all'>('all')
  const [refreshing, setRefreshing] = useState(false)
  const sections = useMemo(
    () => byDay(filter === 'all' ? items : items.filter(item => item.chain === filter)),
    [filter, items]
  )
  const onRefresh = useCallback(() => {
    setRefreshing(true)
    refresh().finally(() => setRefreshing(false))
  }, [refresh])

  if (status !== 'unlocked') {
    return (
      <Page>
        <Island>
          <EmptyState
            description="Create or import a wallet on the Wallet tab: its history shows here."
            icon="receipt-long"
            title="No wallet yet"
          />
        </Island>
      </Page>
    )
  }

  return (
    <SectionList
      ListEmptyComponent={
        loading ? (
          <Box pt="s24">
            <ActivityPlaceholder rows={6} />
          </Box>
        ) : (
          <Island mt="s24">
            <EmptyState
              description="Fund an address from a faucet (Receive, on the Wallet tab) and it shows up here."
              icon="receipt-long"
              title="Nothing yet"
            />
          </Island>
        )
      }
      ListHeaderComponent={<Header errors={errors} filter={filter} onFilter={setFilter} />}
      contentContainerStyle={styles.content}
      contentInsetAdjustmentBehavior="automatic"
      estimatedItemSize={ROW_HEIGHT}
      keyExtractor={keyExtractor}
      onRefresh={onRefresh}
      recycleItems
      refreshing={refreshing}
      renderItem={renderItem}
      renderSectionHeader={renderSectionHeader}
      sections={sections}
      style={{backgroundColor: theme.color('surface.base')}}
      testID="activity"
    />
  )
}

const styles = StyleSheet.create({content: {paddingBottom: 96, paddingHorizontal: 20}})
