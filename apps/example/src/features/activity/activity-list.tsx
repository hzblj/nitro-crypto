import {Box, Skeleton} from '@hzblj/kara-ui'

import type {ActivityItem} from '../../services'
import {ActivityRow} from './activity-row'

/** A few rows in a card, not virtualized: the home and network screens show at most ten. */
export const ActivityList = ({items}: {items: readonly ActivityItem[]}) => (
  <Box testID="activity-list">
    {items.map((item, index) => (
      <ActivityRow first={index === 0} item={item} key={item.id} last={index === items.length - 1} />
    ))}
  </Box>
)

/** Rows the shape of real ones while the history loads. */
export const ActivityPlaceholder = ({rows = 3}: {rows?: number}) => (
  <Box bg="surface.primary" borderRadius="large" gap="s20" p="s16" testID="activity-placeholder">
    {Array.from({length: rows}, (_, row) => (
      <Box align="center" gap="s12" key={row} row>
        <Skeleton borderRadius="full" h={40} w={40} />
        <Box fill gap="s8">
          <Skeleton h={14} w="45%" />
          <Skeleton h={12} w="70%" />
        </Box>
        <Box align="flex-end" gap="s8">
          <Skeleton h={14} w={72} />
          <Skeleton h={10} w={48} />
        </Box>
      </Box>
    ))}
  </Box>
)
