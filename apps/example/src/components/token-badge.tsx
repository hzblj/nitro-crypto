import {Box, RnText} from '@hzblj/kara-ui'

/** A coin's ticker in a circle: the wallet's stand-in for a logo, which a testnet coin does not have. */
export const TokenBadge = ({size = 44, symbol}: {size?: number; symbol: string}) => (
  <Box align="center" bg="fill.tertiary" borderRadius="full" h={size} justify="center" w={size}>
    <RnText variant={symbol.length > 3 ? 'captionMedium' : 'footnoteMedium'}>{symbol}</RnText>
  </Box>
)
