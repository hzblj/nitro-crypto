import {Box, Button, Island, RnIcon, RnText, VStack} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'

import {Notice} from '../../components'

/** The first screen of a device without a wallet: create one, or bring a recovery phrase. */
export const Welcome = () => {
  const router = useRouter()

  return (
    <Box gap="s32" pt="s24" testID="welcome">
      <Box align="center" gap="s16">
        <Box align="center" bg="fill.accent.base" borderRadius="full" h={88} justify="center" w={88}>
          <RnIcon color="content.accent" name="wallet" size="s48" />
        </Box>
        <RnText align="center" variant="headingM">
          A wallet on a Zig engine
        </RnText>
        <RnText align="center" color="content.secondary" variant="body">
          One recovery phrase for Ethereum, Bitcoin and Solana. Keys are derived, held and used inside the native
          engine, and every transaction is built and signed on this device.
        </RnText>
      </Box>
      <Island>
        <VStack spacing="s12" wide>
          <Button
            label="Create a new wallet"
            onPress={() => router.push('/onboarding/create')}
            testID="create-wallet"
          />
          <Button
            label="I have a recovery phrase"
            onPress={() => router.push('/onboarding/import')}
            testID="import-wallet"
            variant="secondary"
          />
        </VStack>
      </Island>
      <Notice
        text="Sepolia, Bitcoin testnet4 and Solana devnet only. Testnet coins are free from faucets and worth nothing: never send real funds here."
        title="Testnets only"
        tone="warning"
      />
    </Box>
  )
}
