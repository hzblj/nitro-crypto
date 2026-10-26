import {Box, Button, Island, LabeledContent, RnText, SegmentedControl, VStack} from '@hzblj/kara-ui'
import {openBrowserAsync} from 'expo-web-browser'
import {Fragment, useState} from 'react'
import {Share} from 'react-native'

import {Notice, Page, QrCode, RowDivider, Rows, Section, useCopy} from '../../components'
import {NETWORKS} from '../../config'
import {CHAIN_IDS, type ChainId} from '../../core'
import {useUnlockedWallet} from '../../hooks'

const ACCEPTS = {
  bitcoin:
    'Only Bitcoin testnet4 coins. A tb1 address of testnet3 or signet looks the same: coins sent from those never arrive here.',
  ethereum:
    'Sepolia ETH and Sepolia ERC-20 tokens (USDC). The same address works on every EVM chain: send nothing from mainnet.',
  solana: "Devnet SOL and devnet SPL tokens (USDC). Tokens land in this address's associated token account.",
} as const satisfies Record<ChainId, string>

export const ReceiveScreen = ({initial}: {initial?: ChainId}) => {
  const wallet = useUnlockedWallet()
  const copy = useCopy()
  const [index, setIndex] = useState(() => Math.max(0, CHAIN_IDS.indexOf(initial ?? 'ethereum')))
  const chain = CHAIN_IDS[index] ?? 'ethereum'
  const network = NETWORKS[chain]

  if (!wallet) {
    return null
  }

  const {address} = wallet.accounts[chain]

  return (
    <Page testID="receive">
      <SegmentedControl
        onChange={setIndex}
        selectedIndex={index}
        testID="receive-chain"
        values={CHAIN_IDS.map(id => NETWORKS[id].native.symbol)}
      />
      <Box align="center" gap="s16">
        <QrCode size={240} value={address} />
        <Box align="center" gap="s4">
          <RnText color="content.secondary" variant="footnote">
            {`Your ${network.name} ${network.testnet} address`}
          </RnText>
          <RnText align="center" monospaced selectable testID="receive-address" variant="subheadline">
            {address}
          </RnText>
        </Box>
      </Box>
      <Island>
        <VStack spacing="s12" wide>
          <Button label="Copy address" onPress={() => copy(address, 'address')} testID="copy-address" />
          <Button
            label="Share"
            onPress={() => Share.share({message: address, title: `${network.name} ${network.testnet} address`})}
            variant="secondary"
          />
        </VStack>
      </Island>
      <Notice text={ACCEPTS[chain]} title="What this address accepts" tone="warning" />
      <Section caption="Testnet coins are free; most faucets ask for a sign-in or a captcha." title="Get testnet coins">
        <Island>
          <Rows>
            {network.faucets.map((faucet, position) => (
              <Fragment key={faucet.url}>
                {position > 0 ? <RowDivider /> : null}
                <LabeledContent icon="water-drop" label={faucet.label} onPress={() => openBrowserAsync(faucet.url)} />
              </Fragment>
            ))}
          </Rows>
        </Island>
      </Section>
    </Page>
  )
}
