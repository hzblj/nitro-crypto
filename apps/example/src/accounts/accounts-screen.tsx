import {
  ActivityIndicator,
  Box,
  Button,
  EmptyState,
  Island,
  RnText,
  SegmentedControl,
  Stepper,
  TextField,
} from '@hzblj/kara-ui'
import {hex} from '@hzblj/nitro-crypto'
import {useState} from 'react'

import {type AppAccount, type AppCrypto, type ChainId, useAccount, useCrypto} from '../crypto'
import {Card, Lead, Page, Pill, Section, Value} from '../ui'

const CHAINS: readonly {id: ChainId; label: string}[] = [
  {id: 'ethereum', label: 'ETH'},
  {id: 'bitcoin', label: 'BTC'},
  {id: 'solana', label: 'SOL'},
  {id: 'tron', label: 'TRX'},
]

type Detail = {readonly label: string; readonly value: string; readonly copyAs?: string}

/** What each chain has to say about its account, beyond the address. The app knows its chains; the core does not. */
const detailsOf = (account: AppAccount<ChainId>): Detail[] => {
  switch (account.chain) {
    case 'ethereum':
      return [
        {copyAs: 'public key', label: 'Public key (uncompressed SEC1)', value: account.publicKey},
        {label: 'Network', value: `${account.network.name}, chain id ${account.network.chainId}`},
      ]
    case 'bitcoin':
      return [
        {copyAs: 'public key', label: 'Public key (compressed SEC1)', value: hex.encode(account.publicKey)},
        {label: 'Network and type', value: `${account.network}, native SegWit (${account.addressType.toUpperCase()})`},
        {copyAs: 'script', label: 'scriptPubKey', value: hex.encode(account.scriptPubKey)},
      ]
    case 'solana':
      return [
        {copyAs: 'public key', label: 'Public key (Ed25519)', value: hex.encode(account.publicKey)},
        {label: 'Cluster', value: account.cluster},
      ]
    case 'tron':
      return []
  }
}

/** The adapter's own verdict on the address it just derived: format, checksum, network. */
const Validation = ({account, crypto}: {account: AppAccount<ChainId>; crypto: AppCrypto}) => {
  const result = crypto.chains[account.chain].validateAddress(account.address)
  const checksum = 'checksum' in result ? result.checksum : undefined
  const type = 'type' in result && typeof result.type === 'string' ? result.type : undefined
  return (
    <Box gap="s6" row wrap testID="account-validation">
      <Pill
        label={result.valid ? 'Valid address' : 'Invalid address'}
        tone={result.valid ? 'success' : 'destructive'}
      />
      {checksum ? <Pill label={checksum === 'valid' ? 'EIP-55 checksum' : 'No checksum'} tone="accent" /> : null}
      {type ? <Pill label={type.toUpperCase()} tone="accent" /> : null}
      {account.chain === 'solana' ? <Pill label={`${account.publicKey.length}-byte key`} /> : null}
    </Box>
  )
}

const AccountCard = ({chain, n}: {chain: ChainId; n: number}) => {
  const {crypto} = useCrypto()
  const state = useAccount(chain, n)

  if (state.status === 'failed') {
    return (
      <Card>
        <RnText color="content.destructive" variant="subheadline">
          {state.message}
        </RnText>
      </Card>
    )
  }
  if (state.status !== 'ready' || !crypto) {
    return (
      <Card>
        <ActivityIndicator accessibilityLabel="Deriving the account" />
      </Card>
    )
  }
  const {account} = state
  return (
    <Card testID={`account-${chain}`}>
      <Value copyAs="address" label="Address" testID="account-address" value={account.address} />
      <Validation account={account} crypto={crypto} />
      {detailsOf(account).map(detail => (
        <Value copyAs={detail.copyAs} key={detail.label} label={detail.label} value={detail.value} />
      ))}
      <Value label="Derivation path" testID="account-path" value={account.path} />
    </Card>
  )
}

/** Any address, checked by the selected chain's adapter. */
const CheckAddress = ({chain}: {chain: ChainId}) => {
  const {crypto} = useCrypto()
  const [text, setText] = useState('')
  const result = crypto && text.trim() ? crypto.chains[chain].validateAddress(text.trim()) : null

  return (
    <Section
      caption="Paste an address of any chain: the selected adapter says whether it is one of its own, and why not."
      title="Check an address"
    >
      <Island>
        <TextField label="Address" onChangeText={setText} testID="check-address" />
      </Island>
      {result ? (
        <Card testID="check-result">
          <Box align="center" gap="s8" row>
            <Pill label={result.valid ? 'Valid' : 'Invalid'} tone={result.valid ? 'success' : 'destructive'} />
            <RnText fill selectable variant="footnote">
              {result.valid ? result.normalized : result.reason}
            </RnText>
          </Box>
        </Card>
      ) : null}
    </Section>
  )
}

export const AccountsScreen = () => {
  const {createWallet, wallet} = useCrypto()
  const [chainIndex, setChainIndex] = useState(0)
  const [n, setN] = useState(0)
  const chain = CHAINS[chainIndex]?.id ?? 'ethereum'

  if (!wallet) {
    return (
      <Page>
        <Island>
          <EmptyState
            action={
              <Button label="Create a demo wallet" onPress={() => createWallet()} testID="accounts-create-wallet" />
            }
            description="Accounts are derived from a wallet's seed. Create one here, or on the Wallet tab."
            icon="wallet"
            title="No demo wallet"
          />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="accounts">
      <Lead>
        One seed, every chain: each adapter derives its own key at its own path, and turns the public key into its own
        address format.
      </Lead>
      <SegmentedControl
        onChange={setChainIndex}
        selectedIndex={chainIndex}
        testID="chain"
        values={CHAINS.map(entry => entry.label)}
      />
      <Island>
        <Stepper label="Account number" max={99} min={0} onValueChange={setN} value={n} />
      </Island>
      <AccountCard chain={chain} n={n} />
      <CheckAddress chain={chain} />
    </Page>
  )
}
