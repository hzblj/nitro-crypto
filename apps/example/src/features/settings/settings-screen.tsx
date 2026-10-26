import {Alert, Button, EmptyState, Island, LabeledContent, SegmentedControl} from '@hzblj/kara-ui'
import {VERSION} from '@hzblj/nitro-crypto'
import {useRouter} from 'expo-router'
import {Fragment, useState} from 'react'
import {Page, RowDivider, Rows, Section} from '../../components'
import {NETWORKS} from '../../config'
import {CHAIN_IDS, lockWallet, removeWallet, walletCrypto} from '../../core'
import {useUnlockedWallet} from '../../hooks'
import {type AutoLock, useWalletStore} from '../../store'

const host = (url: string) => url.replace(/^https:\/\//, '').split('/')[0] ?? url

const AUTO_LOCKS: readonly {value: AutoLock; label: string}[] = [
  {label: 'Immediately', value: 'immediately'},
  {label: '1 minute', value: 'minute'},
  {label: '5 minutes', value: 'five-minutes'},
]

const PROTECTION = {
  biometrics: (method: string) => `${method} guards the Keychain item itself: without it, the phrase cannot be read.`,
  none: () => 'This device has no passcode: only the Keychain guards the phrase.',
  passcode: () => 'The app asks for the device passcode before it reads the phrase.',
} as const

export const SettingsScreen = () => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const crypto = walletCrypto()
  const autoLock = useWalletStore.use.autoLock()
  const setAutoLock = useWalletStore.use.setAutoLock()
  const [confirmRemove, setConfirmRemove] = useState(false)

  if (!wallet || !crypto) {
    return (
      <Page>
        <Island>
          <EmptyState
            description="Create or import a wallet on the Wallet tab."
            icon="settings"
            title="No wallet yet"
          />
        </Island>
      </Page>
    )
  }

  const {record} = wallet

  return (
    <Page testID="settings">
      <Section title="Wallet">
        <Island>
          <Rows>
            <LabeledContent label="Fingerprint" testID="settings-fingerprint" value={record.fingerprint} />
            <RowDivider />
            <LabeledContent
              label="Recovery phrase"
              value={`${record.words} words, ${record.origin === 'created' ? 'created here' : 'imported'}`}
            />
            <RowDivider />
            <LabeledContent label="Added" value={new Date(record.createdAt).toLocaleDateString()} />
          </Rows>
        </Island>
      </Section>
      <Section caption={PROTECTION[record.protection](record.method)} title="Security">
        <Island>
          <Rows>
            <LabeledContent label="Unlock with" value={record.method} />
            <RowDivider />
            <LabeledContent
              icon="key"
              label="Show recovery phrase"
              onPress={() => router.push('/settings/recovery-phrase')}
              testID="show-recovery-phrase"
            />
            <RowDivider />
            <LabeledContent icon="lock" label="Lock now" onPress={() => lockWallet()} testID="lock-now" />
          </Rows>
        </Island>
      </Section>
      <Section
        caption="How long the app may sit in the background before the keys are wiped from the engine and it asks again."
        title="Auto-lock"
      >
        <SegmentedControl
          onChange={index => setAutoLock(AUTO_LOCKS[index]?.value ?? 'minute')}
          selectedIndex={Math.max(
            0,
            AUTO_LOCKS.findIndex(option => option.value === autoLock)
          )}
          testID="auto-lock"
          values={AUTO_LOCKS.map(option => option.label)}
        />
      </Section>
      <Section
        caption="Public endpoints, no API keys: balances and broadcasts go through them, keys never do."
        title="Networks"
      >
        <Island>
          <Rows>
            {CHAIN_IDS.map((chain, index) => {
              const network = NETWORKS[chain]
              return (
                <Fragment key={chain}>
                  {index > 0 ? <RowDivider /> : null}
                  <LabeledContent label={`${network.name} ${network.testnet}`} value={host(network.endpoint)} />
                </Fragment>
              )
            })}
            <RowDivider />
            <LabeledContent label="Ethereum history" value={host(NETWORKS.ethereum.indexer ?? '')} />
            <RowDivider />
            <LabeledContent label="Prices" value="api.coingecko.com" />
          </Rows>
        </Island>
      </Section>
      <Section caption="Every key and signature of this wallet comes from this engine." title="Library">
        <Island>
          <Rows>
            <LabeledContent label="@hzblj/nitro-crypto" value={VERSION} />
            <RowDivider />
            <LabeledContent label="Engine" value={`${crypto.info.engineVersion}, C ABI ${crypto.info.abiVersion}`} />
            <RowDivider />
            <LabeledContent label="Secrets in the engine" value={String(crypto.liveHandles())} />
          </Rows>
        </Island>
      </Section>
      <Section
        caption="Removes the recovery phrase from this device's Keychain. Only the words you wrote down can bring the wallet back."
        title="Danger zone"
      >
        <Island>
          <Button
            label="Remove wallet from this device"
            onPress={() => setConfirmRemove(true)}
            testID="remove-wallet"
            variant="destructive"
          />
          <Alert
            confirmLabel="Remove"
            destructive
            message="Without your written recovery phrase, this wallet and everything on it are gone for good."
            onConfirm={() => removeWallet()}
            onDismiss={() => setConfirmRemove(false)}
            title="Remove this wallet?"
            visible={confirmRemove}
          />
        </Island>
      </Section>
    </Page>
  )
}
