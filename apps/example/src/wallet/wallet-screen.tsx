import {
  Box,
  Button,
  EmptyState,
  Island,
  LabeledContent,
  RnText,
  SegmentedControl,
  TextField,
  VStack,
} from '@hzblj/kara-ui'
import {MNEMONIC_LENGTHS, type MnemonicLength} from '@hzblj/nitro-crypto'
import {useEffect, useState} from 'react'

import {useCrypto, type WalletSummary} from '../crypto'
import {Card, DemoNotice, Lead, Page, Pill, RowDivider, Rows, Section} from '../ui'
import {TEST_MNEMONIC} from '../vectors'

const WORD_OPTIONS = [12, 24] as const satisfies readonly MnemonicLength[]

const fingerprintOf = (wallet: WalletSummary) => wallet.fingerprint.toString(16).padStart(8, '0')

const CreateWallet = ({onError}: {onError: (message: string) => void}) => {
  const {createWallet} = useCrypto()
  const [wordsIndex, setWordsIndex] = useState(0)
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)

  const create = async (mnemonic?: string) => {
    setBusy(true)
    try {
      const words = WORD_OPTIONS[wordsIndex] ?? MNEMONIC_LENGTHS[0]
      await createWallet(mnemonic ? {mnemonic, passphrase} : {passphrase, words})
    } catch (error) {
      onError(error instanceof Error ? error.message : String(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Section
        caption="The mnemonic comes from the operating system's CSPRNG inside the engine, and never leaves it: this version cannot show or export it. The passphrase is BIP-39's optional 25th word."
        title="New demo wallet"
      >
        <SegmentedControl
          onChange={setWordsIndex}
          selectedIndex={wordsIndex}
          testID="word-count"
          values={WORD_OPTIONS.map(words => `${words} words`)}
        />
        <Island>
          <VStack spacing="s12" wide>
            <TextField label="Passphrase (optional)" onChangeText={setPassphrase} secure testID="passphrase" />
            <Button
              disabled={busy}
              label={busy ? 'Creating…' : 'Create demo wallet'}
              onPress={() => create()}
              testID="create-wallet"
            />
          </VStack>
        </Island>
      </Section>
      <Section
        caption={`"${TEST_MNEMONIC}": the mnemonic BIP-84 publishes its vectors for, and the one this app's checks use. Known to everyone, so never for anything real.`}
        title="Test vector"
      >
        <Island>
          <Button
            disabled={busy}
            label="Load the published test mnemonic"
            onPress={() => create(TEST_MNEMONIC)}
            testID="load-test-wallet"
            variant="secondary"
          />
        </Island>
      </Section>
    </>
  )
}

const CurrentWallet = ({onDeleted, wallet}: {onDeleted: (zeroized: number) => void; wallet: WalletSummary}) => {
  const {deleteWallet, liveHandles} = useCrypto()

  return (
    <>
      <Section
        caption="Its seed, and every key derived from it, live in the engine's native memory, never in JavaScript. Nothing is written anywhere: a reload, a restart or a reinstall loses it, and Delete zeroizes it now."
        title="Demo wallet"
      >
        <Island>
          <Rows>
            <LabeledContent label="Fingerprint" testID="wallet-fingerprint" value={fingerprintOf(wallet)} />
            <RowDivider />
            <LabeledContent
              label="Source"
              value={wallet.origin === 'generated' ? 'Generated on this device' : 'Published test mnemonic'}
            />
            <RowDivider />
            <LabeledContent label="Mnemonic" value={`${wallet.words} words, not exportable`} />
            <RowDivider />
            <LabeledContent label="Created" value={wallet.createdAt.toLocaleTimeString()} />
            <RowDivider />
            <LabeledContent label="Secrets in the engine" testID="live-handles" value={String(liveHandles)} />
          </Rows>
        </Island>
      </Section>
      <Island>
        <Button
          label="Delete wallet"
          onPress={() => onDeleted(deleteWallet())}
          testID="delete-wallet"
          variant="destructive"
        />
      </Island>
    </>
  )
}

export const WalletScreen = () => {
  const {crypto, error, wallet} = useCrypto()
  const [notice, setNotice] = useState<{text: string; tone: 'destructive' | 'success'} | null>(null)

  // A new wallet makes the last one's notice stale.
  useEffect(() => {
    if (wallet) {
      setNotice(null)
    }
  }, [wallet])

  if (!crypto) {
    return (
      <Page>
        <Island>
          <EmptyState description={error?.message} icon="warning-filled" title="No native engine" />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="wallet">
      <Lead>
        One BIP-39 seed for every chain, held by the engine for as long as this wallet exists. There are no balances and
        no networks here: only keys, addresses and signatures.
      </Lead>
      <DemoNotice />
      {notice ? (
        <Card testID="wallet-notice">
          <Box align="center" gap="s8" row>
            <Pill label={notice.tone === 'success' ? 'Deleted' : 'Error'} tone={notice.tone} />
            <RnText fill variant="subheadline">
              {notice.text}
            </RnText>
          </Box>
        </Card>
      ) : null}
      {wallet ? (
        <CurrentWallet
          onDeleted={zeroized => setNotice({text: `${zeroized} secrets zeroized in the engine.`, tone: 'success'})}
          wallet={wallet}
        />
      ) : (
        <CreateWallet onError={text => setNotice({text, tone: 'destructive'})} />
      )}
    </Page>
  )
}
