import {Button, Island, TextField} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useState} from 'react'

import {Lead, Notice, Page, Section} from '../../components'
import {checkPhrase} from '../../core'
import {useOnboarding} from './onboarding-context'

const REASONS = {
  INVALID_MNEMONIC: 'A word is not on the BIP-39 English list, or the count is not 12, 15, 18, 21 or 24.',
  MNEMONIC_CHECKSUM: 'Every word is valid, but the checksum fails: a word is wrong or out of order.',
} as const

/** A wallet from its recovery phrase: checked by the engine (word list and checksum) as it is typed. */
export const ImportScreen = () => {
  const router = useRouter()
  const {setDraft} = useOnboarding()
  const [text, setText] = useState('')
  const typed = text.trim().split(/\s+/u).filter(Boolean).length
  const check = typed >= 12 ? checkPhrase(text) : null

  const next = () => {
    setDraft({origin: 'imported', phrase: text.trim().toLowerCase().split(/\s+/u).join(' ')})
    router.push('/onboarding/protect')
  }

  return (
    <Page testID="onboarding-import">
      <Lead>
        Enter the 12 or 24 words, in order, separated by spaces. The same phrase opens the same addresses here as in
        MetaMask, Phantom or any BIP-84 Bitcoin wallet.
      </Lead>
      <Section
        caption={check && !check.valid ? REASONS[check.reason] : `${typed} ${typed === 1 ? 'word' : 'words'}`}
        title="Recovery phrase"
      >
        <Island>
          <TextField
            error={check !== null && !check.valid}
            label="Words"
            multiline
            onChangeText={setText}
            testID="import-phrase"
          />
        </Island>
      </Section>
      <Notice
        text="Only a phrase you made for testing. A phrase that guards real funds should never be typed into a demo app."
        title="Testnet only"
        tone="warning"
      />
      <Island>
        <Button disabled={!check?.valid} label="Continue" onPress={next} testID="import-continue" />
      </Island>
    </Page>
  )
}
