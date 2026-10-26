import {Box, Button, Island, RnIcon, RnText} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useEffect, useState} from 'react'
import {Lead, Notice, Page} from '../../components'
import {availableProtection, createWallet} from '../../core'
import type {Protection} from '../../store'
import {useOnboarding} from './onboarding-context'

const EXPLAIN = {
  biometrics: (method: string) =>
    `The phrase goes into this device's Keychain, readable only after ${method}. It never syncs to iCloud or a backup.`,
  none: () =>
    'This device has neither biometrics nor a passcode, so only the Keychain guards the phrase. Fine on a simulator, not on a phone.',
  passcode: () =>
    "The phrase goes into this device's Keychain, and the app asks for the device passcode before reading it.",
} as const

/** The last step: the phrase is stored under the device's strongest protection, and the wallet opens. */
export const ProtectScreen = () => {
  const router = useRouter()
  const {draft, setDraft} = useOnboarding()
  const [available, setAvailable] = useState<{protection: Protection; method: string} | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    availableProtection().then(setAvailable, () => setAvailable({method: 'None', protection: 'none'}))
  }, [])

  const save = async () => {
    const current = draft()
    if (!current) {
      setError('The phrase is gone from memory: start again.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await createWallet(current.phrase, current.origin)
      setDraft(null)
      // Closes the onboarding modal itself, not only its steps: the home tab shows the new wallet.
      router.dismissTo('/')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure))
      setBusy(false)
    }
  }

  const method = available?.method ?? '…'

  return (
    <Page testID="onboarding-protect">
      <Box align="center" gap="s16" pt="s16">
        <Box align="center" bg="fill.accent.base" borderRadius="full" h={88} justify="center" w={88}>
          <RnIcon color="content.accent" name={available?.protection === 'biometrics' ? 'face' : 'lock'} size="s40" />
        </Box>
        <RnText align="center" variant="headingS">
          {available?.protection === 'biometrics' ? `Protect it with ${method}` : 'Store it on this device'}
        </RnText>
      </Box>
      <Lead>{available ? EXPLAIN[available.protection](method) : 'Checking what this device offers…'}</Lead>
      <Notice
        text="While locked, no key exists anywhere in memory. Unlocking derives them in the engine again, and a minute in the background locks it."
        tone="neutral"
      />
      {error ? <Notice text={error} title="Not saved" tone="destructive" /> : null}
      <Island>
        <Button
          disabled={!available || busy}
          label={busy ? 'Saving…' : available?.protection === 'biometrics' ? `Use ${method}` : 'Save wallet'}
          onPress={save}
          testID="protect-save"
        />
      </Island>
    </Page>
  )
}
