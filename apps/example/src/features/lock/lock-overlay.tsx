import {Alert, Box, Button, Island, RnIcon, RnText, VStack} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useEffect, useRef, useState} from 'react'
import {AppState, StyleSheet} from 'react-native'
import {SafeAreaView} from 'react-native-safe-area-context'
import {Notice} from '../../components'
import {removeWallet, unlockWallet} from '../../core'
import {useCovered, useSessionStore, useWalletStore} from '../../store'

const Mark = () => (
  <Box align="center" gap="s16">
    <Box align="center" bg="fill.accent.base" borderRadius="full" h={88} justify="center" w={88}>
      <RnIcon color="content.accent" name="lock" size="s40" />
    </Box>
    <RnText align="center" variant="headingS">
      Nitro Wallet
    </RnText>
  </Box>
)

/**
 * Over everything while the wallet is locked, and while the app sits in the app switcher. Unlocking reads the phrase
 * from the Keychain (one Face ID prompt) and derives the keys in the engine again.
 */
export const LockOverlay = () => {
  const router = useRouter()
  const covered = useCovered()
  const status = useSessionStore.use.status()
  const reason = useSessionStore.use.lockReason()
  const problem = useSessionStore.use.problem()
  const lost = useSessionStore.use.lost()
  const record = useWalletStore.use.record()
  const [busy, setBusy] = useState(false)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const asked = useRef(false)
  const locked = status === 'locked'

  const tryUnlock = async () => {
    setBusy(true)
    try {
      await unlockWallet()
    } finally {
      setBusy(false)
    }
  }

  // Ask once when the app opens locked or comes back locked, as banking apps do; after that, and after locking by
  // hand, the button asks.
  useEffect(() => {
    if (!locked) {
      asked.current = false
      return
    }
    if (!asked.current && reason !== 'manual' && AppState.currentState === 'active') {
      asked.current = true
      tryUnlock()
    }
  })

  if (!locked && !covered) {
    return null
  }

  return (
    <Box absolute bg="surface.base" inset={0} testID="lock-overlay">
      <SafeAreaView style={styles.fill}>
        <Box flex={1} gap="s32" justify="center" px="s24">
          <Mark />
          {locked && record ? (
            <>
              <RnText align="center" color="content.secondary" variant="body">
                {`Locked. Its keys were wiped from the engine; ${record.method === 'None' ? 'unlocking' : record.method} brings them back.`}
              </RnText>
              {problem ? <Notice text={problem} tone="destructive" /> : null}
              <Island>
                <VStack spacing="s12" wide>
                  <Button
                    disabled={busy}
                    label={record.protection === 'none' ? 'Unlock' : `Unlock with ${record.method}`}
                    onPress={tryUnlock}
                    testID="unlock"
                  />
                  {lost ? (
                    <Button label="Remove and restore" onPress={() => setConfirmRemove(true)} variant="destructive" />
                  ) : null}
                </VStack>
                <Alert
                  confirmLabel="Remove"
                  destructive
                  message="The stored phrase is unreadable. Remove the wallet from this device, then restore it from the words you wrote down."
                  onConfirm={() => removeWallet().then(() => router.push('/onboarding/import'))}
                  onDismiss={() => setConfirmRemove(false)}
                  title="Restore from your phrase?"
                  visible={confirmRemove}
                />
              </Island>
            </>
          ) : null}
        </Box>
      </SafeAreaView>
    </Box>
  )
}

const styles = StyleSheet.create({fill: {flex: 1}})
