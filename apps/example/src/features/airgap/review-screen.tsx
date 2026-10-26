import type {UR} from '@hzblj/crypto-airgap'
import {Box, Button, Island, RnText, VStack} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useState} from 'react'
import {useWindowDimensions} from 'react-native'

import {AnimatedQr, Notice, Page, Pill} from '../../components'
import {NETWORKS} from '../../config'
import {accountsAt, confirmWithUser, signScannedRequest, walletCrypto} from '../../core'
import {useUnlockedWallet} from '../../hooks'
import {useAirgapStore} from '../../store'
import {RequestDetails} from './request-details'

/**
 * A scanned request, read and checked for this wallet: what it does, then Face ID, then the signature as a QR code for
 * the watch-only wallet to scan back. The keys never leave the engine, and this phone never needs a network.
 */
export const ReviewScreen = () => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const scanned = useAirgapStore.use.incoming()
  const clearIncoming = useAirgapStore.use.clearIncoming()
  const {width} = useWindowDimensions()
  const [answer, setAnswer] = useState<UR | null>(null)
  const [signing, setSigning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!wallet || !scanned) {
    return null
  }

  const network = NETWORKS[scanned.chain]
  const origin = scanned.chain === 'bitcoin' ? undefined : scanned.request.origin
  const method = wallet.record.protection === 'none' ? 'Sign' : `Sign with ${wallet.record.method}`

  const sign = async () => {
    const crypto = walletCrypto()

    if (!crypto || !(await confirmWithUser(`Sign this ${network.name} request`))) {
      return
    }

    setSigning(true)
    setError(null)

    try {
      setAnswer(await signScannedRequest(crypto, scanned, wallet.accounts, accountsAt))
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure))
    } finally {
      setSigning(false)
    }
  }

  const finish = () => {
    clearIncoming()
    router.back()
  }

  const crypto = walletCrypto()

  if (answer && crypto) {
    return (
      <Page testID="airgap-signed">
        <Box align="center" gap="s4">
          <Pill label="Signed" tone="success" />
          <RnText align="center" color="content.secondary" variant="subheadline">
            Show this to the watch-only wallet. It checks the signature against its request, then broadcasts.
          </RnText>
        </Box>
        <AnimatedQr sha256={crypto.hash.sha256} size={width - 40} testID="airgap-answer" ur={answer} />
        <Island>
          <Button label="Done" onPress={finish} testID="airgap-done" />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="airgap-review">
      <Box align="center" gap="s8" row wrap>
        <Pill label={`${network.name} ${network.testnet}`} tone="accent" />
        {origin ? <Pill label={`From ${origin}`} /> : null}
      </Box>
      <RequestDetails scanned={scanned} />
      {error ? <Notice text={error} title="Not signed" tone="destructive" /> : null}
      <Island>
        <VStack spacing="s12" wide>
          <Button disabled={signing} label={signing ? 'Signing…' : method} onPress={sign} testID="airgap-sign" />
          <Button disabled={signing} label="Reject" onPress={finish} variant="secondary" />
        </VStack>
      </Island>
      <RnText color="content.tertiary" variant="footnote">
        Everything above is read from the bytes that will be signed, not from what the other wallet says about them.
        Check the recipient and the amount against what you meant to send.
      </RnText>
    </Page>
  )
}
