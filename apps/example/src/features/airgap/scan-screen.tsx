import {isAirgapError, type UR} from '@hzblj/crypto-airgap'
import {Box, Button, Island, Progress, RnText} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {useState} from 'react'
import {useWindowDimensions} from 'react-native'

import {Lead, Notice, Page, QrScanner} from '../../components'
import {fingerprintOf, readSignRequest, SIGN_REQUEST_TYPES, walletCrypto} from '../../core'
import {useUnlockedWallet, useUrScanner} from '../../hooks'
import {useAirgapStore} from '../../store'

/** Why a request this wallet read cannot be signed, for people. */
const refusal = (error: unknown) => {
  if (isAirgapError(error, 'REQUEST_MISMATCH')) {
    return `${error.message} It may be meant for another wallet.`
  }

  if (isAirgapError(error, 'PRIVATE_KEY_MATERIAL')) {
    return 'That code carries a private key or a seed. Nothing should ever ask you to scan one.'
  }

  return error instanceof Error ? error.message : String(error)
}

/**
 * The offline side of air-gapped signing: the camera reads a request from a watch-only wallet (a PSBT, an ERC-4527
 * request, a Solana sign request), part by part, and the wallet reads it for its own accounts before showing it.
 */
export const ScanScreen = () => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const setIncoming = useAirgapStore.use.setIncoming()
  const {width} = useWindowDimensions()
  const [problem, setProblem] = useState<string | null>(null)

  const open = (ur: UR) => {
    const crypto = walletCrypto()

    if (!wallet || !crypto) {
      return
    }

    try {
      setIncoming(readSignRequest(crypto, ur, wallet.accounts, fingerprintOf(wallet.record.fingerprint)))
      router.replace('/airgap-review')
    } catch (error) {
      // The scanner stops at a whole request: it reads another only when asked, not the same refused one again.
      setProblem(refusal(error))
    }
  }

  const scanner = useUrScanner(SIGN_REQUEST_TYPES, walletCrypto()?.hash.sha256, open)
  const {expectedFragmentCount, fraction, recoveredFragmentCount} = scanner.progress

  if (!wallet) {
    return null
  }

  return (
    <Page testID="airgap-scan">
      <Lead>
        Scan the request a watch-only wallet shows: a Bitcoin PSBT, an Ethereum transaction or message, a Solana
        transaction or message. Nothing is signed until you have read it and agreed.
      </Lead>
      <Box align="center">
        <QrScanner onScan={scanner.receive} size={width - 40} testID="airgap-scanner" />
      </Box>
      {expectedFragmentCount > 1 ? (
        <Box gap="s8">
          <Island>
            <Progress accessibilityLabel="Reading the request" value={fraction} />
          </Island>
          <RnText color="content.secondary" monospacedDigit variant="footnote">
            {`${recoveredFragmentCount} of ${expectedFragmentCount} parts, from ${scanner.progress.receivedPartCount} codes read`}
          </RnText>
        </Box>
      ) : null}
      {scanner.error ? <Notice text={scanner.error} tone="warning" /> : null}
      {problem ? (
        <>
          <Notice testID="airgap-refused" text={problem} title="Not signed" tone="destructive" />
          <Island>
            <Button
              label="Scan another"
              onPress={() => {
                setProblem(null)
                scanner.reset()
              }}
              variant="secondary"
            />
          </Island>
        </>
      ) : null}
    </Page>
  )
}
