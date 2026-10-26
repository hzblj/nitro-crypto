import {ActivityIndicator, Box, Button, Island, RnIcon, RnText, VStack} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {openBrowserAsync} from 'expo-web-browser'
import {useEffect, useState} from 'react'

import {Card, Page, Value} from '../../components'
import {findAsset, NETWORKS} from '../../config'
import {type ChainId} from '../../core'
import {invalidate, useUnlockedWallet} from '../../hooks'
import {serviceFor, type TransactionStatus} from '../../services'
import {formatUnits, shortAddress} from '../../utils'

const POLL_MS = 4000

const refresh = (chain: ChainId) => {
  invalidate(`holdings:${chain}`)
  invalidate(`activity:${chain}`)
}

type TransactionScreenProps = {
  readonly chain: ChainId
  readonly hash: string
  readonly asset?: string
  readonly amount?: string
  readonly to?: string
}

const COPY = {
  confirmed: {icon: 'check-circle-filled', title: 'Confirmed'},
  failed: {icon: 'error', title: 'Failed on chain'},
  pending: {icon: 'pending', title: 'Waiting for the network'},
} as const

/** A transaction just broadcast, watched until the network confirms it (or says it failed). */
export const TransactionScreen = ({amount, asset: assetId, chain, hash, to}: TransactionScreenProps) => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const [status, setStatus] = useState<TransactionStatus>('pending')
  const [checkError, setCheckError] = useState<string | null>(null)
  const network = NETWORKS[chain]
  const asset = findAsset(assetId ?? '') ?? network.native
  const services = wallet?.services

  // Broadcast: the mempool already shows it on some networks.
  useEffect(() => refresh(chain), [chain])

  useEffect(() => {
    if (!services || status !== 'pending') {
      return
    }
    let active = true
    const check = () =>
      serviceFor(services, chain)
        .status(hash)
        .then(
          next => {
            if (active) {
              setCheckError(null)
              setStatus(next)
              // Settled: the balances and the history changed, and every screen showing them reloads.
              if (next !== 'pending') {
                refresh(chain)
              }
            }
          },
          (error: Error) => active && setCheckError(error.message)
        )
    const timer = setInterval(check, POLL_MS)
    check()
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [chain, hash, services, status])

  const copy = COPY[status]

  return (
    <Page testID="transaction">
      <Box align="center" gap="s12" pt="s16">
        {status === 'pending' ? (
          <ActivityIndicator accessibilityLabel="Waiting for the network" />
        ) : (
          <RnIcon
            color={status === 'confirmed' ? 'content.success' : 'content.destructive'}
            name={copy.icon}
            size="s64"
          />
        )}
        <RnText align="center" testID="transaction-status" variant="headingS">
          {copy.title}
        </RnText>
        <RnText align="center" color="content.secondary" variant="body">
          {amount
            ? `${formatUnits(BigInt(amount), asset.decimals, 8)} ${asset.symbol}${to ? ` to ${shortAddress(to)}` : ''} on ${network.name} ${network.testnet}`
            : `${network.name} ${network.testnet}`}
        </RnText>
        {checkError ? (
          <RnText align="center" color="content.tertiary" variant="footnote">
            {`Still checking: ${checkError}`}
          </RnText>
        ) : null}
      </Box>
      <Card>
        <Value copyAs="transaction id" label="Transaction" testID="transaction-hash" value={hash} />
      </Card>
      <Island>
        <VStack spacing="s12" wide>
          <Button label="View in explorer" onPress={() => openBrowserAsync(network.explorer.tx(hash))} />
          <Button label="Done" onPress={() => router.dismissTo('/')} testID="transaction-done" variant="secondary" />
        </VStack>
      </Island>
    </Page>
  )
}
