import type {UR} from '@hzblj/crypto-airgap'
import {
  Box,
  Button,
  Island,
  LabeledContent,
  Progress,
  RnText,
  SegmentedControl,
  TextField,
  VStack,
} from '@hzblj/kara-ui'
import {openBrowserAsync} from 'expo-web-browser'
import {Fragment, useEffect, useMemo, useState} from 'react'
import {useWindowDimensions} from 'react-native'

import {AnimatedQr, Lead, Notice, Page, Pill, QrScanner, RowDivider, Rows, Section, Value} from '../../../components'
import {NETWORKS} from '../../../config'
import {
  airgapsOf,
  CHAIN_IDS,
  type ChainId,
  PAIRING_TYPES,
  readPairing,
  walletCrypto,
  walletServices,
} from '../../../core'
import {useUrScanner} from '../../../hooks'
import {type AirgapQuote, serviceFor, type WatchAccount} from '../../../services'
import {useAirgapStore} from '../../../store'
import {formatUnits, parseUnits, shortAddress} from '../../../utils'

type Flow =
  | {readonly step: 'edit'; readonly error?: string}
  | {readonly step: 'quoting'}
  | {readonly step: 'request'; readonly quote: AirgapQuote}
  | {readonly step: 'scan'; readonly quote: AirgapQuote; readonly error?: string}
  | {readonly step: 'broadcasting'; readonly quote: AirgapQuote}
  | {readonly step: 'sent'; readonly quote: AirgapQuote; readonly hash: string}

const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error))

/** Scanning a signer's pairing code: its public accounts, checked by each chain's adapter. */
const Pairing = () => {
  const setPaired = useAirgapStore.use.setPaired()
  const {width} = useWindowDimensions()
  const [problem, setProblem] = useState<string | null>(null)
  const scanner = useUrScanner(PAIRING_TYPES, walletCrypto()?.hash.sha256, ur => {
    const crypto = walletCrypto()

    try {
      if (crypto) {
        setPaired(readPairing(crypto, ur))
      }
    } catch (error) {
      setProblem(messageOf(error))
    }
  })

  return (
    <>
      <Lead>
        This phone as a watch-only wallet: pair it with a signer (another phone's Settings, Pair with a wallet, or the
        accounts a Keystone or OneKey shows), then see its balances, build transactions here and have them signed there,
        over QR codes only.
      </Lead>
      <Box align="center">
        <QrScanner onScan={scanner.receive} size={width - 40} testID="watch-pair-scanner" />
      </Box>
      {scanner.error ? <Notice text={scanner.error} tone="warning" /> : null}
      {problem ? (
        <>
          <Notice text={problem} title="Not paired" tone="destructive" />
          <Island>
            <Button
              label="Scan again"
              onPress={() => {
                setProblem(null)
                scanner.reset()
              }}
              variant="secondary"
            />
          </Island>
        </>
      ) : null}
    </>
  )
}

/** The signer's answer, read part by part, then checked against the request and broadcast by the chain's service. */
const AnswerScanner = ({chain, onAnswer}: {chain: ChainId; onAnswer: (ur: UR) => void}) => {
  const crypto = walletCrypto()
  const {width} = useWindowDimensions()
  const types = useMemo(() => (crypto ? airgapsOf(crypto)[chain].responseTypes : []), [crypto, chain])
  const scanner = useUrScanner(types, crypto?.hash.sha256, onAnswer)
  const {expectedFragmentCount, fraction, recoveredFragmentCount} = scanner.progress

  return (
    <>
      <Box align="center">
        <QrScanner onScan={scanner.receive} size={width - 40} testID="watch-answer-scanner" />
      </Box>
      {expectedFragmentCount > 1 ? (
        <Box gap="s8">
          <Island>
            <Progress accessibilityLabel="Reading the signature" value={fraction} />
          </Island>
          <RnText color="content.secondary" monospacedDigit variant="footnote">
            {`${recoveredFragmentCount} of ${expectedFragmentCount} parts`}
          </RnText>
        </Box>
      ) : null}
      {scanner.error ? <Notice text={scanner.error} tone="warning" /> : null}
    </>
  )
}

/** Each paired account's native balance, read from the network: public data, as any watch-only wallet reads it. */
const useBalances = (accounts: Partial<Record<ChainId, {readonly address: string}>>) => {
  const [balances, setBalances] = useState<Partial<Record<ChainId, bigint | string>>>({})

  useEffect(() => {
    const services = walletServices()
    let cancelled = false

    for (const chain of CHAIN_IDS) {
      const address = accounts[chain]?.address

      if (!services || !address) {
        continue
      }

      serviceFor(services, chain)
        .holdings(address)
        .then(
          holdings => {
            if (!cancelled) {
              setBalances(current => ({...current, [chain]: holdings[0]?.balance ?? 0n}))
            }
          },
          (error: unknown) => {
            if (!cancelled) {
              setBalances(current => ({...current, [chain]: messageOf(error)}))
            }
          }
        )
    }

    return () => {
      cancelled = true
    }
  }, [accounts])

  return balances
}

/**
 * A watch-only wallet for a paired signer: the signer's addresses and balances, and payments built here from the
 * network's state, signed on the signer over QR codes, checked against the request and broadcast from here.
 */
export const WatchScreen = () => {
  const paired = useAirgapStore.use.paired()
  const unpair = useAirgapStore.use.unpair()
  const {width} = useWindowDimensions()
  const crypto = walletCrypto()
  const accounts = useMemo(() => {
    const out: Partial<{[Id in ChainId]: WatchAccount<Id>}> = {}

    if (paired && crypto) {
      out.bitcoin = paired.bitcoin && crypto.chains.bitcoin.watchAccount(paired.bitcoin)
      out.ethereum = paired.ethereum
      out.solana = paired.solana
    }

    return out
  }, [paired, crypto])
  const balances = useBalances(accounts)
  const chains = CHAIN_IDS.filter(chain => accounts[chain])
  const [index, setIndex] = useState(0)
  const [flow, setFlow] = useState<Flow>({step: 'edit'})
  const [to, setTo] = useState('')
  const [amount, setAmount] = useState('')
  const chain = chains[index] ?? chains[0]

  if (!paired || !crypto) {
    return (
      <Page testID="airgap-watch">
        <Pairing />
      </Page>
    )
  }

  const network = chain ? NETWORKS[chain] : undefined
  const native = network?.native
  const parsed = native ? parseUnits(amount, native.decimals) : undefined

  const build = async () => {
    const services = walletServices()
    const account = chain ? accounts[chain] : undefined

    if (!services || !chain || !account || !native || !parsed) {
      return
    }

    setFlow({step: 'quoting'})

    try {
      const quote = await serviceFor(services, chain).airgapQuote(account as never, {
        amount: parsed,
        asset: native,
        to: to.trim(),
      })
      setFlow({quote, step: 'request'})
    } catch (error) {
      setFlow({error: messageOf(error), step: 'edit'})
    }
  }

  const finish = async (quote: AirgapQuote, answer: UR) => {
    setFlow({quote, step: 'broadcasting'})

    try {
      setFlow({hash: await quote.complete(answer), quote, step: 'sent'})
    } catch (error) {
      setFlow({error: messageOf(error), quote, step: 'scan'})
    }
  }

  return (
    <Page testID="airgap-watch">
      <Section title="Signer">
        <Island>
          <Rows>
            <LabeledContent label="Device" value={paired.device ?? 'Unnamed'} />
            <RowDivider />
            <LabeledContent label="Fingerprint" value={paired.fingerprint.toString(16).padStart(8, '0')} />
            <RowDivider />
            <LabeledContent
              icon="close"
              label="Unpair"
              onPress={() => {
                unpair()
                setFlow({step: 'edit'})
              }}
              testID="watch-unpair"
            />
          </Rows>
        </Island>
      </Section>
      <Section caption="Balances at the signer's addresses: public data, read from the network here." title="Accounts">
        <Island>
          <Rows>
            {chains.map((id, position) => {
              const balance = balances[id]
              const coin = NETWORKS[id].native
              return (
                <Fragment key={id}>
                  {position > 0 ? <RowDivider /> : null}
                  <LabeledContent
                    label={`${NETWORKS[id].name} ${shortAddress(accounts[id]?.address ?? '')}`}
                    value={
                      balance === undefined
                        ? '…'
                        : typeof balance === 'string'
                          ? 'Unavailable'
                          : `${formatUnits(balance, coin.decimals, 6)} ${coin.symbol}`
                    }
                  />
                </Fragment>
              )
            })}
          </Rows>
        </Island>
      </Section>
      {flow.step === 'edit' || flow.step === 'quoting' ? (
        <Section caption="Built from the network's current state; signed on the paired phone." title="Send">
          <SegmentedControl
            onChange={next => setIndex(next)}
            selectedIndex={index}
            values={chains.map(id => NETWORKS[id].native.symbol)}
          />
          <Island>
            <VStack spacing="s12" wide>
              <TextField
                key={`to-${chain}`}
                label={`${network?.name ?? ''} ${network?.testnet ?? ''} address`}
                onChangeText={setTo}
                testID="watch-to"
              />
              <TextField
                key={`amount-${chain}`}
                label={`Amount, ${native?.symbol ?? ''}`}
                onChangeText={setAmount}
                testID="watch-amount"
              />
              <Button
                disabled={flow.step === 'quoting' || !parsed || to.trim() === ''}
                label={flow.step === 'quoting' ? 'Building…' : 'Build the request'}
                onPress={build}
                testID="watch-build"
              />
            </VStack>
          </Island>
          {flow.step === 'edit' && flow.error ? (
            <Notice text={flow.error} title="Not built" tone="destructive" />
          ) : null}
        </Section>
      ) : null}
      {flow.step === 'request' ? (
        <Section
          caption="Scan this on the signer: Wallet, Scan. It shows what it signs before it asks."
          title="Request"
        >
          <Box align="center">
            <AnimatedQr sha256={crypto.hash.sha256} size={width - 40} testID="watch-request" ur={flow.quote.request} />
          </Box>
          <Island>
            <Rows>
              <LabeledContent
                label="Amount"
                value={`${formatUnits(flow.quote.amount, native?.decimals ?? 0, 8)} ${native?.symbol ?? ''}`}
              />
              <RowDivider />
              <LabeledContent
                label="Fee, at most"
                value={`${formatUnits(flow.quote.fee, native?.decimals ?? 0, 8)} ${native?.symbol ?? ''}`}
              />
              {flow.quote.details.map(detail => (
                <Fragment key={detail.label}>
                  <RowDivider />
                  <LabeledContent label={detail.label} value={detail.value} />
                </Fragment>
              ))}
            </Rows>
          </Island>
          <Island>
            <VStack spacing="s12" wide>
              <Button
                label="Scan the signature"
                onPress={() => setFlow({quote: flow.quote, step: 'scan'})}
                testID="watch-scan"
              />
              <Button label="Cancel" onPress={() => setFlow({step: 'edit'})} variant="secondary" />
            </VStack>
          </Island>
        </Section>
      ) : null}
      {flow.step === 'scan' || flow.step === 'broadcasting' ? (
        <Section
          caption="Checked against the request, its signer verified, before anything is broadcast."
          title="Signature"
        >
          {flow.step === 'scan' && chain ? (
            <AnswerScanner chain={chain} onAnswer={answer => finish(flow.quote, answer)} />
          ) : (
            <Island>
              <Progress accessibilityLabel="Broadcasting" />
            </Island>
          )}
          {flow.step === 'scan' && flow.error ? <Notice text={flow.error} title="Not sent" tone="destructive" /> : null}
        </Section>
      ) : null}
      {flow.step === 'sent' && network ? (
        <Section title="Sent">
          <Box align="center" gap="s8">
            <Pill label="Broadcast" tone="success" />
          </Box>
          <Box bg="surface.primary" borderRadius="large" gap="s12" p="s16">
            <Value copyAs="transaction id" label="Transaction" value={flow.hash} />
          </Box>
          <Island>
            <VStack spacing="s12" wide>
              <Button label="Open in the explorer" onPress={() => openBrowserAsync(network.explorer.tx(flow.hash))} />
              <Button label="Send another" onPress={() => setFlow({step: 'edit'})} variant="secondary" />
            </VStack>
          </Island>
        </Section>
      ) : null}
    </Page>
  )
}
