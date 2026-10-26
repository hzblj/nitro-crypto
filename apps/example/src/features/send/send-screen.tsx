import {
  Box,
  Button,
  Chip,
  IconButton,
  Island,
  LabeledContent,
  RnText,
  Skeleton,
  TextField,
  VStack,
} from '@hzblj/kara-ui'
import {getStringAsync} from 'expo-clipboard'
import {useRouter} from 'expo-router'
import {Fragment, useState} from 'react'
import {Card, Notice, Page, RowDivider, Rows, Section, Value} from '../../components'
import {type Asset, assetsOf, findAsset, NETWORKS} from '../../config'
import {CHAIN_IDS, confirmWithUser} from '../../core'
import {useHoldings, usePrices, useUnlockedWallet} from '../../hooks'
import {type Quote, serviceFor} from '../../services'
import {useWalletStore} from '../../store'
import {formatExact, formatUnits, formatUsd, parseUnits, shortAddress, usdValue} from '../../utils'
import {RecipientVerdict, useRecipientCheck} from './recipient-check'

const ASSETS = CHAIN_IDS.flatMap(assetsOf)

const assetLabel = (asset: Asset) => (asset.contract ? `${asset.symbol} · ${NETWORKS[asset.chain].name}` : asset.symbol)

type Step =
  | {readonly step: 'edit'; readonly error?: string}
  | {readonly step: 'quoting'}
  | {readonly step: 'review'; readonly quote: Quote; readonly to: string; readonly error?: string}
  | {readonly step: 'sending'; readonly quote: Quote; readonly to: string}

/** A text field whose text the screen can also set: a paste, the maximum. Kara's fields are uncontrolled. */
const useField = (initial = '') => {
  const [text, setText] = useState(initial)
  const [version, setVersion] = useState(0)

  return {
    key: version,
    replace: (next: string) => {
      setText(next)
      setVersion(current => current + 1)
    },
    setText,
    text,
  }
}

const Review = ({
  asset,
  onEdit,
  onSend,
  state,
}: {
  asset: Asset
  onEdit: () => void
  onSend: () => void
  state: Extract<Step, {step: 'review' | 'sending'}>
}) => {
  const wallet = useUnlockedWallet()
  const prices = usePrices()
  const {quote, to} = state
  const network = NETWORKS[asset.chain]
  const native = network.native
  const sending = state.step === 'sending'
  const method = wallet?.record.protection === 'none' ? 'Send' : `Send with ${wallet?.record.method}`

  return (
    <>
      <Box align="center" gap="s4" testID="review">
        <RnText color="content.secondary" variant="subheadline">
          You send
        </RnText>
        <RnText align="center" monospacedDigit variant="headingL">
          {`${formatUnits(quote.amount, asset.decimals, 8)} ${asset.symbol}`}
        </RnText>
        <RnText color="content.secondary" variant="footnote">
          {`${formatUsd(usdValue(quote.amount, asset.decimals, prices.data?.[asset.priceId]))} at mainnet prices`}
        </RnText>
      </Box>
      <Card>
        <Value copyAs="recipient" label="To" value={to} />
      </Card>
      <Island>
        <Rows>
          <LabeledContent
            label="Network fee, at most"
            value={`${formatUnits(quote.fee, native.decimals, 8)} ${native.symbol}`}
          />
          {asset.contract ? null : (
            <>
              <RowDivider />
              <LabeledContent
                label="Total"
                value={`${formatUnits(quote.amount + quote.fee, native.decimals, 8)} ${native.symbol}`}
              />
            </>
          )}
          {quote.details.map(detail => (
            <Fragment key={detail.label}>
              <RowDivider />
              <LabeledContent label={detail.label} value={detail.value} />
            </Fragment>
          ))}
        </Rows>
      </Island>
      {state.step === 'review' && state.error ? (
        <Notice testID="send-error" text={state.error} title="Not sent" tone="destructive" />
      ) : null}
      <Island>
        <VStack spacing="s12" wide>
          <Button
            disabled={sending}
            label={sending ? 'Signing and sending…' : method}
            onPress={onSend}
            testID="confirm-send"
          />
          <Button disabled={sending} label="Edit" onPress={onEdit} variant="secondary" />
        </VStack>
      </Island>
      <RnText color="content.tertiary" variant="footnote">
        The transaction is built from the network's current state, signed by the key inside the engine, and broadcast to{' '}
        {network.endpoint.replace(/^https:\/\//, '').split('/')[0]}. A testnet transaction cannot be undone either.
      </RnText>
    </>
  )
}

/** Send any asset the wallet holds: compose, review the built transaction and its fee, approve, sign, broadcast. */
export const SendScreen = ({initialAsset}: {initialAsset?: string}) => {
  const router = useRouter()
  const wallet = useUnlockedWallet()
  const [asset, setAsset] = useState<Asset>(() => findAsset(initialAsset ?? '') ?? NETWORKS.ethereum.native)
  const recipient = useField()
  const amount = useField()
  const [max, setMax] = useState(false)
  const [state, setState] = useState<Step>({step: 'edit'})
  const holdings = useHoldings(asset.chain)
  const prices = usePrices()
  const check = useRecipientCheck(asset.chain, recipient.text)
  const addPending = useWalletStore.use.addPending()

  if (!wallet) {
    return null
  }

  const held = holdings.data?.find(holding => holding.asset.id === asset.id)?.balance
  const parsed = max ? undefined : parseUnits(amount.text, asset.decimals)
  const amountError =
    !max && amount.text.trim() !== '' && (parsed === undefined || parsed === 0n)
      ? `Enter an amount of ${asset.symbol}, with at most ${asset.decimals} decimals.`
      : !max && parsed !== undefined && held !== undefined && parsed > held
        ? `More than the ${formatUnits(held, asset.decimals)} ${asset.symbol} this wallet holds.`
        : undefined
  const ready = check?.valid === true && (max || (parsed !== undefined && parsed > 0n)) && !amountError

  const choose = (next: Asset) => {
    setAsset(next)
    setMax(false)
    amount.replace('')
    setState({step: 'edit'})
  }

  const paste = async () => {
    const text = (await getStringAsync()).trim()
    if (text) {
      recipient.replace(text)
    }
  }

  const review = async () => {
    const to = check?.normalized
    if (!to) {
      return
    }
    setState({step: 'quoting'})
    try {
      const quote = await serviceFor(wallet.services, asset.chain).quote(wallet.accounts[asset.chain] as never, {
        amount: max ? 'max' : (parsed ?? 0n),
        asset,
        to,
      })
      setState({quote, step: 'review', to})
    } catch (error) {
      setState({error: error instanceof Error ? error.message : String(error), step: 'edit'})
    }
  }

  const send = async () => {
    if (state.step !== 'review') {
      return
    }
    const approved = await confirmWithUser(`Send ${formatUnits(state.quote.amount, asset.decimals)} ${asset.symbol}`)
    if (!approved) {
      return
    }
    setState({...state, step: 'sending'})
    try {
      const hash = await state.quote.send()
      addPending({
        amount: state.quote.amount,
        assetId: asset.id,
        chain: asset.chain,
        hash,
        sentAt: new Date(),
        to: state.to,
      })
      router.replace({
        params: {
          amount: state.quote.amount.toString(),
          asset: asset.id,
          chain: asset.chain,
          hash,
          to: state.to,
        },
        pathname: '/transaction',
      })
    } catch (error) {
      setState({...state, error: error instanceof Error ? error.message : String(error), step: 'review'})
    }
  }

  if (state.step === 'review' || state.step === 'sending') {
    return (
      <Page testID="send">
        <Review asset={asset} onEdit={() => setState({step: 'edit'})} onSend={send} state={state} />
      </Page>
    )
  }

  const network = NETWORKS[asset.chain]

  return (
    <Page testID="send">
      <Section title="Asset">
        <Box gap="s8" row wrap>
          {ASSETS.map(entry => (
            <Chip
              key={entry.id}
              label={assetLabel(entry)}
              onPress={() => choose(entry)}
              selected={entry.id === asset.id}
              testID={`asset-${entry.id}`}
            />
          ))}
        </Box>
        {held === undefined ? (
          <Skeleton h={14} w="60%" />
        ) : (
          <RnText color="content.secondary" variant="footnote">
            {`${formatUnits(held, asset.decimals, 8)} ${asset.symbol} available on ${network.name} ${network.testnet}`}
          </RnText>
        )}
      </Section>
      <Section title="To">
        <Box align="flex-end" gap="s8" row>
          <Island flex={1}>
            <TextField
              defaultValue={recipient.text}
              key={`recipient-${recipient.key}`}
              label={`${network.name} address`}
              onChangeText={recipient.setText}
              testID="recipient"
            />
          </Island>
          <Island h={48} w={48}>
            <IconButton accessibilityLabel="Paste the address" name="content-paste" onPress={paste} />
          </Island>
        </Box>
        {check ? <RecipientVerdict check={check} /> : null}
      </Section>
      <Section title="Amount">
        <Box align="flex-end" gap="s8" row>
          <Island flex={1}>
            <TextField
              defaultValue={amount.text}
              disabled={max}
              error={amountError}
              key={`amount-${asset.id}-${amount.key}`}
              label={`Amount in ${asset.symbol}`}
              onChangeText={amount.setText}
              testID="amount"
            />
          </Island>
          <Chip
            label="Max"
            onPress={() => {
              setMax(!max)
              amount.replace(!max && held !== undefined ? formatExact(held, asset.decimals) : '')
            }}
            selected={max}
            testID="amount-max"
          />
        </Box>
        <RnText color="content.secondary" variant="footnote">
          {max
            ? 'Everything, less the network fee: the review shows the exact amount.'
            : parsed !== undefined
              ? `${formatUsd(usdValue(parsed, asset.decimals, prices.data?.[asset.priceId]))} at mainnet prices`
              : ' '}
        </RnText>
      </Section>
      {state.step === 'edit' && state.error ? (
        <Notice testID="send-error" text={state.error} title="Cannot build this transaction" tone="destructive" />
      ) : null}
      <Island>
        <Button
          disabled={!ready || state.step === 'quoting'}
          label={state.step === 'quoting' ? 'Building the transaction…' : 'Review'}
          onPress={review}
          testID="review-send"
        />
      </Island>
      <RnText color="content.tertiary" variant="footnote">
        {`Sending from ${shortAddress(wallet.accounts[asset.chain].address)}. Fees are paid in ${network.native.symbol}.`}
      </RnText>
    </Page>
  )
}
