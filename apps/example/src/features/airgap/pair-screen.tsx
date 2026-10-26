import {Box, Island, LabeledContent, RnText, SegmentedControl} from '@hzblj/kara-ui'
import {Fragment, useMemo, useState} from 'react'
import {useWindowDimensions} from 'react-native'

import {AnimatedQr, Lead, Notice, Page, RowDivider, Rows, Section} from '../../components'
import {NETWORKS} from '../../config'
import {
  accountPathOf,
  type ChainId,
  extendedPublicKey,
  fingerprintOf,
  type PairingFormat,
  pairingRequest,
  walletCrypto,
} from '../../core'
import {useUnlockedWallet} from '../../hooks'
import {shortAddress} from '../../utils'

/** Each format: who reads it, what to tell the user, and the accounts it shares (an account key or one address). */
const FORMATS: readonly {
  readonly format: PairingFormat
  readonly label: string
  readonly lead: string
  readonly shares: readonly {readonly chain: ChainId; readonly account: boolean}[]
}[] = [
  {
    format: 'nitro',
    label: 'Nitro',
    lead: "Scan this from a watch-only Nitro Wallet (another phone's Debug tab, Air gap). It learns your addresses, not your keys: it can see and propose, only this phone can sign.",
    shares: [
      {account: true, chain: 'bitcoin'},
      {account: true, chain: 'ethereum'},
      {account: false, chain: 'solana'},
    ],
  },
  {
    format: 'sparrow',
    label: 'Sparrow',
    lead: 'In Sparrow (testnet), make a new wallet, add an Airgapped Hardware Wallet keystore and scan this with its Scan button. Sparrow builds transactions from any address of the account, and this phone signs them.',
    shares: [{account: true, chain: 'bitcoin'}],
  },
  {
    format: 'metamask',
    label: 'MetaMask',
    lead: "In MetaMask, connect a hardware wallet, choose QR-based and scan this. MetaMask lists the account's addresses and shows each transaction to this phone to sign, on Sepolia.",
    shares: [{account: true, chain: 'ethereum'}],
  },
]

/**
 * This wallet as an air-gapped signer, for the wallet that will ask it to sign: a watch-only Nitro Wallet, Sparrow or
 * MetaMask. Bitcoin and Ethereum go out as the account's extended public key (the public key and chain code every
 * address of the account derives from), Solana as its one address.
 */
export const PairScreen = () => {
  const wallet = useUnlockedWallet()
  const crypto = walletCrypto()
  const {width} = useWindowDimensions()
  const [index, setIndex] = useState(0)
  const selected = FORMATS[index] ?? FORMATS[0]
  const ur = useMemo(
    () =>
      wallet && crypto && selected
        ? pairingRequest(
            crypto,
            wallet.accounts,
            fingerprintOf(wallet.record.fingerprint),
            selected.format,
            extendedPublicKey
          )
        : null,
    [wallet, crypto, selected]
  )

  if (!wallet || !crypto || !ur || !selected) {
    return null
  }

  return (
    <Page testID="airgap-pair">
      <SegmentedControl
        onChange={setIndex}
        selectedIndex={index}
        testID="airgap-pair-format"
        values={FORMATS.map(format => format.label)}
      />
      <Lead>{selected.lead}</Lead>
      <Box align="center">
        <AnimatedQr sha256={crypto.hash.sha256} size={width - 40} testID="airgap-pairing" ur={ur} />
      </Box>
      <Section caption="Public keys only: nothing in this code can spend." title="Shared">
        <Island>
          <Rows>
            {selected.shares.map(({account, chain}, position) => {
              const {address, path} = wallet.accounts[chain]
              return (
                <Fragment key={chain}>
                  {position > 0 ? <RowDivider /> : null}
                  <LabeledContent
                    label={`${NETWORKS[chain].name} ${account ? accountPathOf(path) : path}`}
                    value={account ? 'Every address' : shortAddress(address)}
                  />
                </Fragment>
              )
            })}
            <RowDivider />
            <LabeledContent label="Wallet fingerprint" value={wallet.record.fingerprint} />
          </Rows>
        </Island>
      </Section>
      <Notice
        text="Anyone who scans this sees every address of these accounts, their balances and history. Show it only to a wallet of your own."
        tone="neutral"
      />
      <RnText color="content.tertiary" variant="footnote">
        An extended public key cannot sign, and cannot derive the keys of other accounts or of the wallet itself: those
        paths are hardened.
      </RnText>
    </Page>
  )
}
