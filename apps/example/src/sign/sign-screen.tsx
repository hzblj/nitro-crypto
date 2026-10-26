import type {Hex} from '@hzblj/crypto-ethereum'
import {ActivityIndicator, Button, EmptyState, Island, RnText, SegmentedControl} from '@hzblj/kara-ui'
import {base58} from '@hzblj/nitro-crypto'
import {useMemo, useState} from 'react'

import {type AppAccount, type AppCrypto, useAccount, useCrypto} from '../crypto'
import {Card, Lead, Page, Pills, Section} from '../ui'
import {SignAndVerify, type SignatureScheme} from './sign-and-verify'

const MODES = ['Ethereum', 'Solana', 'Bitcoin'] as const

/** Swaps one character for its neighbour in `alphabet`, near the middle of `text`, so the encoding stays valid. */
const flipCharacter = (text: string, alphabet: string) => {
  const index = Math.floor(text.length / 2)
  const current = alphabet.indexOf(text[index] ?? '')
  const next = alphabet[(current + 1) % alphabet.length] ?? alphabet[0]
  return `${text.slice(0, index)}${next}${text.slice(index + 1)}`
}

const ethereumScheme = (crypto: AppCrypto, account: AppAccount<'ethereum'>): SignatureScheme => ({
  name: 'Ethereum: EIP-191 personal_sign',
  sign: async message => account.signMessage({message}),
  signer: account.address,
  tamper: signature => flipCharacter(signature, '0123456789abcdef'),
  verify: async (message, signature) => {
    const recovered = crypto.chains.ethereum.recoverMessageAddress({message, signature: signature as Hex})
    return {
      detail: recovered ? `Recovers to ${recovered}` : 'Recovers no key: not a well-formed signature.',
      verified: await account.verifyMessage({message, signature: signature as Hex}),
    }
  },
})

const solanaScheme = (account: AppAccount<'solana'>): SignatureScheme => ({
  name: 'Solana: Ed25519 over the message bytes',
  sign: async message => base58.encode(await account.signMessage({message})),
  signer: account.address,
  tamper: signature => flipCharacter(signature, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'),
  verify: async (message, signature) => ({verified: await account.verifyMessage({message, signature})}),
})

const Loading = () => (
  <Card>
    <ActivityIndicator accessibilityLabel="Deriving the account" />
  </Card>
)

const EthereumSigning = ({crypto}: {crypto: AppCrypto}) => {
  const state = useAccount('ethereum', 0)
  const scheme = useMemo(
    () => (state.status === 'ready' ? ethereumScheme(crypto, state.account) : null),
    [crypto, state]
  )
  return scheme ? <SignAndVerify key={scheme.signer} scheme={scheme} /> : <Loading />
}

const SolanaSigning = () => {
  const state = useAccount('solana', 0)
  const scheme = useMemo(() => (state.status === 'ready' ? solanaScheme(state.account) : null), [state])
  return scheme ? <SignAndVerify key={scheme.signer} scheme={scheme} /> : <Loading />
}

/** Said plainly rather than faked: the Bitcoin adapter signs nothing in this version. */
const BitcoinUnsupported = ({crypto}: {crypto: AppCrypto}) => {
  const adapter = crypto.adapters.find(entry => entry.id === 'bitcoin')
  return (
    <Section
      caption="Its accounts have no signMessage at all, so no code can sign the Ethereum way for a Bitcoin address by mistake."
      title="Bitcoin"
    >
      <Card testID="bitcoin-unsupported">
        <RnText variant="headline">Not supported in this version</RnText>
        <RnText color="content.secondary" variant="subheadline">
          Bitcoin's message formats (BIP-137's signed messages, BIP-322's generic ones) differ from Ethereum's, and
          neither is implemented yet. Nor are PSBT transactions, or Taproot (BIP-86, Schnorr). The adapter says so in
          its features:
        </RnText>
        <Pills labels={Object.entries(adapter?.features ?? {}).map(([name, on]) => `${name}: ${on ? 'yes' : 'no'}`)} />
      </Card>
    </Section>
  )
}

export const SignScreen = () => {
  const {createWallet, crypto, wallet} = useCrypto()
  const [mode, setMode] = useState(0)

  if (!crypto || !wallet) {
    return (
      <Page>
        <Island>
          <EmptyState
            action={crypto ? <Button label="Create a demo wallet" onPress={() => createWallet()} /> : undefined}
            description="Messages are signed by an account of the demo wallet."
            icon="verified"
            title="No demo wallet"
          />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="sign">
      <Lead>
        Sign a message with an account's key, inside the engine, and verify it. Each chain signs its own way; neither
        signature here authorizes a transaction.
      </Lead>
      <SegmentedControl onChange={setMode} selectedIndex={mode} testID="sign-chain" values={[...MODES]} />
      {MODES[mode] === 'Ethereum' ? <EthereumSigning crypto={crypto} /> : null}
      {MODES[mode] === 'Solana' ? <SolanaSigning /> : null}
      {MODES[mode] === 'Bitcoin' ? <BitcoinUnsupported crypto={crypto} /> : null}
    </Page>
  )
}
