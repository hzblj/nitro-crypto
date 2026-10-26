import {Box, Button, Island, RnText, SegmentedControl, TextField} from '@hzblj/kara-ui'
import {base58} from '@hzblj/nitro-crypto'
import {useState} from 'react'

import {Card, Lead, Notice, Page, Pill, Section, Value} from '../../components'
import {confirmWithUser} from '../../core'
import {useUnlockedWallet} from '../../hooks'

const SCHEMES = [
  {chain: 'ethereum', label: 'Ethereum', standard: 'EIP-191 personal_sign: what a dapp asks MetaMask to sign.'},
  {chain: 'solana', label: 'Solana', standard: 'Ed25519 over the message bytes: what a dapp asks Phantom to sign.'},
] as const

const DEFAULT_MESSAGE = 'Sign in to example.com with Nitro Wallet'

type Signed = {readonly signature: string; readonly verified: boolean; readonly signer: string}

/** Signs a message with the wallet's own keys, as a dapp would ask for a sign-in, and checks the signature back. */
export const SignMessageScreen = () => {
  const wallet = useUnlockedWallet()
  const [index, setIndex] = useState(0)
  const [message, setMessage] = useState(DEFAULT_MESSAGE)
  const [result, setResult] = useState<Signed | null>(null)
  const [error, setError] = useState<string | null>(null)
  const scheme = SCHEMES[index] ?? SCHEMES[0]

  if (!wallet) {
    return null
  }

  const sign = async () => {
    setError(null)
    setResult(null)
    if (!(await confirmWithUser('Sign this message'))) {
      return
    }
    try {
      if (scheme.chain === 'ethereum') {
        const account = wallet.accounts.ethereum
        const signature = await account.signMessage({message})
        setResult({signature, signer: account.address, verified: await account.verifyMessage({message, signature})})
      } else {
        const account = wallet.accounts.solana
        const signature = base58.encode(await account.signMessage({message}))
        setResult({signature, signer: account.address, verified: await account.verifyMessage({message, signature})})
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure))
    }
  }

  return (
    <Page testID="sign-message">
      <Lead>
        A signature proves you hold an address without moving anything. Read what you sign: a message can authorize more
        than it says.
      </Lead>
      <SegmentedControl
        onChange={next => {
          setIndex(next)
          setResult(null)
        }}
        selectedIndex={index}
        values={SCHEMES.map(entry => entry.label)}
      />
      <Section caption={scheme.standard} title="Message">
        <Island>
          <TextField defaultValue={DEFAULT_MESSAGE} multiline onChangeText={setMessage} testID="message" />
        </Island>
      </Section>
      <Island>
        <Button disabled={message.length === 0} label="Sign" onPress={sign} testID="sign-message-button" />
      </Island>
      {error ? <Notice text={error} tone="destructive" /> : null}
      {result ? (
        <Card testID="signature-result">
          <Box align="center" gap="s8" row>
            <Pill
              label={result.verified ? 'Verifies' : 'Does not verify'}
              tone={result.verified ? 'success' : 'destructive'}
            />
            <RnText color="content.secondary" fill variant="footnote">
              {scheme.chain === 'ethereum' ? 'Recovered to the signer by the adapter' : 'Checked with Ed25519'}
            </RnText>
          </Box>
          <Value copyAs="signature" label="Signature" value={result.signature} />
          <Value copyAs="address" label="Signer" value={result.signer} />
        </Card>
      ) : null}
    </Page>
  )
}
