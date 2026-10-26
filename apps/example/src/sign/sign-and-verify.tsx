import {Box, Button, Island, RnText, TextField, VStack} from '@hzblj/kara-ui'
import {useState} from 'react'

import {Card, Pill, Section, Value} from '../ui'

export type Verdict = {readonly verified: boolean; readonly detail?: string}

/** One chain's message signature, as this screen drives it. */
export type SignatureScheme = {
  /** "EIP-191 personal_sign": what is being signed, by its standard's name. */
  readonly name: string
  /** Who signs: the account's address. */
  readonly signer: string
  /** The signature as its chain writes it (hex, Base58). */
  readonly sign: (message: string) => Promise<string>
  readonly verify: (message: string, signature: string) => Promise<Verdict>
  /** A copy of `signature` with one character changed, still in its encoding. */
  readonly tamper: (signature: string) => string
}

const DEFAULT_MESSAGE = 'Hello from Expo'

/**
 * Sign a message, then verify it: as signed, or after changing the message or the signature. Both fields stay
 * editable, so any signature from elsewhere can be checked too.
 */
export const SignAndVerify = ({scheme}: {scheme: SignatureScheme}) => {
  const [message, setMessage] = useState(DEFAULT_MESSAGE)
  const [signature, setSignature] = useState<string | null>(null)
  const [checked, setChecked] = useState({message: DEFAULT_MESSAGE, signature: ''})
  // The fields are uncontrolled: a new key remounts them with the value set from here.
  const [revision, setRevision] = useState(0)
  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [busy, setBusy] = useState(false)

  const verify = async (next: {message: string; signature: string}) => {
    setChecked(next)
    setRevision(value => value + 1)
    setVerdict(await scheme.verify(next.message, next.signature))
  }

  const sign = async () => {
    setBusy(true)
    try {
      const signed = await scheme.sign(message)
      setSignature(signed)
      await verify({message, signature: signed})
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Section caption={`Signed by ${scheme.signer}, account 0 of the demo wallet.`} title={scheme.name}>
        <Island>
          <VStack spacing="s12" wide>
            <TextField
              defaultValue={DEFAULT_MESSAGE}
              label="Message"
              multiline
              onChangeText={setMessage}
              testID="sign-message"
            />
            <Button disabled={busy} label="Sign" onPress={sign} testID="sign" />
          </VStack>
        </Island>
        {signature ? (
          <Card>
            <Value copyAs="signature" label="Signature" testID="signature" value={signature} />
          </Card>
        ) : null}
      </Section>

      {signature ? (
        <Section caption="Change one letter of either and the signature no longer verifies." title="Verify">
          <Island>
            <VStack spacing="s12" wide>
              <TextField
                defaultValue={checked.message}
                key={`message-${revision}`}
                label="Message"
                multiline
                onChangeText={text => setChecked(current => ({...current, message: text}))}
                testID="verify-message"
              />
              <TextField
                defaultValue={checked.signature}
                key={`signature-${revision}`}
                label="Signature"
                multiline
                onChangeText={text => setChecked(current => ({...current, signature: text}))}
                testID="verify-signature"
              />
              <Button label="Verify" onPress={() => verify(checked)} testID="verify" />
            </VStack>
          </Island>
          <Box gap="s8" row>
            <Island flex={1}>
              <Button
                label="Change message"
                onPress={() => verify({...checked, message: `${checked.message}!`})}
                testID="tamper-message"
                variant="secondary"
              />
            </Island>
            <Island flex={1}>
              <Button
                label="Change signature"
                onPress={() => verify({...checked, signature: scheme.tamper(checked.signature)})}
                testID="tamper-signature"
                variant="secondary"
              />
            </Island>
          </Box>
          {verdict ? (
            <Card testID="verdict">
              <Box align="center" gap="s8" row>
                <Pill
                  label={verdict.verified ? 'Verified' : 'Does not verify'}
                  tone={verdict.verified ? 'success' : 'destructive'}
                />
                <RnText fill testID="verdict-text" variant="subheadlineMedium">
                  {verdict.verified
                    ? 'The signer signed this message.'
                    : 'Not this signer’s signature of this message.'}
                </RnText>
              </Box>
              {verdict.detail ? (
                <RnText color="content.secondary" selectable variant="footnote">
                  {verdict.detail}
                </RnText>
              ) : null}
            </Card>
          ) : null}
        </Section>
      ) : null}
    </>
  )
}
