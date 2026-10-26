import {Box, Button, EmptyState, Island, LabeledContent, RnText, SegmentedControl, TextField} from '@hzblj/kara-ui'
import {hex, type SigningKey, utf8} from '@hzblj/nitro-crypto'
import {useRouter} from 'expo-router'
import {useEffect, useRef, useState} from 'react'
import {Card, Lead, Page, Pill, Rows, Section, Value} from '../../../components'
import {type AppCrypto, useCrypto} from '../crypto'
import {useChecks, type VectorResult} from '../vectors'

const INPUT_MODES = ['Text', 'Hex'] as const

type Input = {readonly bytes: Uint8Array} | {readonly error: string}

const parseInput = (text: string, mode: (typeof INPUT_MODES)[number]): Input => {
  if (mode === 'Text') {
    return {bytes: utf8.encode(text)}
  }
  try {
    return {bytes: hex.decode(text.replace(/\s+/g, ''))}
  } catch (error) {
    return {error: error instanceof Error ? error.message : String(error)}
  }
}

const Digests = ({bytes, crypto}: {bytes: Uint8Array; crypto: AppCrypto}) => (
  <Card testID="digests">
    <RnText color="content.secondary" variant="caption">
      {`${bytes.length} bytes: ${hex.encode(bytes.subarray(0, 24))}${bytes.length > 24 ? '…' : ''}`}
    </RnText>
    <Value
      copyAs="SHA-256 digest"
      label="SHA-256"
      testID="digest-sha256"
      value={hex.encode(crypto.hash.sha256(bytes))}
    />
    <Value copyAs="Keccak-256 digest" label="Keccak-256" value={hex.encode(crypto.hash.keccak256(bytes))} />
    <Value copyAs="RIPEMD-160 digest" label="RIPEMD-160" value={hex.encode(crypto.hash.ripemd160(bytes))} />
    <Value copyAs="SHA-512 digest" label="SHA-512" value={hex.encode(crypto.hash.sha512(bytes))} />
  </Card>
)

const CURVES = ['secp256k1', 'Ed25519'] as const

type Signed = {readonly publicKey: string; readonly signature: string; readonly verified: boolean}

/** A key made on demand and disposed when replaced or left: sign the input with it, and verify the signature. */
const CurvePlayground = ({bytes, crypto}: {bytes: Uint8Array; crypto: AppCrypto}) => {
  const [curveIndex, setCurveIndex] = useState(0)
  const [signed, setSigned] = useState<Signed | null>(null)
  const key = useRef<SigningKey | null>(null)

  useEffect(() => () => key.current?.dispose(), [])

  const generate = () => {
    key.current?.dispose()
    key.current = crypto.keys.generate(curveIndex === 0 ? 'secp256k1' : 'ed25519')
    sign()
  }

  const sign = () => {
    const current = key.current
    if (!current) {
      return
    }
    if (current.curve === 'secp256k1') {
      // ECDSA signs a digest: here, SHA-256 of the input.
      const digest = crypto.hash.sha256(bytes)
      const {recovery, signature} = current.sign(digest)
      setSigned({
        publicKey: hex.encode(current.publicKey()),
        signature: `${hex.encode(signature)} (recovery ${recovery})`,
        verified: crypto.secp256k1.verify(current.publicKey(), digest, signature),
      })
    } else {
      const signature = current.sign(bytes)
      setSigned({
        publicKey: hex.encode(current.publicKey()),
        signature: hex.encode(signature),
        verified: crypto.ed25519.verify(current.publicKey(), bytes, signature),
      })
    }
  }

  return (
    <Section
      caption="A fresh key from the operating system's CSPRNG, held by the engine and disposed when you make another or leave. secp256k1 signs SHA-256 of the input; Ed25519 signs the input itself."
      title="Keys"
    >
      <SegmentedControl
        onChange={index => {
          setCurveIndex(index)
          setSigned(null)
        }}
        selectedIndex={curveIndex}
        values={[...CURVES]}
      />
      <Box gap="s8" row>
        <Island flex={1}>
          <Button label="New key" onPress={generate} testID="new-key" />
        </Island>
        <Island flex={1}>
          <Button disabled={!signed} label="Sign the input" onPress={sign} variant="secondary" />
        </Island>
      </Box>
      {signed ? (
        <Card testID="key-result">
          <Value copyAs="public key" label="Public key" value={signed.publicKey} />
          <Value copyAs="signature" label="Signature" value={signed.signature} />
          <Box row>
            <Pill
              label={signed.verified ? 'Verifies' : 'Does not verify'}
              tone={signed.verified ? 'success' : 'destructive'}
            />
          </Box>
        </Card>
      ) : null}
    </Section>
  )
}

const VectorRow = ({result}: {result: VectorResult}) => (
  <Box gap="s4" testID={`vector-${result.check.id}`}>
    <Box align="center" gap="s8" row>
      <Pill label={result.passed ? 'Match' : 'Mismatch'} tone={result.passed ? 'success' : 'destructive'} />
      <RnText fill variant="subheadlineMedium">
        {result.check.title}
      </RnText>
      <RnText color="content.tertiary" variant="caption">
        {`${result.milliseconds.toFixed(1)} ms`}
      </RnText>
    </Box>
    <RnText color="content.secondary" variant="caption">
      {result.check.source}
    </RnText>
    <RnText color={result.passed ? 'content.secondary' : 'content.destructive'} monospaced selectable variant="caption">
      {result.passed ? result.actual : `expected ${result.check.expected}\nactual   ${result.actual}`}
    </RnText>
  </Box>
)

const Vectors = () => {
  const {results, run, running} = useChecks()
  return (
    <Section
      caption="Each value is computed now, by the native engine, and compared with the one its standard publishes."
      title="Published vectors"
    >
      <Card testID="vectors">
        {results ? (
          results.map(result => <VectorRow key={result.check.id} result={result} />)
        ) : (
          <RnText variant="subheadline">Running…</RnText>
        )}
      </Card>
      <Island>
        <Button disabled={running} label="Run again" onPress={run} variant="secondary" />
      </Island>
    </Section>
  )
}

export const PrimitivesScreen = () => {
  const router = useRouter()
  const {crypto, error} = useCrypto()
  const [modeIndex, setModeIndex] = useState(0)
  const [text, setText] = useState('abc')

  if (!crypto) {
    return (
      <Page>
        <Island>
          <EmptyState description={error?.message} icon="warning-filled" title="No native engine" />
        </Island>
      </Page>
    )
  }
  const input = parseInput(text, INPUT_MODES[modeIndex] ?? 'Text')

  return (
    <Page testID="primitives">
      <Lead>
        The engine's primitives on any input: hashes, keys, signatures, and the published vectors they must match.
      </Lead>
      <Section title="Input">
        <SegmentedControl onChange={setModeIndex} selectedIndex={modeIndex} values={[...INPUT_MODES]} />
        <Island>
          <TextField
            defaultValue="abc"
            error={'error' in input ? input.error : undefined}
            multiline
            onChangeText={setText}
            testID="input"
          />
        </Island>
      </Section>
      {'bytes' in input ? (
        <>
          <Section title="Hashes">
            <Digests bytes={input.bytes} crypto={crypto} />
          </Section>
          <CurvePlayground bytes={input.bytes} crypto={crypto} />
        </>
      ) : null}
      <Vectors />
      <Island>
        <Rows>
          <LabeledContent icon="schedule" label="Performance" onPress={() => router.push('/debug/performance')} />
        </Rows>
      </Island>
    </Page>
  )
}
