import {Box, Button, EmptyState, Island, LabeledContent, RnText, SegmentedControl} from '@hzblj/kara-ui'
import {useState} from 'react'
import {Card, Lead, Page, Pill, RowDivider, Rows, Section} from '../../../components'
import {useCrypto} from '../crypto'
import {runtime} from '../overview'
import {createFixture, disposeFixture, iterationsFor, measure, OPERATIONS, type Operation} from './benchmarks'

const ITERATIONS = [10, 100, 1000] as const
const PAYLOADS = [
  {label: '32 B', length: 32},
  {label: '1 KiB', length: 1024},
  {label: '64 KiB', length: 64 << 10},
  {label: '1 MiB', length: 1 << 20},
] as const

type Result = {
  readonly operation: Operation
  readonly iterations: number
  readonly native: number
  readonly javascript: number | null
}

const formatTime = (microseconds: number) =>
  microseconds >= 1000
    ? `${(microseconds / 1000).toFixed(2)} ms`
    : `${microseconds.toFixed(microseconds < 10 ? 2 : 1)} µs`

/** Which side was faster, and by how much: stated either way round, never only when native wins. */
const comparison = ({javascript, native}: Result) => {
  if (javascript === null) {
    return null
  }
  return native <= javascript
    ? {label: `Native ${(javascript / native).toFixed(1)}× faster`, tone: 'success' as const}
    : {label: `JavaScript ${(native / javascript).toFixed(1)}× faster`, tone: 'neutral' as const}
}

const ResultRow = ({result}: {result: Result}) => {
  const verdict = comparison(result)
  return (
    <Box gap="s4" testID={`benchmark-${result.operation.id}`}>
      <Box align="center" gap="s8" row>
        <RnText fill variant="subheadlineMedium">
          {result.operation.title}
        </RnText>
        {verdict ? <Pill label={verdict.label} tone={verdict.tone} /> : <Pill label="Native only" />}
      </Box>
      <RnText color="content.secondary" monospaced variant="footnote">
        {`native ${formatTime(result.native)}${result.javascript === null ? '' : `   @noble ${formatTime(result.javascript)}`}   ×${result.iterations}`}
      </RnText>
      <RnText color="content.tertiary" variant="caption">
        {result.operation.measures}
      </RnText>
    </Box>
  )
}

/** Gives the screen a frame between measurements, so a long run stays responsive and shows its progress. */
const nextFrame = () => new Promise(resolve => setTimeout(resolve, 0))

export const PerformanceScreen = () => {
  const {crypto, error} = useCrypto()
  const [iterationIndex, setIterationIndex] = useState(1)
  const [payloadIndex, setPayloadIndex] = useState(1)
  const [results, setResults] = useState<Result[]>([])
  const [running, setRunning] = useState<string | null>(null)

  if (!crypto) {
    return (
      <Page>
        <Island>
          <EmptyState description={error?.message} icon="warning-filled" title="No native engine" />
        </Island>
      </Page>
    )
  }
  const iterations = ITERATIONS[iterationIndex] ?? 100
  const payload = PAYLOADS[payloadIndex] ?? PAYLOADS[0]
  const device = runtime()

  const run = async () => {
    setResults([])
    const fixture = createFixture(crypto, payload.length)
    try {
      for (const operation of OPERATIONS) {
        setRunning(operation.title)
        await nextFrame()
        const count = iterationsFor(operation, iterations, payload.length)
        const native = await measure(operation.native(fixture), count)
        const javascript = operation.javascript ? await measure(operation.javascript(fixture), count) : null
        setResults(current => [...current, {iterations: count, javascript, native, operation}])
      }
    } finally {
      disposeFixture(fixture)
      setRunning(null)
    }
  }

  return (
    <Page testID="performance">
      <Lead>
        The engine against @noble, the audited JavaScript implementation, doing the same work on the same keys. Numbers
        are this device's, this build's, this run's: nothing more general.
      </Lead>
      {device.build === 'Debug' ? (
        <Card>
          <RnText color="content.destructive" variant="subheadline">
            Debug build: JavaScript runs slower in development mode than in a release build, which flatters the native
            side. Compare release builds before drawing conclusions.
          </RnText>
        </Card>
      ) : null}
      <Section
        caption="Iterations are capped for large payloads, so no run hashes more than 64 MiB per side; each result says how many it ran."
        title="Run"
      >
        <SegmentedControl
          onChange={setIterationIndex}
          selectedIndex={iterationIndex}
          values={ITERATIONS.map(count => `${count}×`)}
        />
        <SegmentedControl
          onChange={setPayloadIndex}
          selectedIndex={payloadIndex}
          values={PAYLOADS.map(entry => entry.label)}
        />
        <Island>
          <Button
            disabled={running !== null}
            label={running ? `Measuring ${running}…` : 'Run benchmarks'}
            onPress={run}
            testID="run-benchmarks"
          />
        </Island>
      </Section>
      {results.length > 0 ? (
        <Section title={`Results, ${payload.label} payload`}>
          <Card testID="benchmark-results">
            {results.map(result => (
              <ResultRow key={result.operation.id} result={result} />
            ))}
          </Card>
        </Section>
      ) : null}
      <Section title="Measured on">
        <Island>
          <Rows>
            <LabeledContent label="Device" value={device.device} />
            <RowDivider />
            <LabeledContent label="Platform" value={device.os} />
            <RowDivider />
            <LabeledContent label="CPU" value={device.architectures} />
            <RowDivider />
            <LabeledContent label="JavaScript" value={`${device.javascript}, ${device.build}`} />
            <RowDivider />
            <LabeledContent label="Engine" value={crypto.info.build} />
          </Rows>
        </Island>
      </Section>
    </Page>
  )
}
