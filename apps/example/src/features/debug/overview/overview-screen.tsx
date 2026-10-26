import {Box, Button, EmptyState, Island, LabeledContent, RnText} from '@hzblj/kara-ui'
import {useRouter} from 'expo-router'
import {Fragment} from 'react'
import {Card, DemoNotice, Lead, Page, Pill, Pills, RowDivider, Rows, Section} from '../../../components'
import {PLATFORM_VERSIONS} from '../about/versions'
import {type AppCrypto, useCrypto} from '../crypto'
import {useChecks} from '../vectors'
import {runtime} from './runtime'

const SCREENS = [
  {href: '/debug/demo-wallet', icon: 'wallet', label: 'Demo wallet'},
  {href: '/debug/accounts', icon: 'layers', label: 'Accounts'},
  {href: '/debug/sign', icon: 'verified', label: 'Sign and verify'},
  {href: '/debug/primitives', icon: 'science', label: 'Primitives'},
  {href: '/debug/performance', icon: 'schedule', label: 'Performance'},
  {href: '/debug/about', icon: 'shield', label: 'About and security'},
] as const

const Engine = ({crypto}: {crypto: AppCrypto}) => (
  <Section
    caption="The engine is Zig behind a C ABI; the bridge refuses one whose ABI it was not built for."
    title="Engine"
  >
    <Island>
      <Rows>
        <LabeledContent label="Engine" value={crypto.info.engineVersion} />
        <RowDivider />
        <LabeledContent label="C ABI" value={String(crypto.info.abiVersion)} />
        <RowDivider />
        <LabeledContent label="Built with" value={crypto.info.build} />
        {PLATFORM_VERSIONS.map(({name, version}) => (
          <Fragment key={name}>
            <RowDivider />
            <LabeledContent label={name} value={version} />
          </Fragment>
        ))}
      </Rows>
    </Island>
  </Section>
)

const Runtime = () => {
  const {architectures, build, device, javascript, os} = runtime()
  return (
    <Section title="Runtime">
      <Island>
        <Rows>
          <LabeledContent label="Platform" value={os} />
          <RowDivider />
          <LabeledContent label="Device" value={device} />
          <RowDivider />
          <LabeledContent label="CPU" value={architectures} />
          <RowDivider />
          <LabeledContent label="JavaScript" value={`${javascript}, ${build}`} />
        </Rows>
      </Island>
    </Section>
  )
}

/** The published vectors, run live through the native engine: the screen's quick answer to "does it work here". */
const SelfTest = () => {
  const router = useRouter()
  const {results, run, running} = useChecks()
  const passed = results?.filter(result => result.passed).length ?? 0
  const all = results?.length ?? 0
  const ok = results !== null && passed === all

  return (
    <Section
      caption="Hashes, curves, BIP-39, BIP-32, SLIP-0010 and every chain's address, against their published values."
      title="Self-test"
    >
      <Card testID="self-test">
        <Box align="center" gap="s8" row>
          <Pill
            label={running ? 'Running…' : ok ? 'All pass' : results ? 'Failures' : 'Not run'}
            tone={running ? 'neutral' : ok ? 'success' : 'destructive'}
          />
          <RnText testID="self-test-summary" variant="subheadlineMedium">
            {results ? `${passed} of ${all} vectors match` : 'Checking the vectors…'}
          </RnText>
        </Box>
        {results
          ?.filter(result => !result.passed)
          .map(({actual, check}) => (
            <RnText color="content.destructive" key={check.id} variant="footnote">
              {check.title}: {actual}
            </RnText>
          ))}
      </Card>
      <Box gap="s8" row>
        <Island flex={1}>
          <Button disabled={running} label="Run again" onPress={run} variant="secondary" />
        </Island>
        <Island flex={1}>
          <Button label="See each vector" onPress={() => router.push('/debug/primitives')} variant="secondary" />
        </Island>
      </Box>
    </Section>
  )
}

const Adapters = ({crypto}: {crypto: AppCrypto}) => (
  <Section
    caption="Each adapter declares the capabilities it needs; the registry refused it at start-up if the engine lacked one. TRON is defined in this app, with no change to any package."
    title="Adapters"
  >
    {crypto.adapters.map(adapter => (
      <Card key={adapter.id} testID={`adapter-${adapter.id}`}>
        <Box align="center" gap="s8" row>
          <RnText fill variant="headline">
            {adapter.name}
          </RnText>
          {adapter.id === 'tron' ? <Pill label="This app" tone="accent" /> : <Pill label={`v${adapter.version}`} />}
        </Box>
        <RnText color="content.secondary" monospaced variant="footnote">
          {`${adapter.id} · ${adapter.curve} · ${[...adapter.formats.address, ...adapter.formats.signature].join(', ')}`}
        </RnText>
        <Box gap="s6" row wrap>
          {Object.entries(adapter.features).map(([feature, on]) => (
            <Pill key={feature} label={on ? feature : `no ${feature}`} tone={on ? 'success' : 'neutral'} />
          ))}
        </Box>
      </Card>
    ))}
  </Section>
)

export const OverviewScreen = () => {
  const router = useRouter()
  const {crypto, error, liveHandles, wallet} = useCrypto()

  if (!crypto) {
    return (
      <Page>
        <Island>
          <EmptyState
            description={error?.message ?? 'The native module did not load.'}
            icon="warning-filled"
            title="No native engine"
          />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="overview">
      <Lead>
        Native cryptography for React Native: a Zig engine behind Nitro Modules, with chains as adapters. Every value on
        these screens comes from the engine, nothing is mocked.
      </Lead>
      <DemoNotice compact />
      <SelfTest />
      <Section title="Status">
        <Island>
          <Rows>
            <LabeledContent
              label="Demo wallet"
              value={wallet ? wallet.fingerprint.toString(16).padStart(8, '0') : 'None'}
            />
            <RowDivider />
            <LabeledContent label="Secrets in the engine" value={String(liveHandles)} />
          </Rows>
        </Island>
      </Section>
      <Section
        caption="The library on its own, before the wallet: a demo wallet that lives in memory, mainnet accounts, signatures, primitives and benchmarks."
        title="Screens"
      >
        <Island>
          <Rows>
            {SCREENS.map(({href, icon, label}, index) => (
              <Fragment key={href}>
                {index > 0 ? <RowDivider /> : null}
                <LabeledContent
                  icon={icon}
                  label={label}
                  onPress={() => router.push(href)}
                  testID={href.replace('/debug/', 'debug-')}
                />
              </Fragment>
            ))}
          </Rows>
        </Island>
      </Section>
      <Engine crypto={crypto} />
      <Section title={`Capabilities (${crypto.info.capabilities.length})`}>
        <Pills labels={crypto.info.capabilities} tone="accent" />
      </Section>
      <Adapters crypto={crypto} />
      <Runtime />
    </Page>
  )
}
