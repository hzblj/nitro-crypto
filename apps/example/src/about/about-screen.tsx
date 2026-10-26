import {Box, EmptyState, Island, LabeledContent, RnText} from '@hzblj/kara-ui'
import {openBrowserAsync} from 'expo-web-browser'
import {Fragment} from 'react'

import {useCrypto} from '../crypto'
import {Card, DemoNotice, Lead, Page, Pills, RowDivider, Rows, Section} from '../ui'
import {PACKAGE_VERSIONS, PLATFORM_VERSIONS} from './versions'

const REPOSITORY = 'https://github.com/hzblj/nitro-crypto/blob/main'

/** The layers, top to bottom: each depends only on the one below it. */
const LAYERS = [
  {detail: 'Expo Router, Kara UI. Never sees a private key.', title: 'This app'},
  {
    detail: '@hzblj/crypto-ethereum, -bitcoin, -solana, and TRON from this app: paths, addresses, message formats.',
    title: 'Chain adapters (TypeScript)',
  },
  {detail: 'Typed facade, adapter registry, capability checks, wallets, errors.', title: '@hzblj/nitro-crypto'},
  {detail: 'Generated JSI bindings; buffers cross without copies.', title: 'Nitro Modules'},
  {detail: 'Three Hybrid Objects over the C ABI. No cryptography.', title: 'C++ bridge'},
  {detail: 'Versioned C ABI, opaque handles, zeroized on release.', title: 'nitro_crypto.h'},
  {
    detail: 'libsecp256k1 (Bitcoin Core), Zig std (SHA-2, Keccak, Ed25519, PBKDF2), RIPEMD-160, BIP-39/32, SLIP-0010.',
    title: 'Zig engine',
  },
] as const

const Architecture = () => (
  <Section
    caption="No layer knows a chain below the adapters; adding one whose primitives exist touches nothing but a new adapter."
    title="Architecture"
  >
    <Box gap="s4" testID="architecture">
      {LAYERS.map((layer, index) => (
        <Fragment key={layer.title}>
          {index > 0 ? (
            <RnText align="center" color="content.tertiary" variant="caption">
              ↓
            </RnText>
          ) : null}
          <Box
            bg={index === LAYERS.length - 1 ? 'fill.accent.base' : 'surface.primary'}
            borderRadius="medium"
            gap="s2"
            px="s16"
            py="s10"
          >
            <RnText
              color={index === LAYERS.length - 1 ? 'content.accent' : 'content.primary'}
              variant="subheadlineMedium"
            >
              {layer.title}
            </RnText>
            <RnText color="content.secondary" variant="footnote">
              {layer.detail}
            </RnText>
          </Box>
        </Fragment>
      ))}
    </Box>
  </Section>
)

/** The security model in short; SECURITY.md has the whole of it. */
const FACTS = [
  'Seeds and private keys live in the engine’s native memory, behind opaque handles. JavaScript holds objects, never key bytes.',
  'Nothing is persisted: delete, reload, restart or reinstall and the keys are gone. There is no backup or recovery.',
  'Disposing a key or a wallet zeroizes its slot in the engine. Copies the operating system or a runtime made are beyond reach: zeroization is best effort.',
  'These keys are not hardware-backed: neither Secure Enclave nor StrongBox holds secp256k1 or Ed25519 keys.',
  'Randomness comes from the operating system, and the engine fails closed when it has none.',
  'Not security audited. A demonstration of the architecture, never a wallet for real funds.',
] as const

const Security = () => (
  <Section title="Security">
    <Card testID="security">
      {FACTS.map(fact => (
        <Box gap="s8" key={fact} row>
          <RnText color="content.accent" variant="subheadline">
            •
          </RnText>
          <RnText fill variant="subheadline">
            {fact}
          </RnText>
        </Box>
      ))}
    </Card>
  </Section>
)

const LICENSES = [
  'libsecp256k1: MIT',
  'Zig standard library: MIT',
  'BIP-39 English word list: BSD-2-Clause (BIP-39)',
  'Nitro Modules: MIT',
  '@noble/hashes, @noble/curves (benchmarks only): MIT',
  'Kara UI: MIT',
  'Material Symbols: Apache-2.0',
] as const

const DOCUMENTS = [
  {label: 'Security policy', path: 'SECURITY.md'},
  {label: 'Architecture', path: 'docs/architecture.md'},
  {label: 'Adding an adapter', path: 'docs/adding-an-adapter.md'},
  {label: 'Compatibility', path: 'docs/compatibility.md'},
  {label: 'Benchmarks', path: 'docs/benchmarks.md'},
] as const

export const AboutScreen = () => {
  const {crypto, error} = useCrypto()

  if (!crypto) {
    return (
      <Page>
        <Island>
          <EmptyState description={error?.message} icon="warning-filled" title="No native engine" />
        </Island>
      </Page>
    )
  }

  return (
    <Page testID="about">
      <Lead>
        How the example is built, what it promises about keys, and what it does not. The documents behind each answer
        are at the end.
      </Lead>
      <DemoNotice />
      <Architecture />
      <Security />
      <Section title="Versions">
        <Island>
          <Rows>
            {PACKAGE_VERSIONS.map(({name, version}) => (
              <Fragment key={name}>
                <LabeledContent label={name} value={version} />
                <RowDivider />
              </Fragment>
            ))}
            <LabeledContent label="Engine" value={`${crypto.info.engineVersion}, C ABI ${crypto.info.abiVersion}`} />
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
      <Section title="Licenses">
        <Pills labels={LICENSES} />
      </Section>
      <Section title="Documentation">
        <Island>
          <Rows>
            {DOCUMENTS.map(({label, path}, index) => (
              <Fragment key={path}>
                {index > 0 ? <RowDivider /> : null}
                <LabeledContent
                  icon="open-in-new"
                  label={label}
                  onPress={() => openBrowserAsync(`${REPOSITORY}/${path}`)}
                />
              </Fragment>
            ))}
          </Rows>
        </Island>
      </Section>
    </Page>
  )
}
