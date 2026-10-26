/**
 * Checks what npm would receive, the way a consumer meets it. Packs every published package (each `prepack` builds it
 * through turbo's cache), asserts what must and must not ship in each tarball, then installs them into a throwaway
 * app and type-checks real usage with a consumer's TypeScript: no `source` condition, no workspace links, only what
 * the tarballs declare.
 *
 * The negative cases matter as much as the positive ones: if a declaration failed to resolve, its imports would
 * quietly become `any` and everything would compile, so each `@ts-expect-error` is there to prove the types are real.
 *
 * The engine artifacts must exist (`yarn engine`): a tarball without them would install and fail at link time.
 */
import {execFileSync} from 'node:child_process'
import {existsSync} from 'node:fs'
import {mkdir, readdir, readFile, rm, writeFile} from 'node:fs/promises'
import path from 'node:path'

const ROOT = path.resolve(import.meta.dirname, '..')
const WORK = path.join(ROOT, '.pack-check')

const run = (command, args, cwd = ROOT) => execFileSync(command, args, {cwd, encoding: 'utf8', maxBuffer: 64 << 20})

const fail = message => {
  console.error(`pack-check: ${message}`)
  process.exit(1)
}

const ENGINE = [
  'engine/manifest.json',
  'engine/include/nitro_crypto.h',
  'engine/ios/NitroCryptoEngine.xcframework/Info.plist',
  'engine/ios/NitroCryptoEngine.xcframework/ios-arm64/libnitro_crypto.a',
  'engine/ios/NitroCryptoEngine.xcframework/ios-arm64_x86_64-simulator/libnitro_crypto.a',
  ...['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'].map(abi => `engine/android/${abi}/libnitro_crypto.a`),
]

const ADAPTER = ['package.json', 'README.md', 'LICENSE', 'build/index.js', 'build/index.d.ts']

const REQUIRED = {
  '@hzblj/crypto-airgap': ADAPTER,
  '@hzblj/crypto-airgap-bitcoin': ADAPTER,
  '@hzblj/crypto-airgap-ethereum': ADAPTER,
  '@hzblj/crypto-airgap-solana': ADAPTER,
  '@hzblj/crypto-bitcoin': ADAPTER,
  '@hzblj/crypto-ethereum': ADAPTER,
  '@hzblj/crypto-solana': ADAPTER,
  '@hzblj/nitro-crypto': [
    'package.json',
    'README.md',
    'LICENSE',
    'build/index.js',
    'build/index.d.ts',
    'build/adapter.js',
    'build/adapter.d.ts',
    'build/testing.js',
    'build/testing.d.ts',
    'build/host/wasm-binary.generated.js',
    'NitroCrypto.podspec',
    'nitro.json',
    'android/build.gradle',
    'android/CMakeLists.txt',
    'android/fix-prefab.gradle',
    'android/gradle.properties',
    'android/src/main/AndroidManifest.xml',
    'android/src/main/cpp/cpp-adapter.cpp',
    'android/src/main/java/com/margelo/nitro/nitrocrypto/NitroCryptoPackage.kt',
    'cpp/EngineBridge.hpp',
    'cpp/EngineHandle.hpp',
    'cpp/HybridNitroCrypto.cpp',
    'cpp/HybridNitroKey.cpp',
    'cpp/HybridNitroSeed.cpp',
    'nitrogen/generated/ios/NitroCrypto+autolinking.rb',
    'nitrogen/generated/android/NitroCrypto+autolinking.cmake',
    'nitrogen/generated/shared/c++/HybridNitroCryptoSpec.hpp',
    ...ENGINE,
  ],
}

// Tests, TypeScript sources, the WebAssembly binary (the testing entry carries it), and native build output stay home.
const FORBIDDEN = [
  /^src\//,
  /^test\//,
  /^engine\/wasm\//,
  /\/build\/intermediates\//,
  /\.cxx\//,
  /\.DS_Store$/,
  /\.tsbuildinfo$/,
]

for (const file of ENGINE) {
  if (!existsSync(path.join(ROOT, 'packages/nitro-crypto', file))) {
    fail(`packages/nitro-crypto/${file} is missing: run \`yarn engine\` first`)
  }
}

const packages = []
for (const directory of await readdir(path.join(ROOT, 'packages'))) {
  const manifestPath = path.join(ROOT, 'packages', directory, 'package.json')
  if (!existsSync(manifestPath)) {
    continue
  }
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  if (!manifest.private) {
    packages.push({directory, name: manifest.name})
  }
}

await rm(WORK, {force: true, recursive: true})
await mkdir(path.join(WORK, 'tarballs'), {recursive: true})

let fileCount = 0
for (const {directory, name} of packages) {
  const tarball = path.join(WORK, 'tarballs', `${directory}.tgz`)
  run('yarn', ['pack', '--out', tarball], path.join(ROOT, 'packages', directory))

  const files = run('tar', ['-tzf', tarball])
    .split('\n')
    .filter(Boolean)
    .map(file => file.replace(/^package\//, ''))
  const missing = (REQUIRED[name] ?? ['package.json', 'README.md']).filter(file => !files.includes(file))
  const leaked = files.filter(file => FORBIDDEN.some(pattern => pattern.test(file)))
  if (missing.length > 0) {
    fail(`${name} is missing:\n  ${missing.join('\n  ')}`)
  }
  if (leaked.length > 0) {
    fail(`${name} must not ship:\n  ${leaked.join('\n  ')}`)
  }

  const packed = JSON.parse(run('tar', ['-xzOf', tarball, 'package/package.json']))
  for (const field of ['dependencies', 'peerDependencies']) {
    if (JSON.stringify(packed[field] ?? {}).includes('workspace:')) {
      fail(`${name} still declares a workspace: range in ${field}: it would not install outside this repo`)
    }
  }
  // `source` points at src/, which stays home: a consumer that sets the condition (a monorepo's own tests do) would
  // resolve to a file that is not there. `publishConfig.exports` is the published map without it.
  if (JSON.stringify(packed.exports ?? {}).includes('"source"')) {
    fail(`${name} publishes a \`source\` condition in its exports, to a src/ it does not ship`)
  }

  const installed = path.join(WORK, 'node_modules', name)
  await mkdir(installed, {recursive: true})
  run('tar', ['-xzf', tarball, '-C', installed, '--strip-components', '1'])
  fileCount += files.length
}

const consumer = `import {
  CRYPTO_MULTI_ACCOUNTS,
  createMultipartDecoder,
  createMultipartEncoder,
  createRequestId,
  fromUR,
  isAirgapError,
  type UR,
} from '@hzblj/crypto-airgap'
import {bitcoinAirgap} from '@hzblj/crypto-airgap-bitcoin'
import {ethereumAirgap} from '@hzblj/crypto-airgap-ethereum'
import {solanaAirgap} from '@hzblj/crypto-airgap-solana'
import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {ethereumAdapter, type Hex} from '@hzblj/crypto-ethereum'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {
  base58,
  type CryptoEngine,
  createCryptoEngine,
  type EphemeralWallet,
  type ExtendedPublicKey,
  hex,
  isCryptoError,
  type RecoverableSignature,
} from '@hzblj/nitro-crypto'
import {defineAdapter, type KeySource} from '@hzblj/nitro-crypto/adapter'
import {createTestCryptoEngine} from '@hzblj/nitro-crypto/testing'

export const app = async () => {
  const crypto = createCryptoEngine({adapters: [ethereumAdapter(), bitcoinAdapter({network: 'testnet'}), solanaAdapter()]})
  const wallet = await crypto.createEphemeralWallet()
  const eth = await wallet.deriveAccount({chain: 'ethereum', index: 1})
  const btc = await wallet.deriveAccount({chain: 'bitcoin', change: 1})
  const sol = await wallet.deriveAccount({account: 2, chain: 'solana'})
  const signature: Hex = await eth.signMessage({message: 'Hello from Expo'})
  const verified: boolean = await eth.verifyMessage({message: 'Hello from Expo', signature})
  const solSignature: Uint8Array = await sol.signMessage({message: new Uint8Array([1, 2, 3])})
  const script: Uint8Array = btc.scriptPubKey
  const digest: Uint8Array = crypto.hash.keccak256(new Uint8Array())
  const recovered: Uint8Array = crypto.secp256k1.recover(digest, {recovery: 0, signature: new Uint8Array(64)} satisfies RecoverableSignature)
  wallet.dispose()

  // @ts-expect-error: no adapter registers this chain
  await wallet.deriveAccount({chain: 'dogecoin'})
  // @ts-expect-error: Bitcoin accounts sign nothing in this version
  await btc.signMessage({message: 'x'})
  // @ts-expect-error: hashes take bytes, not strings
  crypto.hash.sha256('abc')

  return [verified, solSignature, script, recovered, hex.encode(digest), base58.encode(digest), isCryptoError(null)]
}

export const airgap = async (scanned: UR) => {
  const crypto = createCryptoEngine({adapters: [ethereumAdapter(), bitcoinAdapter({network: 'testnet'}), solanaAdapter()]})
  const btc = bitcoinAirgap(crypto.chains.bitcoin)
  const eth = ethereumAirgap(crypto.chains.ethereum)
  const sol = solanaAirgap(crypto.chains.solana)
  const {sha256} = crypto.hash
  const sender = createMultipartEncoder(btc.encodeSignRequest({psbt: new Uint8Array()}), {maxFragmentLength: 180, sha256})
  const part: string = sender.nextPart()
  const receiver = createMultipartDecoder({allowedTypes: [...eth.responseTypes, ...sol.responseTypes], sha256})
  receiver.receivePart(part)
  const fraction: number = receiver.progress.fraction
  const account = {address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', fingerprint: 1, path: "m/44'/60'/0'/0/0"} as const
  const request = eth.decodeSignRequest(scanned, {account})
  const to: string | undefined = request.kind === 'transaction' ? request.transaction.to : request.text
  const answer = eth.decodeSignResponse(scanned, {request: {account, message: 'x', requestId: createRequestId(crypto.random)}})
  const serialized: string | undefined = answer.kind === 'transaction' ? answer.transaction.serialized : undefined
  const keys = fromUR(CRYPTO_MULTI_ACCOUNTS, scanned).keys.map(key => sol.watchAccount(key).address)
  const review = btc.decodeSignRequest(scanned, {account: crypto.chains.bitcoin.watchAccount({fingerprint: 1, path: "m/84'/1'/0'/0/0", publicKey: new Uint8Array(33)})})
  const fee: bigint | undefined = review.fee

  // Account keys: Sparrow's crypto-account, MetaMask's crypto-hdkey, and requests for any address of the account.
  const wallet = await crypto.createEphemeralWallet()
  const extendedKey: ExtendedPublicKey = wallet.extendedPublicKey("m/84'/1'/0'")
  const child: ExtendedPublicKey = crypto.bip32.derivePublic(extendedKey, 'm/0/1')
  const bitcoinKey = btc.accountKey({extendedKey, fingerprint: wallet.fingerprint, path: "m/84'/1'/0'"})
  const sparrow: UR<'crypto-account'> = btc.encodeAccount({keys: [bitcoinKey], masterFingerprint: wallet.fingerprint})
  const third: string = btc.watchAccount(bitcoinKey, wallet.fingerprint, 2).address
  const metamask = eth.accountKey({extendedKey: wallet.extendedPublicKey("m/44'/60'/0'"), fingerprint: 1, name: 'Wallet', path: "m/44'/60'/0'"})
  const anyAddress = eth.decodeSignRequest(scanned, {accountPath: "m/44'/60'/0'", fingerprint: wallet.fingerprint})
  const signed = eth.encodeSignResponse(await eth.signRequest(anyAddress, path => wallet.deriveAccount({chain: 'ethereum', path})))
  const psbt = btc.decodeSignRequest(scanned, {accountPath: "m/84'/1'/0'", fingerprint: wallet.fingerprint})
  const answered: UR = btc.encodeSignResponse(await btc.signRequest(psbt, path => wallet.deriveAccount({chain: 'bitcoin', path})))
  wallet.dispose()

  // @ts-expect-error: an Ethereum request carries no PSBT
  request.psbt
  // @ts-expect-error: decoders take an allowlist
  createMultipartDecoder({sha256})
  // @ts-expect-error: multipart takes SHA-256 from the caller (the engine), having none of its own
  createMultipartEncoder(scanned, {maxFragmentLength: 180})

  return [fraction, to, serialized, keys, fee, child, sparrow, third, metamask, signed, answered, isAirgapError(null, 'REQUEST_MISMATCH')]
}

export const customChain = defineAdapter({
  create: () => ({
    deriveAccount: async (keys: KeySource, request: {index: number}) => keys.deriveKey('bip32', \`m/0/\${request.index}\`).publicKey(),
    validateAddress: () => ({reason: 'none', valid: false as const}),
  }),
  curve: 'secp256k1',
  features: {},
  formats: {address: [], signature: []},
  id: 'custom',
  name: 'Custom',
  requires: ['bip32-secp256k1'],
  version: '1.0.0',
})

export const tests = async () => {
  const crypto: CryptoEngine<{readonly custom: ReturnType<typeof customChain.create>}> = createTestCryptoEngine({adapters: [customChain]})
  const wallet: EphemeralWallet<typeof crypto.chains> = await crypto.createEphemeralWallet({mnemonic: 'test'})
  const key: Uint8Array = await wallet.deriveAccount({chain: 'custom', index: 0})
  // @ts-expect-error: the custom chain needs an index
  await wallet.deriveAccount({chain: 'custom'})
  return key
}
`

await writeFile(path.join(WORK, 'consumer.ts'), consumer)
await writeFile(
  path.join(WORK, 'tsconfig.json'),
  JSON.stringify(
    {
      compilerOptions: {lib: ['ESNext', 'DOM'], noEmit: true, skipLibCheck: true, strict: true, types: []},
      extends: 'expo/tsconfig.base',
      include: ['consumer.ts'],
    },
    null,
    2
  )
)

try {
  run('yarn', ['run', '-T', 'tsc', '-p', WORK])
} catch (error) {
  fail(`a consumer's type check failed:\n${error.stdout}`)
}

await rm(WORK, {force: true, recursive: true})
console.log(`pack-check: ${packages.length} packages, ${fileCount} files, and a consumer type-checks`)
