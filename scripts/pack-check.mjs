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
  '@hzblj/crypto-bitcoin': ADAPTER,
  '@hzblj/crypto-ethereum': [...ADAPTER, 'build/viem.js', 'build/viem.d.ts'],
  '@hzblj/crypto-solana': [...ADAPTER, 'build/kit.js', 'build/kit.d.ts'],
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

  // An optional peer dependency belongs to its subpath alone: no other file may import it, or installing the package
  // without it would break the main entry.
  for (const [peer, meta] of Object.entries(packed.peerDependenciesMeta ?? {})) {
    if (!meta.optional) {
      continue
    }
    const importers = files.filter(
      file =>
        /^build\/.*\.js$/.test(file) &&
        file !== `build/${peer}.js` &&
        new RegExp(`from ['"]${peer}(/[^'"]*)?['"]`).test(run('tar', ['-xzOf', tarball, `package/${file}`]))
    )
    if (importers.length > 0) {
      fail(`${name} imports its optional peer ${peer} outside build/${peer}.js:\n  ${importers.join('\n  ')}`)
    }
  }

  const installed = path.join(WORK, 'node_modules', name)
  await mkdir(installed, {recursive: true})
  run('tar', ['-xzf', tarball, '-C', installed, '--strip-components', '1'])
  fileCount += files.length

  // An optional peer dependency is the app's to install or not: no published JavaScript may load it (its types may
  // be named, as `@hzblj/crypto-solana/kit` names @solana/kit's, since declarations load nothing).
  const optional = Object.entries(packed.peerDependenciesMeta ?? {}).flatMap(([peer, meta]) =>
    meta.optional ? [peer] : []
  )
  for (const file of files.filter(file => file.endsWith('.js'))) {
    const code = await readFile(path.join(installed, file), 'utf8')
    const loaded = optional.filter(peer => new RegExp(`(from|import|require)\\s*\\(?\\s*['"]${peer}['"/]`).test(code))
    if (loaded.length > 0) {
      fail(`${name}'s ${file} loads ${loaded.join(', ')}, an optional peer dependency`)
    }
  }
}

const consumer = `import {bitcoinAdapter} from '@hzblj/crypto-bitcoin'
import {ethereumAdapter, type Hex, type ParsedEthereumTransaction} from '@hzblj/crypto-ethereum'
import {toViemAccount} from '@hzblj/crypto-ethereum/viem'
import {solanaAdapter} from '@hzblj/crypto-solana'
import {toKitSigner} from '@hzblj/crypto-solana/kit'
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
import type {MessagePartialSigner, TransactionPartialSigner} from '@solana/kit'
import {createWalletClient, http} from 'viem'
import {sepolia} from 'viem/chains'

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

// Signing elsewhere: what an air-gapped signer's watch-only side and the signer itself use (@hzblj/crypto-airgap-*
// builds on these), extended public keys and public derivation.
export const elsewhere = async (psbt: Uint8Array, unsigned: Uint8Array, signature: RecoverableSignature) => {
  const crypto = createCryptoEngine({adapters: [ethereumAdapter(), bitcoinAdapter({network: 'testnet'}), solanaAdapter()]})
  const wallet = await crypto.createEphemeralWallet()
  const extendedKey: ExtendedPublicKey = wallet.extendedPublicKey("m/84'/1'/0'")
  const child: ExtendedPublicKey = crypto.bip32.derivePublic(extendedKey, 'm/0/1')
  const watch = crypto.chains.bitcoin.watchAccount({extendedKey, fingerprint: wallet.fingerprint, index: 2, path: "m/84'/1'/0'"})
  const fee: bigint | undefined = crypto.chains.bitcoin.decodePsbt(psbt).fee
  const signed: Uint8Array = (await (await wallet.deriveAccount({chain: 'bitcoin'})).signPsbt(psbt)).psbt
  const sol = await wallet.deriveAccount({chain: 'solana'})
  const v0: Uint8Array = crypto.chains.solana.compileMessage({addressLookupTables: {}, feePayer: sol.address, instructions: [], recentBlockhash: '', version: 0})
  const looked: string | undefined = crypto.chains.solana.decodeTransaction(unsigned, {addressLookupTables: {}}).accounts[0]?.address
  const partial: boolean = (await sol.partiallySignTransaction(unsigned)).complete
  const offchain: Uint8Array = (await sol.signOffchainMessage({signers: [sol.address], text: 'Hello', version: 1})).signature
  const kitSigner: TransactionPartialSigner & MessagePartialSigner = toKitSigner(sol)
  const transaction = crypto.chains.ethereum.parseTransaction(unsigned)
  const signer: string | undefined = crypto.chains.ethereum.recoverTransactionAddress({signature, transaction})
  wallet.dispose()

  // @ts-expect-error: public derivation takes an extended public key, not a path alone
  crypto.bip32.derivePublic("m/84'/1'/0'", 'm/0/1')
  // @ts-expect-error: off-chain messages are version 0 or 1
  await sol.signOffchainMessage({signers: [sol.address], text: 'Hello', version: 2})
  // @ts-expect-error: a kit signer is a Solana account's, not an Ethereum one's
  toKitSigner(await wallet.deriveAccount({chain: 'ethereum'}))

  return [child, watch.address, fee, signed, signer, v0, looked, partial, offchain, kitSigner]
}

// Ethereum beyond EIP-1559: typed data, EIP-7702 authorizations and transactions, and a viem account.
export const evm = async (unsigned: Uint8Array) => {
  const crypto = createCryptoEngine({adapters: [ethereumAdapter({chainId: 11155111, id: 'sepolia', name: 'Sepolia'})]})
  const wallet = await crypto.createEphemeralWallet()
  const account = await wallet.deriveAccount({chain: 'sepolia'})
  const typed: Hex = await account.signTypedData({
    domain: {chainId: 11155111, name: 'Example'},
    message: {amount: 1n},
    primaryType: 'Transfer',
    types: {Transfer: [{name: 'amount', type: 'uint256'}]},
  })
  const authorization = await account.signAuthorization({address: account.address, nonce: 1})
  const signed = await account.signTransaction({
    authorizationList: [authorization],
    gas: 60_000n,
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
    nonce: 0,
    to: account.address,
    type: 'eip7702',
  })
  const parsed: ParsedEthereumTransaction = crypto.chains.sepolia.parseTransaction(unsigned)
  const viemAccount = toViemAccount(account)
  const client = createWalletClient({account: viemAccount, chain: sepolia, transport: http()})
  const hash: Hex = await client.sendTransaction({to: account.address, value: 1n})

  // @ts-expect-error: the viem account signs no bare hash (eth_sign)
  await viemAccount.sign({hash})
  // @ts-expect-error: a legacy transaction pays a gasPrice, not EIP-1559 fees
  await account.signTransaction({gas: 21_000n, maxFeePerGas: 1n, nonce: 0, to: account.address, type: 'legacy'})
  // @ts-expect-error: an EIP-7702 transaction always has a recipient
  await account.signTransaction({authorizationList: [], gas: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, nonce: 0, to: null, type: 'eip7702'})

  return [typed, signed.hash, parsed.type, hash]
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
