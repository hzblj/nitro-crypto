#!/usr/bin/env node
/**
 * `yarn engine:verify`: checks the prebuilt engine in packages/nitro-crypto/engine/ before anything ships it.
 *
 *   - every artifact the package needs exists, and matches the SHA-256 in manifest.json
 *   - the header's ABI version is the manifest's
 *   - each archive defines every function the header declares, for the right architectures and platforms
 *   - nothing but `nc_*` is exported: libsecp256k1's own names stay renamed (src/curves/secp256k1_prefix.h), so an
 *     app that links another copy of it links both
 *   - the WebAssembly build exports the ABI and imports nothing but `random_get`
 *
 * Runs on macOS (it reads Mach-O load commands with otool); `--skip-ios` leaves the XCFramework out elsewhere, and
 * `--skip-android` the Android archives, for a job that builds one platform.
 */
import {execFileSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {existsSync, readFileSync} from 'node:fs'
import path from 'node:path'
import {parseArgs} from 'node:util'

const ROOT = path.resolve(import.meta.dirname, '../..')
const ENGINE = path.join(ROOT, 'packages/nitro-crypto/engine')
const {values} = parseArgs({options: {'skip-android': {type: 'boolean'}, 'skip-ios': {type: 'boolean'}}})

const problems = []
const problem = message => problems.push(message)
const run = (command, args) => execFileSync(command, args, {encoding: 'utf8', maxBuffer: 64 << 20})
const at = relative => path.join(ENGINE, relative)

const header = readFileSync(path.join(ROOT, 'packages/zig-engine-crypto/include/nitro_crypto.h'), 'utf8')
const declared = [...header.matchAll(/^[a-z_ *0-9]+?\b(nc_[a-z0-9_]+)\(/gm)].map(match => match[1])
const abiVersion = Number(header.match(/#define NC_ABI_VERSION (\d+)/)[1])

/** iOS slices: their architectures and the LC_BUILD_VERSION platform (2 iOS, 7 iOS simulator). */
const IOS_SLICES = [
  {architectures: ['arm64'], directory: 'ios-arm64', platform: 2},
  {architectures: ['arm64', 'x86_64'], directory: 'ios-arm64_x86_64-simulator', platform: 7},
]
const XCFRAMEWORK = 'ios/NitroCryptoEngine.xcframework'
const ANDROID_ABIS = ['arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64']

const required = [
  'include/nitro_crypto.h',
  'wasm/nitro_crypto.wasm',
  ...(values['skip-android'] ? [] : ANDROID_ABIS.map(abi => `android/${abi}/libnitro_crypto.a`)),
  ...(values['skip-ios']
    ? []
    : [
        `${XCFRAMEWORK}/Info.plist`,
        ...IOS_SLICES.flatMap(slice => [
          `${XCFRAMEWORK}/${slice.directory}/libnitro_crypto.a`,
          `${XCFRAMEWORK}/${slice.directory}/Headers/nitro_crypto.h`,
        ]),
      ]),
]

const checkManifest = () => {
  if (!existsSync(at('manifest.json'))) {
    problem('engine/manifest.json is missing: run `yarn engine`')
    return
  }
  const manifest = JSON.parse(readFileSync(at('manifest.json'), 'utf8'))
  if (manifest.abiVersion !== abiVersion) {
    problem(`manifest ABI ${manifest.abiVersion}, header ABI ${abiVersion}`)
  }
  for (const file of required) {
    if (!existsSync(at(file))) {
      problem(`missing ${file}`)
    } else if (!manifest.artifacts[file]) {
      problem(`${file} is not in the manifest`)
    }
  }
  for (const [file, digest] of Object.entries(manifest.artifacts)) {
    if (
      existsSync(at(file)) &&
      createHash('sha256')
        .update(readFileSync(at(file)))
        .digest('hex') !== digest
    ) {
      problem(`${file} does not match its manifest digest`)
    }
  }
  if (readFileSync(at('include/nitro_crypto.h'), 'utf8') !== header) {
    problem('engine/include/nitro_crypto.h differs from packages/zig-engine-crypto/include/nitro_crypto.h')
  }
}

/** Global symbols an archive defines, without Mach-O's leading underscore. */
const definedSymbols = archive =>
  new Set(
    run('nm', ['-g', '--defined-only', archive])
      .split('\n')
      .map(line => line.trim().split(/\s+/))
      .filter(fields => fields.length === 3)
      .map(([, , name]) => name.replace(/^_/, ''))
  )

const checkSymbols = (archive, label) => {
  const symbols = definedSymbols(archive)
  const missing = declared.filter(name => !symbols.has(name))
  if (missing.length > 0) {
    problem(`${label} lacks ${missing.join(', ')}`)
  }
  const foreign = [...symbols].filter(name => !name.startsWith('nc_'))
  if (foreign.length > 0) {
    problem(`${label} exports names outside nc_*: ${foreign.slice(0, 8).join(', ')}`)
  }
}

const checkIos = () => {
  for (const slice of IOS_SLICES) {
    const archive = at(`${XCFRAMEWORK}/${slice.directory}/libnitro_crypto.a`)
    if (!existsSync(archive)) {
      continue
    }
    const label = `ios ${slice.directory}`
    const architectures = run('lipo', ['-archs', archive]).trim().split(/\s+/).sort()
    if (architectures.join() !== slice.architectures.join()) {
      problem(`${label}: architectures ${architectures.join()}, expected ${slice.architectures.join()}`)
    }
    const platforms = new Set(
      [...run('otool', ['-l', archive]).matchAll(/platform (\d+)/g)].map(match => Number(match[1]))
    )
    if (platforms.size !== 1 || !platforms.has(slice.platform)) {
      problem(`${label}: built for platform(s) ${[...platforms].join()}, expected ${slice.platform}`)
    }
    checkSymbols(archive, label)
  }
}

const checkAndroid = () => {
  for (const abi of ANDROID_ABIS) {
    const archive = at(`android/${abi}/libnitro_crypto.a`)
    if (existsSync(archive)) {
      checkSymbols(archive, `android ${abi}`)
    }
  }
}

const checkWasm = async () => {
  const file = at('wasm/nitro_crypto.wasm')
  if (!existsSync(file)) {
    return
  }
  const module = await WebAssembly.compile(readFileSync(file))
  const exports = new Set(WebAssembly.Module.exports(module).map(entry => entry.name))
  const missing = [...declared, 'nc_wasm_alloc', 'nc_wasm_free'].filter(name => !exports.has(name))
  if (missing.length > 0) {
    problem(`wasm lacks ${missing.join(', ')}`)
  }
  const imports = WebAssembly.Module.imports(module).map(entry => `${entry.module}.${entry.name}`)
  if (imports.join() !== 'wasi_snapshot_preview1.random_get') {
    problem(`wasm imports ${imports.join(', ')}; only wasi_snapshot_preview1.random_get is expected`)
  }
}

checkManifest()
if (!values['skip-ios']) {
  checkIos()
}
if (!values['skip-android']) {
  checkAndroid()
}
await checkWasm()

if (problems.length > 0) {
  console.error(`verify-artifacts: ${problems.length} problem(s)\n  ${problems.join('\n  ')}`)
  process.exit(1)
}
console.log(
  `verify-artifacts: ${required.length} artifacts, ${declared.length} ABI functions in each, nothing else exported`
)
