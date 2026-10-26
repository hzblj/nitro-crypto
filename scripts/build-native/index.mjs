#!/usr/bin/env node
/**
 * `yarn engine [--platform ios,android,wasm]`: builds the Zig engine for every platform the package ships, into
 * packages/nitro-crypto/engine/, and writes engine/manifest.json (versions, toolchain, and a SHA-256 of every
 * artifact, which `yarn engine:verify` checks).
 *
 * Without `--platform` it builds everything this machine can: iOS needs macOS and Xcode, Android needs the NDK.
 * A release builds all three on macOS.
 */
import {cpSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync} from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {parseArgs} from 'node:util'

import {buildAndroid, NDK_VERSION} from './android.mjs'
import {buildIos} from './ios.mjs'
import {
  ANDROID_API_LEVEL,
  checkZig,
  ENGINE_OUTPUT,
  ENGINE_SOURCE,
  freshDirectory,
  HEADER,
  IOS_DEPLOYMENT_TARGET,
  log,
  ROOT,
  sha256,
  ZIG_VERSION,
} from './shared.mjs'
import {buildWasm} from './wasm.mjs'

const BUILDERS = {android: buildAndroid, ios: buildIos, wasm: buildWasm}

const {values} = parseArgs({options: {platform: {type: 'string'}}})
const platforms = values.platform
  ? values.platform.split(',').map(platform => platform.trim())
  : ['wasm', 'android', ...(process.platform === 'darwin' ? ['ios'] : [])]

for (const platform of platforms) {
  if (!BUILDERS[platform]) {
    throw new Error(`unknown platform "${platform}" (ios, android, wasm)`)
  }
}

checkZig()
mkdirSync(ENGINE_OUTPUT, {recursive: true})
mkdirSync(path.join(ENGINE_OUTPUT, 'include'), {recursive: true})
cpSync(HEADER, path.join(ENGINE_OUTPUT, 'include/nitro_crypto.h'))

const work = freshDirectory(path.join(os.tmpdir(), `nitro-crypto-engine-${process.pid}`))
for (const platform of platforms) {
  BUILDERS[platform](path.join(work, platform))
}

/** Every file under engine/, recursively, with its digest: the manifest describes what is on disk now. */
const listFiles = directory =>
  readdirSync(directory).flatMap(entry => {
    const full = path.join(directory, entry)
    return statSync(full).isDirectory() ? listFiles(full) : [full]
  })

const zon = readFileSync(path.join(ENGINE_SOURCE, 'build.zig.zon'), 'utf8')
const header = readFileSync(HEADER, 'utf8')
const buildZig = readFileSync(path.join(ENGINE_SOURCE, 'build.zig'), 'utf8')

const manifest = {
  abiVersion: Number(header.match(/#define NC_ABI_VERSION (\d+)/)[1]),
  artifacts: Object.fromEntries(
    listFiles(ENGINE_OUTPUT)
      .filter(file => !file.endsWith('manifest.json'))
      .map(file => [path.relative(ENGINE_OUTPUT, file), sha256(file)])
      .sort(([a], [b]) => a.localeCompare(b))
  ),
  ecmultWindow: Number(buildZig.match(/const default_ecmult_window: u8 = (\d+);/)[1]),
  engineVersion: zon.match(/\.version = "([^"]+)"/)[1],
  secp256k1: zon.match(/secp256k1\/archive\/refs\/tags\/(v\d+\.\d+\.\d+)/)[1],
  targets: {
    android: {apiLevel: ANDROID_API_LEVEL, ndk: NDK_VERSION},
    ios: {deploymentTarget: IOS_DEPLOYMENT_TARGET},
  },
  zig: ZIG_VERSION,
}

const manifestPath = path.join(ENGINE_OUTPUT, 'manifest.json')
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
log(`${Object.keys(manifest.artifacts).length} artifacts, ${path.relative(ROOT, manifestPath)}`)

if (!existsSync(path.join(ENGINE_OUTPUT, 'wasm'))) {
  log('note: no wasm build; the TypeScript tests need `yarn engine:wasm`')
}
