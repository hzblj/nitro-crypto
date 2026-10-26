/**
 * What every native build shares: where things are, the pinned toolchain, and one way to run `zig build`.
 *
 * Every artifact lands in packages/nitro-crypto/engine/, the directory npm ships, so an app installs the engine
 * prebuilt and never needs Zig. The directory is build output: gitignored, rebuilt by `yarn engine`.
 */
import {execFileSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {existsSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs'
import path from 'node:path'

export const ROOT = path.resolve(import.meta.dirname, '../..')
export const ENGINE_SOURCE = path.join(ROOT, 'packages/zig-engine-crypto')
export const ENGINE_OUTPUT = path.join(ROOT, 'packages/nitro-crypto/engine')
export const HEADER = path.join(ENGINE_SOURCE, 'include/nitro_crypto.h')

/** The toolchain the artifacts are reproducible with. A different Zig is refused, not tolerated. */
export const ZIG_VERSION = '0.16.0'
/** React Native 0.86's floors: `min_ios_version_supported` and `minSdk`. */
export const IOS_DEPLOYMENT_TARGET = '15.1'
export const ANDROID_API_LEVEL = 24

/**
 * `ZERO_AR_DATE` makes Apple's libtool write zero timestamps into archives, so two builds of the same source
 * are the same bytes.
 */
const ENVIRONMENT = {...process.env, ZERO_AR_DATE: '1'}

export const run = (command, args, options = {}) =>
  execFileSync(command, args, {cwd: ROOT, encoding: 'utf8', env: ENVIRONMENT, stdio: 'pipe', ...options})

export const log = message => process.stdout.write(`engine: ${message}\n`)

export const fail = message => {
  process.stderr.write(`engine: ${message}\n`)
  process.exit(1)
}

export const checkZig = () => {
  let version
  try {
    version = run('zig', ['version']).trim()
  } catch {
    fail(`Zig ${ZIG_VERSION} is required to build the engine from source (https://ziglang.org/download/)`)
  }
  if (version !== ZIG_VERSION) {
    fail(`Zig ${ZIG_VERSION} is required, found ${version}`)
  }
}

/** Zig's `--libc` file: where a cross-compilation finds the target's C headers and runtime. */
export const writeLibcFile = (directory, {crt, include, system}) => {
  const file = path.join(directory, 'libc.txt')
  const lines = [`include_dir=${include}`, `sys_include_dir=${system}`, `crt_dir=${crt}`]
  writeFileSync(file, `${[...lines, 'msvc_lib_dir=', 'kernel32_lib_dir=', 'gcc_dir='].join('\n')}\n`)
  return file
}

/** `zig build` of the static library for one target, into `prefix`. Returns the archive. */
export const zigBuild = ({libc, pic = false, prefix, target}) => {
  const args = [
    'build',
    `-Dtarget=${target}`,
    '-Doptimize=ReleaseFast',
    '-Dstrip=true',
    '--prefix',
    prefix,
    '--libc',
    libc,
  ]
  if (pic) {
    args.push('-Dpic=true')
  }
  run('zig', args, {cwd: ENGINE_SOURCE})
  return path.join(prefix, 'lib', 'libnitro_crypto.a')
}

export const freshDirectory = directory => {
  rmSync(directory, {force: true, recursive: true})
  mkdirSync(directory, {recursive: true})
  return directory
}

export const sha256 = file => createHash('sha256').update(readFileSync(file)).digest('hex')

export const ensureFile = (file, hint) => {
  if (!existsSync(file)) {
    fail(`${path.relative(ROOT, file)} is missing. ${hint}`)
  }
}
