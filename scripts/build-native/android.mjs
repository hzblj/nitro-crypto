/**
 * The engine for Android: a static archive per ABI, compiled position-independent (it is linked into the
 * module's libNitroCrypto.so) against the NDK's sysroot at the minimum API level. CMake links it; Gradle never
 * sees Zig.
 *
 * All four ABIs React Native ships, because an Expo app's release build (`reactNativeArchitectures`) builds all
 * four by default, and a missing one fails that build. Only arm64-v8a runs on the Apple Silicon emulator; the
 * others are built and link-checked, not run, here.
 */
import {cpSync, existsSync, readdirSync} from 'node:fs'
import path from 'node:path'

import {ANDROID_API_LEVEL, ENGINE_OUTPUT, fail, freshDirectory, log, writeLibcFile, zigBuild} from './shared.mjs'

/** React Native 0.86's NDK (`ndkVersion` in its libs.versions.toml). */
export const NDK_VERSION = '27.1.12297006'

/** `target` is Zig's (whose `arm` default for Android is ARMv7-A, Thumb-2, VFPv3: armeabi-v7a); `triple` the NDK's. */
const ABIS = [
  {abi: 'arm64-v8a', target: 'aarch64-linux-android', triple: 'aarch64-linux-android'},
  {abi: 'armeabi-v7a', target: 'arm-linux-androideabi', triple: 'arm-linux-androideabi'},
  {abi: 'x86', target: 'x86-linux-android', triple: 'i686-linux-android'},
  {abi: 'x86_64', target: 'x86_64-linux-android', triple: 'x86_64-linux-android'},
]

const findNdk = () => {
  const explicit = process.env.ANDROID_NDK_HOME ?? process.env.ANDROID_NDK_ROOT
  if (explicit && existsSync(explicit)) {
    return explicit
  }
  const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT
  if (!sdk) {
    fail('set ANDROID_HOME (or ANDROID_NDK_HOME) so the build can find the NDK')
  }
  const pinned = path.join(sdk, 'ndk', NDK_VERSION)
  if (existsSync(pinned)) {
    return pinned
  }
  const installed = existsSync(path.join(sdk, 'ndk')) ? readdirSync(path.join(sdk, 'ndk')) : []
  fail(`NDK ${NDK_VERSION} is required (found: ${installed.join(', ') || 'none'}). Install it with the SDK Manager.`)
}

/** The NDK names its prebuilt directory after the host; Apple Silicon still uses darwin-x86_64. */
const sysrootOf = ndk => {
  const host = process.platform === 'darwin' ? 'darwin-x86_64' : `${process.platform}-x86_64`
  const sysroot = path.join(ndk, 'toolchains/llvm/prebuilt', host, 'sysroot')
  if (!existsSync(sysroot)) {
    fail(`no NDK sysroot at ${sysroot}`)
  }
  return sysroot
}

export const buildAndroid = work => {
  const sysroot = sysrootOf(findNdk())
  const output = freshDirectory(path.join(ENGINE_OUTPUT, 'android'))

  return ABIS.map(({abi, target, triple}) => {
    const abiWork = freshDirectory(path.join(work, abi))
    const libc = writeLibcFile(abiWork, {
      crt: path.join(sysroot, 'usr/lib', triple, String(ANDROID_API_LEVEL)),
      include: path.join(sysroot, 'usr/include'),
      system: path.join(sysroot, 'usr/include', triple),
    })
    const archive = zigBuild({libc, pic: true, prefix: abiWork, target: `${target}.${ANDROID_API_LEVEL}`})
    const destination = path.join(output, abi, 'libnitro_crypto.a')
    freshDirectory(path.dirname(destination))
    cpSync(archive, destination)
    log(`built ${target} (${abi})`)
    return destination
  })
}
