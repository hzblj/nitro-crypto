/**
 * The engine for iOS: an XCFramework with a device slice (arm64) and a simulator slice (arm64 and x86_64, one
 * fat archive), each carrying the C header. The podspec vendors it; Xcode never sees Zig.
 *
 * Zig's archives are repacked with Apple's libtool: ld64 ignores any member of a Zig 0.16 archive that is not
 * 8-byte aligned ("64-bit mach-o not 8-byte aligned"), which drops libsecp256k1's tables and fails the link
 * with undefined symbols. Zig also writes the members with mode 000, so they are made readable first.
 */
import {chmodSync, cpSync, readdirSync, writeFileSync} from 'node:fs'
import path from 'node:path'

import {
  ENGINE_OUTPUT,
  freshDirectory,
  HEADER,
  IOS_DEPLOYMENT_TARGET,
  log,
  run,
  writeLibcFile,
  zigBuild,
} from './shared.mjs'

const SLICES = [
  {name: 'device', sdk: 'iphoneos', targets: ['aarch64-ios']},
  {name: 'simulator', sdk: 'iphonesimulator', targets: ['aarch64-ios-simulator', 'x86_64-ios-simulator']},
]

const sdkPath = sdk => run('xcrun', ['--sdk', sdk, '--show-sdk-path']).trim()

/** The archive's members, re-archived by libtool with the alignment ld64 requires. */
const repack = (archive, work) => {
  const members = freshDirectory(path.join(work, 'members'))
  run('ar', ['-x', archive], {cwd: members})
  const objects = readdirSync(members).filter(file => file.endsWith('.o'))
  for (const object of objects) {
    chmodSync(path.join(members, object), 0o644)
  }
  const repacked = path.join(work, 'libnitro_crypto.a')
  run('xcrun', ['libtool', '-static', '-no_warning_for_no_symbols', '-o', repacked, ...objects.sort()], {cwd: members})
  return repacked
}

const buildSlice = ({name, sdk, targets}, work) => {
  const sysroot = sdkPath(sdk)
  const sliceWork = freshDirectory(path.join(work, name))
  const libc = writeLibcFile(sliceWork, {
    crt: path.join(sysroot, 'usr/lib'),
    include: path.join(sysroot, 'usr/include'),
    system: path.join(sysroot, 'usr/include'),
  })

  const archives = targets.map(target => {
    const targetWork = freshDirectory(path.join(sliceWork, target))
    // "aarch64-ios-simulator" → "aarch64-ios.15.1-simulator": the OS version sits after the OS.
    const archive = zigBuild({
      libc,
      prefix: targetWork,
      target: target.replace('-ios', `-ios.${IOS_DEPLOYMENT_TARGET}`),
    })
    log(`built ${target}`)
    return repack(archive, targetWork)
  })

  if (archives.length === 1) {
    return archives[0]
  }
  const fat = path.join(sliceWork, 'libnitro_crypto.a')
  run('xcrun', ['lipo', '-create', ...archives, '-output', fat])
  return fat
}

/**
 * `xcodebuild -create-xcframework` lists the libraries in no fixed order, so two builds of the same archives
 * write different Info.plists. Sorted by identifier, the plist is the same bytes every time.
 */
const canonicalizeInfoPlist = (xcframework, work) => {
  const plist = path.join(xcframework, 'Info.plist')
  const info = JSON.parse(run('plutil', ['-convert', 'json', '-o', '-', plist]))
  info.AvailableLibraries.sort((a, b) => a.LibraryIdentifier.localeCompare(b.LibraryIdentifier))
  const json = path.join(work, 'Info.json')
  writeFileSync(json, JSON.stringify(info))
  run('plutil', ['-convert', 'xml1', json, '-o', plist])
}

export const buildIos = work => {
  const headers = freshDirectory(path.join(work, 'Headers'))
  cpSync(HEADER, path.join(headers, 'nitro_crypto.h'))

  const libraries = SLICES.flatMap(slice => ['-library', buildSlice(slice, work), '-headers', headers])
  const xcframework = path.join(freshDirectory(path.join(ENGINE_OUTPUT, 'ios')), 'NitroCryptoEngine.xcframework')
  run('xcodebuild', ['-create-xcframework', ...libraries, '-output', xcframework])
  canonicalizeInfoPlist(xcframework, work)
  log(`ios: ${path.relative(process.cwd(), xcframework)}`)
  return [xcframework]
}
