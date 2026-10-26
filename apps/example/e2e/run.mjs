#!/usr/bin/env node
/**
 * `yarn e2e ios|android [flow ...] [--release] [--maestro-option=value ...]`: runs the Maestro flows against the booted
 * simulator or the running emulator, on the development build installed there and the Metro server on port 8081, or
 * with `--release` on the release build installed there. The platform names the device (Maestro alone takes whichever
 * it finds first, an emulator for `ios` too); `--device=…` chooses another. Maestro's own options are passed before its
 * `test` command.
 *
 * Flows get `APP_ID` (read from app.config.ts), `BUILD` (`development` or `release`), `DEV_SERVER_LINK` (the dev
 * client's deep link to Metro) and `OUT` (the flow's name, which prefixes its screenshots). Reports go to
 * e2e/output/<platform>/reports/, screenshots beside them.
 */
import {execFileSync, spawnSync} from 'node:child_process'
import {copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync} from 'node:fs'
import path from 'node:path'

const ROOT = import.meta.dirname
const [platform, ...rest] = process.argv.slice(2)
if (platform !== 'ios' && platform !== 'android') {
  console.error('Usage: yarn e2e <ios|android> [flow ...] [--maestro-flag=value ...]')
  process.exit(2)
}

const config = readFileSync(path.join(ROOT, '../app.config.ts'), 'utf8')
const appId = /const BUNDLE_ID = '([^']+)'/.exec(config)?.[1]
const scheme = /scheme: '([^']+)'/.exec(config)?.[1]
if (!appId || !scheme) {
  throw new Error('app.config.ts must state BUNDLE_ID and scheme as string literals')
}

/** The booted simulator's UDID, or the first Android emulator or device adb lists as ready. */
const deviceFor = target => {
  if (target === 'ios') {
    const {devices} = JSON.parse(
      execFileSync('xcrun', ['simctl', 'list', 'devices', 'booted', '--json'], {encoding: 'utf8'})
    )

    return Object.values(devices)
      .flat()
      .find(device => device.state === 'Booted')?.udid
  }

  const ready = execFileSync('adb', ['devices'], {encoding: 'utf8'})
    .split('\n')
    .slice(1)
    .map(line => line.trim().split(/\s+/))
    .find(([, state]) => state === 'device')

  return ready?.[0]
}

const release = rest.includes('--release')
const options = rest.filter(arg => arg.startsWith('-') && arg !== '--release')
const chosen = options.some(arg => arg.startsWith('--device') || arg.startsWith('--udid'))
const device = chosen ? undefined : deviceFor(platform)

if (!chosen && !device) {
  console.error(platform === 'ios' ? 'No iOS simulator is booted.' : 'No Android emulator or device is running.')
  process.exit(2)
}

const flags = device ? [`--device=${device}`, ...options] : options
const named = rest.filter(arg => !arg.startsWith('-'))
// `release-*` flows expect a release build (no dev client): they run only when named.
const flows =
  named.length > 0
    ? named
    : readdirSync(path.join(ROOT, 'flows'))
        .filter(file => file.endsWith('.yaml') && !file.startsWith('release-'))
        .map(file => file.slice(0, -5))
const output = path.join(ROOT, 'output', platform)
mkdirSync(output, {recursive: true})

// The dev client's own chrome stays out of the way: no menu introduction, no menu opened at launch (either one lays a
// sheet over the app and hides it from Maestro), and no floating button over the content.
/** Every file under `directory` whose name ends in `.png`: Maestro nests screenshots deep inside its report. */
const screenshots = directory =>
  readdirSync(directory).flatMap(entry => {
    const full = path.join(directory, entry)
    return statSync(full).isDirectory() ? screenshots(full) : entry.endsWith('.png') ? [full] : []
  })

const link = `${scheme}://expo-development-client/?url=${encodeURIComponent('http://localhost:8081')}&disableOnboarding=1&disableAutoLaunch=1&disableFab=1`
const report = flow => path.join(output, 'reports', flow)
rmSync(path.join(output, 'reports'), {force: true, recursive: true})
let failed = 0
for (const flow of flows) {
  const result = spawnSync(
    'maestro',
    [
      ...flags,
      'test',
      '--env',
      `APP_ID=${appId}`,
      '--env',
      `BUILD=${release ? 'release' : 'development'}`,
      '--env',
      `DEV_SERVER_LINK=${link}`,
      '--env',
      `OUT=${flow}`,
      '--test-output-dir',
      report(flow),
      path.join(ROOT, 'flows', `${flow}.yaml`),
    ],
    {stdio: 'inherit'}
  )
  if (result.status !== 0) {
    failed++
  }
  // The flow's screenshots, collected beside the reports: e2e/output/<platform>/<flow>-01-….png.
  for (const file of screenshots(report(flow)).filter(file => path.basename(file).startsWith(`${flow}-`))) {
    copyFileSync(file, path.join(output, path.basename(file)))
  }
}
process.exit(failed === 0 ? 0 : 1)
