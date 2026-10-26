/**
 * Keeps each published package's `src/version.ts` equal to its package.json, after `changeset version` bumps the
 * latter. Adapters report their version at runtime (`adapter.version`), and a hand-kept copy would drift; each
 * package's tests fail if the two disagree, so a release cannot ship them out of step.
 */
import {existsSync} from 'node:fs'
import {readdir, readFile, writeFile} from 'node:fs/promises'
import path from 'node:path'

const PACKAGES = path.resolve(import.meta.dirname, '../packages')
const PATTERN = /export const VERSION = '[^']*'/

for (const directory of await readdir(PACKAGES)) {
  const versionFile = path.join(PACKAGES, directory, 'src/version.ts')
  if (!existsSync(versionFile)) {
    continue
  }
  const {version} = JSON.parse(await readFile(path.join(PACKAGES, directory, 'package.json'), 'utf8'))
  const source = await readFile(versionFile, 'utf8')
  if (!PATTERN.test(source)) {
    throw new Error(`${versionFile} has no \`export const VERSION = '…'\``)
  }
  const updated = source.replace(PATTERN, `export const VERSION = '${version}'`)
  if (updated !== source) {
    await writeFile(versionFile, updated)
    console.log(`sync-versions: ${directory} ${version}`)
  }
}
