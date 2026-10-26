const fs = require('node:fs')
const path = require('node:path')
const {getDefaultConfig} = require('expo/metro-config')

const projectRoot = __dirname
const workspaceRoot = path.resolve(projectRoot, '../..')
const packagesRoot = path.resolve(workspaceRoot, 'packages')

const config = getDefaultConfig(projectRoot)

config.watchFolders = [workspaceRoot]

config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, 'node_modules'),
  path.resolve(workspaceRoot, 'node_modules'),
]

/**
 * Every workspace package's entry points mapped to the TypeScript source its `exports` names under `source`. The
 * published entry points are the built `build/`, which would make every edit wait for a build; here the example runs
 * the package's source, so Fast Refresh reaches it like app code.
 */
const packageSources = new Map(
  fs
    .readdirSync(packagesRoot)
    .map(directory => path.join(packagesRoot, directory))
    .filter(directory => fs.existsSync(path.join(directory, 'package.json')))
    .flatMap(directory => {
      const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'))

      return Object.entries(manifest.exports ?? {})
        .filter(([, target]) => typeof target === 'object' && target.source)
        .map(([subpath, target]) => [path.posix.join(manifest.name, subpath), path.resolve(directory, target.source)])
    })
)

config.resolver.resolveRequest = (context, moduleName, platform) => {
  const source = packageSources.get(moduleName)

  return source ? {filePath: source, type: 'sourceFile'} : context.resolveRequest(context, moduleName, platform)
}

module.exports = config
