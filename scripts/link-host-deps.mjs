/**
 * Point this checkout at the harness's own copies of the host packages.
 *
 * dsh-reaper ships no dependencies on purpose: at runtime the harness resolves
 * `@deepseek-ai/*` from its own installation, and a bundled copy would shadow
 * the real one. But a checkout with no `node_modules` cannot import those
 * packages at all, so this script links the three that `lib/` imports.
 *
 * Junctions on Windows, symlinks elsewhere — `ln -s` needs developer mode on
 * Windows and `mklink /J` needs cmd, so the platform is branched explicitly.
 *
 * Usage: `npm run setup:deps` (or `node scripts/link-host-deps.mjs`).
 *
 * @module dsh-reaper/scripts/link-host-deps
 */

import { existsSync, mkdirSync, symlinkSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Packages `lib/` imports, mapped to their directory name under the host. */
const HOST_PACKAGES = ['cordis', 'dsh-tools', 'schemastery']

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Locate the harness installation that owns `@deepseek-ai/*`.
 *
 * Candidates are tried in order, most explicit first: an override the caller
 * set, then the standard desktop and user install locations. The first one that
 * actually contains `@deepseek-ai/dsh-tools` wins, because that package is what
 * the plugin really needs — a directory that merely exists is not enough.
 *
 * @returns {string | undefined} the `@deepseek-ai` directory, when found.
 */
function findHostScope() {
  const candidates = [
    process.env.DSH_HOST_NODE_MODULES,
    'E:\\deepseekharness\\DSH Desktop\\resources\\app\\node_modules',
    process.env.LOCALAPPDATA === undefined ? undefined : join(process.env.LOCALAPPDATA, 'Programs', 'dsh', 'resources', 'app', 'node_modules'),
    process.env.DSH_HOME === undefined ? undefined : join(process.env.DSH_HOME, 'dsh-runtimes', 'dsh-primary-runtime', 'node_modules'),
  ].filter((value) => typeof value === 'string' && value !== '')

  for (const candidate of candidates) {
    const scope = join(candidate, '@deepseek-ai')
    if (existsSync(join(scope, 'dsh-tools', 'package.json'))) return scope
  }
  return undefined
}

const scope = findHostScope()
if (scope === undefined) {
  console.error('Could not find the harness installation.')
  console.error('Set DSH_HOST_NODE_MODULES to the harness\'s node_modules directory and retry, e.g.')
  console.error('  $env:DSH_HOST_NODE_MODULES = "C:\\path\\to\\DSH Desktop\\resources\\app\\node_modules"')
  process.exit(1)
}

const target = join(packageRoot, 'node_modules', '@deepseek-ai')
mkdirSync(target, { recursive: true })

let linked = 0
for (const name of HOST_PACKAGES) {
  const source = join(scope, name)
  if (!existsSync(source)) {
    console.warn(`skip ${name}: not present in ${scope}`)
    continue
  }
  const destination = join(target, name)
  rmSync(destination, { recursive: true, force: true })
  symlinkSync(source, destination, process.platform === 'win32' ? 'junction' : 'dir')
  console.log(`linked ${name} -> ${source}`)
  linked += 1
}

console.log(`\n${linked} package(s) linked from ${scope}`)
console.log('Run `npm test` to verify the pure modules, then `npm run test:live` for a real scan.')
