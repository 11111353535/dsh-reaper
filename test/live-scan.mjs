/**
 * A live, read-only scan against the machine this is run on.
 *
 * `node --test` covers the parsers with recorded fixtures; this covers the part
 * fixtures cannot — that the real enumeration actually works on the host. It
 * never signals anything: the only thing it calls is `scanSystem` and the pure
 * classifier on top of it.
 *
 * Run it directly: `npm run test:live`.
 *
 * @module dsh-reaper/test/live-scan
 */

import { ancestorChain, scanSystem } from '../lib/scan.js'
import { classify } from '../lib/attribute.js'
import { renderScan } from '../lib/format.js'

const raw = await scanSystem({ includeUdp: false, timeoutMs: 30_000 })
const selfChain = new Set([process.pid, ...ancestorChain(raw.processes, process.pid)])

const graded = classify({
  listeners: raw.listeners,
  processes: raw.processes,
  hostPid: process.pid,
  selfChain,
  protectPorts: [],
  neverKill: [],
})

const counts = {}
for (const row of graded.endpoints) counts[row.verdict] = (counts[row.verdict] ?? 0) + 1

const report = renderScan({
  platform: raw.platform,
  scannedAt: new Date().toISOString(),
  workspaceRoot: process.cwd(),
  protectedPorts: [],
  endpoints: graded.endpoints,
  summary: {
    listeners: graded.endpoints.length,
    processes: raw.processes.length,
    reapable: graded.endpoints.filter((row) => row.verdict === 'agent-spawned' || row.verdict === 'workspace').length,
  },
  degraded: raw.degraded,
})

console.log(report)
console.log('')
console.log(`verdicts: ${JSON.stringify(counts)}`)
console.log(`degraded: ${raw.degraded.length === 0 ? 'none' : raw.degraded.join('; ')}`)

/* A live run is a smoke test, so it fails loudly when the enumeration produced
 * nothing at all — that is the one outcome that means the host path is broken
 * rather than merely quiet. */
if (raw.listeners.length === 0 && raw.degraded.length > 0) {
  console.error('\nlive scan produced no listeners and reported degradation')
  process.exitCode = 1
}
