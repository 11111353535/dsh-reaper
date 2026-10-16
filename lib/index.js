/**
 * dsh-reaper — orphan process and port reaper for DeepSeek Harness.
 *
 * ## The problem this solves
 *
 * An agent starts a dev server, a watcher, or a tunnel to check its work, and
 * then the turn ends. The process does not. Twenty minutes later the next
 * `npm run dev` dies with `EADDRINUSE`, and the thing holding the port is a
 * node process whose only distinguishing feature is a command line the agent
 * itself wrote three turns ago and has since forgotten.
 *
 * Existing port tooling answers "what holds port 3000". That is the easy half
 * and it is already well served. The hard half is *attribution*: of the
 * forty-odd listening sockets on a working machine, which ones belong to this
 * harness, and of those, which ones will not come back if they are killed.
 * This plugin grades every listener on that question and refuses to touch
 * anything it cannot attribute.
 *
 * ## Design commitments
 *
 * - **Preview is the default.** `reaper_reap` signals nothing unless the
 *   caller passes `confirm: true`. The preview path computes the identical
 *   plan, so what you approve is what runs.
 * - **Refusals are hard.** The harness's own ancestor chain, pid 0-4,
 *   `neverKill` patterns and `protectPorts` are refused, and re-checked
 *   immediately before each individual signal.
 * - **Trees, not pids.** Killing a `npm run dev` shim without its child leaves
 *   the port held, which is the exact failure this plugin exists to fix. Plans
 *   always include the descendant closure, signalled deepest-first.
 * - **Optional services are consumed defensively.** `workspaceRegistry` is
 *   read through `ctx.get` and the plugin works without it, because a plugin
 *   that refuses to load when one seam is absent is worse than a plugin that
 *   degrades.
 *
 * ## Tools
 *
 * - `reaper_scan` — graded inventory of listening endpoints and their holders.
 * - `reaper_reap` — plan, preview, and (on `confirm: true`) terminate trees.
 * - `reaper_free_port` — reclaim one specific port, refusing to guess.
 * - `/reap` — the same inventory as a slash command, for a human at the UI.
 *
 * @module dsh-reaper
 */

import { setTimeout as sleep } from 'node:timers/promises'

import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'

import { buildKillPlan, classify, isAutoSelectable, verdictRank } from './attribute.js'
import { renderPlan, renderScan } from './format.js'
import { terminate, waitForPortsReleased } from './kill.js'
import { probePorts } from './probe.js'
import { ancestorChain, scanSystem } from './scan.js'

export const name = 'dsh-reaper'

/** Services this plugin touches; every one is required for `apply` to run. */
export const inject = ['tools', 'commands']

/**
 * The pids that belong to the harness's own process tree: this process plus
 * everything it sits under.
 *
 * `ancestorChain` deliberately excludes its starting pid, so the caller joins
 * the two halves here. These pids are never reap candidates — killing one would
 * take down the harness that is running the scan.
 *
 * @param {Array<{ pid: number, ppid: number }>} processes - process table.
 * @returns {Set<number>} protected pids.
 */
function selfChainFor(processes) {
  const chain = new Set([process.pid])
  for (const pid of ancestorChain(processes, process.pid)) chain.add(pid)
  return chain
}

/**
 * Per-profile configuration. Every knob the plugin has lives here, so a
 * deployment can retune it from `cordis.patch.yml` without touching code.
 */
export const Config = Schema.object({
  /** Process-name or command-line substrings that must never be signalled. */
  neverKill: Schema.array(Schema.string()).default([]).description(
    'Process name or command-line substrings that dsh-reaper must never signal.',
  ),
  /** Ports whose holder is refused even when named explicitly. */
  protectPorts: Schema.array(Schema.number()).default([]).description(
    'Ports whose holders dsh-reaper must refuse to signal, even when named explicitly.',
  ),
  /** Whether the scan also enumerates UDP endpoints. */
  includeUdp: Schema.boolean().default(false).description(
    'Include UDP endpoints in the scan. Off by default: dev servers are TCP.',
  ),
  /** How long a graceful SIGTERM gets before a forced kill is offered. */
  graceMs: Schema.number().default(3000).description(
    'Milliseconds to wait for a process to exit after SIGTERM before reporting it as surviving.',
  ),
  /** Wall-clock ceiling for one system enumeration. */
  scanTimeoutMs: Schema.number().default(20_000).description(
    'Milliseconds allowed for one system enumeration before it is abandoned.',
  ),
})

/**
 * Pull the harness's own web port out of the environment so the plugin never
 * offers to reap the UI it is running inside.
 *
 * @param {string | undefined} webUrl - the `DSH_WEB_URL` value.
 * @returns {number[]} ports to protect by default.
 */
export function defaultProtectedPorts(webUrl) {
  if (typeof webUrl !== 'string' || webUrl === '') return []
  try {
    const parsed = new URL(webUrl)
    const port = Number(parsed.port)
    return Number.isInteger(port) && port > 0 ? [port] : []
  } catch {
    return []
  }
}

/**
 * Resolve the current workspace root, if the host composes a registry.
 *
 * Read through `ctx.get` rather than `inject` on purpose: a deployment without
 * `workspaceRegistry` still gets a working reaper, just with weaker
 * attribution.
 *
 * @param {any} ctx - the plugin context.
 * @param {any} exec - the tool execution record.
 * @returns {string | undefined} an absolute workspace path, when known.
 */
function workspaceRootFor(ctx, exec) {
  try {
    const registry = typeof ctx.get === 'function' ? ctx.get('workspaceRegistry') : undefined
    if (registry === undefined) return undefined
    const session = exec?.agent?.session
    if (session !== undefined && typeof registry.forSession === 'function') {
      const root = registry.forSession(session)
      if (typeof root === 'string' && root !== '') return root
    }
    if (typeof registry.current === 'function') {
      const root = registry.current()
      if (typeof root === 'string' && root !== '') return root
    }
    if (typeof registry.defaultRoot === 'function') {
      const root = registry.defaultRoot()
      if (typeof root === 'string' && root !== '') return root
    }
  } catch {
    /* Attribution is best-effort; a broken registry must not break the scan. */
  }
  return undefined
}

/**
 * Run one enumeration and grade every endpoint against the current session.
 *
 * @param {any} ctx - the plugin context.
 * @param {any} config - resolved plugin configuration.
 * @param {any} exec - the tool execution record.
 * @param {{ includeUdp?: boolean, workspace?: string }} [options]
 * @returns {Promise<any>} the graded scan.
 */
async function runScan(ctx, config, exec, options = {}) {
  const includeUdp = options.includeUdp ?? config.includeUdp
  const raw = await scanSystem({
    includeUdp,
    timeoutMs: config.scanTimeoutMs,
    signal: exec?.signal,
  })

  const selfChain = selfChainFor(raw.processes)
  const protectPorts = [
    ...new Set([...config.protectPorts, ...defaultProtectedPorts(process.env.DSH_WEB_URL)]),
  ]
  const workspaceRoot = options.workspace ?? workspaceRootFor(ctx, exec)

  const graded = classify({
    listeners: raw.listeners,
    processes: raw.processes,
    hostPid: process.pid,
    selfChain,
    workspaceRoot,
    protectPorts,
    neverKill: config.neverKill,
  })

  const endpoints = graded.endpoints
    .map((row) => ({ ...row, rank: verdictRank(row.verdict) }))
    .sort((a, b) => a.rank - b.rank || a.port - b.port)

  const counts = {}
  for (const row of endpoints) counts[row.verdict] = (counts[row.verdict] ?? 0) + 1

  return {
    platform: raw.platform,
    scannedAt: new Date().toISOString(),
    workspaceRoot,
    hostPid: process.pid,
    protectedPorts: protectPorts,
    endpoints,
    verdicts: counts,
    summary: {
      listeners: endpoints.length,
      processes: raw.processes.length,
      reapable: endpoints.filter((row) => isAutoSelectable(row.verdict)).length,
    },
    degraded: raw.degraded,
  }
}

/**
 * Select the root pids a reap call should act on.
 *
 * `all: true` selects only verdicts the classifier considers safe to select
 * automatically — never `system`, `unattributed` or `protected`. Explicit
 * `pids` bypass that filter but still pass through the hard refusal list when
 * the plan is built.
 *
 * @param {any} scan - a graded scan.
 * @param {{ pids?: number[], ports?: number[], all?: boolean }} args - tool arguments.
 * @returns {{ roots: number[], notes: string[] }} selected roots and notes.
 */
export function selectRoots(scan, args) {
  const notes = []
  const roots = new Set()

  for (const pid of args.pids ?? []) roots.add(pid)

  for (const port of args.ports ?? []) {
    const matches = scan.endpoints.filter((row) => row.port === port)
    if (matches.length === 0) {
      notes.push(`port ${port}: nothing is listening`)
      continue
    }
    for (const row of matches) {
      if (row.pid === null) {
        notes.push(`port ${port}: holder pid unknown, refusing`)
        continue
      }
      roots.add(row.pid)
    }
  }

  if (args.all === true) {
    const auto = scan.endpoints.filter((row) => isAutoSelectable(row.verdict))
    if (auto.length === 0) notes.push('no endpoint was confidently attributable to this session')
    for (const row of auto) {
      if (row.pid !== null) roots.add(row.pid)
    }
    for (const row of scan.endpoints) {
      if (isAutoSelectable(row.verdict) || row.pid === null) continue
      /* Infrastructure gets a note that does not invite an override. Saying
       * "name it explicitly to include it" next to nginx is how a machine's own
       * daemon gets killed by an agent that was only trying to be helpful. */
      if (row.verdict === 'protected' || row.verdict === 'system') {
        notes.push(`port ${row.port}: ${row.verdict} — left alone`)
        continue
      }
      notes.push(`port ${row.port}: ${row.verdict} — not auto-selected (name it explicitly to include it)`)
    }
  }

  return { roots: [...roots].sort((a, b) => a - b), notes }
}

/**
 * Build the plan and, when confirmed, execute it.
 *
 * @param {any} ctx - the plugin context.
 * @param {any} config - resolved plugin configuration.
 * @param {any} exec - the tool execution record.
 * @param {any} args - tool arguments.
 * @returns {Promise<any>} plan plus optional outcome.
 */
async function reap(ctx, config, exec, args) {
  const scan = await runScan(ctx, config, exec, {})
  const { roots, notes } = selectRoots(scan, args)

  if (roots.length === 0) {
    return {
      confirmed: args.confirm === true,
      force: args.force === true,
      targets: [],
      refused: [],
      freedPorts: [],
      untouched: [],
      notes,
      scan,
    }
  }

  const processes = await loadProcesses(exec, config)
  const selfChain = selfChainFor(processes)
  const plan = buildKillPlan({
    processes,
    listeners: scan.endpoints,
    roots,
    selfChain,
    protectPorts: scan.protectedPorts,
    neverKill: config.neverKill,
  })

  if (args.confirm !== true) {
    return { ...plan, confirmed: false, force: args.force === true, notes, scan }
  }

  const ports = plan.freedPorts.map((row) => row.port)
  const outcome = await terminate({
    targets: plan.targets,
    force: args.force === true,
    graceMs: config.graceMs,
    signal: exec?.signal,
  })

  const release = ports.length > 0 ? await waitForPortsReleased(ports, { signal: exec?.signal }) : { released: [], stillHeld: [] }

  return {
    ...plan,
    confirmed: true,
    force: args.force === true,
    outcome,
    portsReleased: release.released,
    portsStillHeld: release.stillHeld,
    notes,
    scan,
  }
}

/**
 * Re-read the process table for plan building.
 *
 * Deliberately a second read rather than a cached one: the table the scan saw
 * may already be stale, and a plan built on a stale parent/child map can miss
 * a descendant or, worse, target a recycled pid.
 *
 * @param {any} exec - the tool execution record.
 * @param {any} config - resolved plugin configuration.
 * @returns {Promise<any[]>} the process table.
 */
async function loadProcesses(exec, config) {
  const raw = await scanSystem({ includeUdp: false, timeoutMs: config.scanTimeoutMs, signal: exec?.signal })
  return raw.processes
}

/**
 * Register the tools and the slash command.
 *
 * @param {any} ctx - the plugin context.
 * @param {any} config - resolved plugin configuration.
 * @returns {void}
 */
export function apply(ctx, config) {
  ctx.tools.register(
    defineTool({
      name: 'reaper_scan',
      description:
        'Inventory every listening TCP endpoint on this machine and grade its holder as agent-spawned, workspace, dev-server, unattributed, system, or protected. Read-only: signals nothing. Use this before reaping, and to answer "what is holding that port".',
      parameters: {
        includeUdp: { type: 'boolean', description: 'Also enumerate UDP endpoints. Defaults to the plugin config.' },
        workspace: { type: 'string', description: 'Workspace root used to attribute processes by command line. Defaults to the current session workspace.' },
      },
      output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: renderScan(value) }] },
      timeoutMs: 60_000,
      async execute(args, exec) {
        return await runScan(ctx, config, exec, { includeUdp: args.includeUdp, workspace: args.workspace })
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'reaper_reap',
      description:
        'Reclaim processes left behind by this session. Computes the full descendant closure of each target (so a dev-server shim does not orphan its child) and, unless confirm is true, only PREVIEWS the plan. Nothing is signalled without confirm: true. Processes in the harness process tree, pid 0-4, neverKill matches and protectPorts holders are refused unconditionally.',
      parameters: {
        pids: { type: 'array', items: { type: 'integer' }, description: 'Explicit root pids to reap. Their descendants are included automatically.' },
        ports: { type: 'array', items: { type: 'integer' }, description: 'Reap whatever holds these ports.' },
        all: { type: 'boolean', description: 'Also select every endpoint confidently attributable to this session (agent-spawned and workspace verdicts only).' },
        force: { type: 'boolean', description: 'Escalate to SIGKILL for processes that ignore SIGTERM. Defaults to false.' },
        confirm: { type: 'boolean', description: 'Actually signal the planned processes. Defaults to false, which previews only.' },
      },
      output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: renderPlan(value) }] },
      timeoutMs: 120_000,
      async execute(args, exec) {
        return await reap(ctx, config, exec, args)
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'reaper_free_port',
      description:
        'Reclaim one specific port. Refuses when the holder cannot be attributed, when the port is protected, or when the holder is part of the harness itself — in those cases it reports why instead of guessing. Previews by default; pass confirm: true to signal.',
      parameters: {
        port: { type: 'integer', required: true, description: 'The TCP port to reclaim.' },
        force: { type: 'boolean', description: 'Escalate to SIGKILL if SIGTERM is ignored. Defaults to false.' },
        confirm: { type: 'boolean', description: 'Actually signal the holder. Defaults to false, which previews only.' },
      },
      output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: renderPlan(value) }] },
      timeoutMs: 120_000,
      async execute(args, exec) {
        const probe = await probePorts([args.port], { signal: exec?.signal })
        if (probe.free.includes(args.port)) {
          return {
            confirmed: false,
            force: false,
            targets: [],
            refused: [],
            freedPorts: [],
            untouched: [],
            notes: [`port ${args.port} is already free (connection refused)`],
          }
        }
        return await reap(ctx, config, exec, { ports: [args.port], force: args.force, confirm: args.confirm })
      },
    }),
  )

  ctx.commands.register({
    name: 'reap',
    description: 'Show the orphan-process inventory, or reap what this session left behind.',
    input: { hint: '[--all] [--confirm] [--force] [port ...]' },
    async handler(invocation) {
      const tokens = invocation.rawInput.trim().split(/\s+/u).filter((token) => token !== '')
      const ports = tokens.filter((token) => /^\d+$/u.test(token)).map(Number)
      const all = tokens.includes('--all')
      const exec = { agent: invocation.agent, signal: invocation.signal }

      try {
        /* Bare `/reap` is the inventory view. Anything else names work to do,
         * and the selection is what decides which of the two it is — running
         * the reaper first and scanning only when it came back empty would
         * enumerate the machine twice on the common path. */
        if (!all && ports.length === 0) {
          return { kind: 'success', text: renderScan(await runScan(ctx, config, exec, {})) }
        }
        const result = await reap(ctx, config, exec, {
          ports: ports.length > 0 ? ports : undefined,
          all,
          force: tokens.includes('--force'),
          confirm: tokens.includes('--confirm'),
        })
        return { kind: 'success', text: renderPlan(result) }
      } catch (error) {
        return { kind: 'error', text: `reaper failed: ${error instanceof Error ? error.message : String(error)}` }
      }
    },
  })
}

/* Re-exported for tests and for anyone composing this plugin's pieces. */
export { buildKillPlan, classify, renderPlan, renderScan, scanSystem, terminate, probePorts, sleep }
