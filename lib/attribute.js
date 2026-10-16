/**
 * Attribution: deciding which listening processes are *yours*, and what a
 * kill would actually take down.
 *
 * The interesting problem is not "what holds port 3000" — `netstat` answers
 * that. It is "which of these did this harness spawn, and which are the
 * machine's own daemons that will not come back if I kill them". Two signals
 * carry almost all of that weight:
 *
 *   1. **Ancestry.** A process that descends from the harness host is
 *      harness-spawned. A process that does not is not.
 *   2. **Workspace mention.** The command line names a path under the current
 *      workspace, which is what a `npm run dev` in this repo looks like.
 *
 * Everything else is a hint. The classifier never claims certainty it does
 * not have: verdicts are graded, and the graded verdict is what the caller
 * sees before anything is signalled.
 *
 * @module dsh-reaper/attribute
 */

/** Process names that are almost always the operating system's own. */
const SYSTEM_NAMES = new Set([
  'system',
  'system idle process',
  'registry',
  'memory compression',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'winlogon.exe',
  'services.exe',
  'lsass.exe',
  'svchost.exe',
  'fontdrvhost.exe',
  'dwm.exe',
  'explorer.exe',
  'sihost.exe',
  'taskhostw.exe',
  'shellexperiencehost.exe',
  'startmenuexperiencehost.exe',
  'searchhost.exe',
  'runtimebroker.exe',
  'spoolsv.exe',
  'audiodg.exe',
  'conhost.exe',
  'init',
  'systemd',
  'launchd',
  'kernel_task',
  'loginwindow',
  'windowserver',
])

/**
 * Substrings that mark a command line as a development server, watcher or
 * bundler — the processes an agent leaves behind most often.
 */
const DEV_SERVER_MARKERS = [
  'vite',
  'next dev',
  'next-server',
  'nuxt',
  'webpack',
  'webpack-dev-server',
  'rollup',
  'esbuild',
  'parcel',
  'nodemon',
  'ts-node-dev',
  'tsx watch',
  'concurrently',
  'http-server',
  'serve -s',
  'live-server',
  'json-server',
  'uvicorn',
  'gunicorn',
  'flask run',
  'manage.py runserver',
  'rails server',
  'php -s',
  'php artisan serve',
  'cargo watch',
  'air',
  'nodemon',
  'dev-server',
  'storybook',
  'jest --watch',
  'vitest',
  'cypress open',
  'playwright',
  'ng serve',
  'ngrok',
  'cloudflared tunnel',
  'localtunnel',
  'socat',
  'ng serve',
  'docker-proxy',
  'com.docker.backend',
  'wslrelay',
]

/** Port ranges commonly used by ephemeral dev servers. */
const DEV_PORT_RANGES = [
  [3000, 3999],
  [4000, 4999],
  [5000, 5999],
  [8000, 8999],
  [9000, 9999],
  [10000, 10999],
  [1234, 1234],
  [1420, 1420],
  [24678, 24678],
  [5173, 5174],
  [4200, 4200],
  [7860, 7860],
  [8888, 8888],
]

/** Ports whose holder is treated as infrastructure and never auto-selected. */
const WELL_KNOWN_PORTS = new Set([
  22, 53, 80, 123, 135, 137, 138, 139, 161, 389, 443, 445, 464, 500, 514,
  587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5672, 5900, 6379,
  8080, 8443, 9200, 11211, 27017,
])

/**
 * Build a pid → process-row index.
 *
 * @param {Array<{ pid: number }>} processes - process table.
 * @returns {Map<number, any>} index by pid.
 */
function indexByPid(processes) {
  return new Map(processes.map((row) => [row.pid, row]))
}

/**
 * Walk a process's ancestor chain, stopping at pid 0, a cycle, or a depth cap.
 *
 * @param {Map<number, any>} byPid - process index.
 * @param {number} pid - start pid.
 * @returns {number[]} ancestor pids, nearest first, excluding `pid` itself.
 */
export function ancestorsOf(byPid, pid) {
  const chain = []
  const seen = new Set([pid])
  let cursor = byPid.get(pid)?.ppid ?? 0
  for (let depth = 0; depth < 64 && cursor > 0; depth += 1) {
    if (seen.has(cursor)) break
    seen.add(cursor)
    chain.push(cursor)
    cursor = byPid.get(cursor)?.ppid ?? 0
  }
  return chain
}

/**
 * Collect a pid and every live descendant, breadth-first.
 *
 * @param {Map<number, any>} byPid - process index.
 * @param {number[]} roots - starting pids.
 * @returns {number[]} the closure, roots first.
 */
export function descendantClosure(byPid, roots) {
  const childrenOf = new Map()
  for (const row of byPid.values()) {
    const siblings = childrenOf.get(row.ppid)
    if (siblings === undefined) childrenOf.set(row.ppid, [row.pid])
    else siblings.push(row.pid)
  }

  const ordered = []
  const seen = new Set()
  const queue = [...roots]
  while (queue.length > 0) {
    const pid = queue.shift()
    if (pid === undefined || seen.has(pid)) continue
    seen.add(pid)
    ordered.push(pid)
    for (const child of childrenOf.get(pid) ?? []) {
      if (!seen.has(child)) queue.push(child)
    }
  }
  return ordered
}

/**
 * Whether a port falls inside a development-server range.
 *
 * A well-known service port is never a dev port, even when it sits inside a
 * dev range: `postgres` on 5432 lives in the 5000-5999 block, and grading it
 * "dev" would invite exactly the kill this plugin refuses to make.
 *
 * @param {number} port - port number.
 * @returns {boolean} true when it looks like a dev port.
 */
export function isDevPort(port) {
  if (WELL_KNOWN_PORTS.has(port)) return false
  return DEV_PORT_RANGES.some(([low, high]) => port >= low && port <= high)
}

/**
 * Whether a command line names a development server, watcher or tunnel.
 *
 * @param {string} commandLine - full command line.
 * @returns {string | undefined} the marker that matched.
 */
export function devServerMarker(commandLine) {
  const lowered = commandLine.toLowerCase()
  return DEV_SERVER_MARKERS.find((marker) => lowered.includes(marker))
}

/**
 * Whether a path-ish needle appears in a command line, comparing with both
 * slash directions normalized so a Windows path matches either way.
 *
 * @param {string} commandLine - full command line.
 * @param {string} needle - path or fragment to look for.
 * @returns {boolean} true on a normalized substring match.
 */
export function mentionsPath(commandLine, needle) {
  if (needle === undefined || needle === '') return false
  const normalize = (value) => value.replaceAll('\\', '/').replace(/^[a-z]:\//iu, '/').toLowerCase()
  return normalize(commandLine).includes(normalize(needle))
}

/**
 * Classify every listening endpoint and grade each holder.
 *
 * Verdicts, strongest first:
 * - `protected` — matched a `neverKill` pattern or a protected port; never
 *   auto-selected, and refused even when named explicitly.
 * - `system` — an operating-system process or a well-known service port.
 * - `agent-spawned` — descends from the harness host process.
 * - `workspace` — the command line names the current workspace.
 * - `dev-server` — looks like a dev server, watcher or tunnel.
 * - `unattributed` — listening, but nothing ties it to this session.
 *
 * @param {{
 *   listeners: Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>,
 *   processes: Array<{ pid: number, ppid: number, name: string, commandLine: string, ageSeconds: number | null }>,
 *   hostPid: number,
 *   selfChain: Set<number>,
 *   workspaceRoot?: string,
 *   protectPorts?: number[],
 *   neverKill?: string[],
 * }} input
 * @returns {{
 *   endpoints: Array<any>,
 *   processes: Array<any>,
 *   protectedPids: Set<number>,
 * }}
 */
export function classify(input) {
  const byPid = indexByPid(input.processes)
  const protectPorts = new Set(input.protectPorts ?? [])
  const neverKill = (input.neverKill ?? []).map((value) => value.toLowerCase()).filter((value) => value !== '')

  /* Which pids descend from the harness host? Computed once, not per endpoint. */
  const hostDescendants = new Set()
  for (const row of input.processes) {
    if (row.pid === input.hostPid) continue
    const chain = ancestorsOf(byPid, row.pid)
    if (chain.includes(input.hostPid)) hostDescendants.add(row.pid)
  }

  const endpoints = []
  for (const listener of input.listeners) {
    const row = listener.pid === null ? undefined : byPid.get(listener.pid)
    const grade = verdictFor({ listener, row, ...input, hostDescendants, protectPorts, neverKill })
    endpoints.push({
      ...listener,
      process:
        row === undefined
          ? null
          : {
              pid: row.pid,
              ppid: row.ppid,
              name: row.name,
              commandLine: row.commandLine,
              ageSeconds: row.ageSeconds,
            },
      verdict: grade.verdict,
      reasons: grade.reasons,
      ...(grade.marker === undefined ? {} : { marker: grade.marker }),
    })
  }

  const protectedPids = new Set()
  for (const row of input.processes) {
    const verdict = verdictForProcess({ row, ...input, hostDescendants, protectPorts, neverKill })
    if (verdict.verdict === 'protected') protectedPids.add(row.pid)
  }

  return { endpoints, processes: input.processes, protectedPids }
}

/**
 * Grade one listening endpoint's holder.
 *
 * @param {any} context - classification inputs plus the listener and its row.
 * @returns {{ verdict: string, reasons: string[], marker?: string }} the grade.
 */
function verdictFor(context) {
  const { listener, row, selfChain, protectPorts, neverKill, hostDescendants } = context

  if (listener.pid !== null && selfChain.has(listener.pid)) {
    return { verdict: 'protected', reasons: ['holds the harness process tree'] }
  }
  if (protectPorts.has(listener.port)) {
    return { verdict: 'protected', reasons: [`port ${listener.port} is in protectPorts`] }
  }
  if (row === undefined) {
    return { verdict: 'unattributed', reasons: ['no process details available for this pid'] }
  }
  return verdictForProcess(context, listener)
}

/**
 * Grade one process row.
 *
 * @param {any} context - classification inputs plus the row.
 * @param {{ port?: number } | undefined} [listener] - the endpoint it holds, if any.
 * @returns {{ verdict: string, reasons: string[], marker?: string }} the grade.
 */
function verdictForProcess(context, listener) {
  const { row, selfChain, protectPorts, neverKill, hostDescendants, workspaceRoot } = context
  const reasons = []
  const port = listener?.port

  if (selfChain.has(row.pid)) return { verdict: 'protected', reasons: ['part of the harness process tree'] }

  const loweredName = row.name.toLowerCase()
  const loweredLine = row.commandLine.toLowerCase()
  for (const pattern of neverKill) {
    if (loweredName.includes(pattern) || loweredLine.includes(pattern)) {
      return { verdict: 'protected', reasons: [`matches neverKill pattern "${pattern}"`] }
    }
  }

  if (port !== undefined && protectPorts.has(port)) {
    return { verdict: 'protected', reasons: [`port ${port} is in protectPorts`] }
  }

  if (row.pid <= 4 || SYSTEM_NAMES.has(loweredName)) {
    return { verdict: 'system', reasons: [`"${row.name}" is an operating-system process`] }
  }
  if (port !== undefined && WELL_KNOWN_PORTS.has(port)) {
    reasons.push(`port ${port} is a well-known service port`)
  }

  if (hostDescendants.has(row.pid)) reasons.push('descends from the harness process')
  if (workspaceRoot !== undefined && mentionsPath(row.commandLine, workspaceRoot)) {
    reasons.push('command line names this workspace')
  }
  const marker = devServerMarker(row.commandLine)
  if (marker !== undefined) reasons.push(`looks like a dev server ("${marker}")`)
  if (port !== undefined && isDevPort(port)) reasons.push(`port ${port} is in a dev range`)

  if (hostDescendants.has(row.pid)) return { verdict: 'agent-spawned', reasons, marker }
  if (workspaceRoot !== undefined && mentionsPath(row.commandLine, workspaceRoot)) {
    return { verdict: 'workspace', reasons, marker }
  }
  if (marker !== undefined) return { verdict: 'dev-server', reasons, marker }

  /* Nothing ties it to this session. A holder of a well-known service port is
   * the machine's own infrastructure — same "hands off" grade as an OS process,
   * and the reasons say which port made it so. */
  if (port !== undefined && WELL_KNOWN_PORTS.has(port)) return { verdict: 'system', reasons }

  return { verdict: 'unattributed', reasons: reasons.length > 0 ? reasons : ['nothing ties this process to the session'] }
}

/**
 * Rank verdicts so callers can sort offenders most-reapable first.
 *
 * @param {string} verdict - a verdict name.
 * @returns {number} higher means more clearly the caller's own to reclaim.
 */
export function verdictRank(verdict) {
  switch (verdict) {
    case 'agent-spawned':
      return 0
    case 'workspace':
      return 1
    case 'dev-server':
      return 2
    case 'unattributed':
      return 3
    case 'system':
      return 4
    case 'protected':
      return 5
    default:
      return 6
  }
}

/**
 * Whether a verdict may be auto-selected by a "reap everything obvious" call.
 *
 * @param {string} verdict - a verdict name.
 * @returns {boolean} true when the verdict is safe to select automatically.
 */
export function isAutoSelectable(verdict) {
  return verdict === 'agent-spawned' || verdict === 'workspace'
}

/**
 * Build the exact kill plan for a set of roots, without signalling anything.
 *
 * The plan includes every descendant of every root — killing a `npm run dev`
 * shim without its child leaves the port held, which is the whole failure mode
 * this plugin exists to avoid.
 *
 * @param {{
 *   processes: Array<{ pid: number, ppid: number, name: string, commandLine: string }>,
 *   listeners: Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>,
 *   roots: number[],
 *   selfChain: Set<number>,
 *   protectPorts?: number[],
 *   neverKill?: string[],
 * }} input
 * @returns {{
 *   targets: Array<{ pid: number, ppid: number, name: string, commandLine: string, root: number, depth: number }>,
 *   refused: Array<{ pid: number, reason: string }>,
 *   freedPorts: Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>,
 *   untouched: number[],
 * }} the plan.
 */
export function buildKillPlan(input) {
  const byPid = indexByPid(input.processes)
  const protectPorts = new Set(input.protectPorts ?? [])
  const neverKill = (input.neverKill ?? []).map((value) => value.toLowerCase()).filter((value) => value !== '')

  const refused = []
  const accepted = []
  for (const pid of input.roots) {
    const row = byPid.get(pid)
    if (row === undefined) {
      refused.push({ pid, reason: 'no such process' })
      continue
    }
    if (input.selfChain.has(pid)) {
      refused.push({ pid, reason: 'part of the harness process tree' })
      continue
    }
    if (row.pid <= 4) {
      refused.push({ pid, reason: 'operating-system process' })
      continue
    }
    const loweredName = row.name.toLowerCase()
    const loweredLine = row.commandLine.toLowerCase()
    const hit = neverKill.find((pattern) => loweredName.includes(pattern) || loweredLine.includes(pattern))
    if (hit !== undefined) {
      refused.push({ pid, reason: `matches neverKill pattern "${hit}"` })
      continue
    }
    const held = input.listeners.filter((listener) => listener.pid === pid)
    const protectedPort = held.find((listener) => protectPorts.has(listener.port))
    if (protectedPort !== undefined) {
      refused.push({ pid, reason: `holds protected port ${protectedPort.port}` })
      continue
    }
    accepted.push(pid)
  }

  const closure = descendantClosure(byPid, accepted)
  const rootOf = new Map()
  const depthOf = new Map()
  for (const root of accepted) {
    const members = descendantClosure(byPid, [root])
    members.forEach((pid, index) => {
      if (rootOf.has(pid)) return
      rootOf.set(pid, root)
      depthOf.set(pid, index)
    })
  }

  const targets = []
  const untouched = []
  for (const pid of closure) {
    const row = byPid.get(pid)
    if (row === undefined) continue
    if (input.selfChain.has(pid) || row.pid <= 4) {
      untouched.push(pid)
      continue
    }
    const loweredName = row.name.toLowerCase()
    const loweredLine = row.commandLine.toLowerCase()
    if (neverKill.some((pattern) => loweredName.includes(pattern) || loweredLine.includes(pattern))) {
      untouched.push(pid)
      continue
    }
    targets.push({
      pid: row.pid,
      ppid: row.ppid,
      name: row.name,
      commandLine: row.commandLine,
      root: rootOf.get(pid) ?? row.pid,
      depth: depthOf.get(pid) ?? 0,
    })
  }

  const targetPids = new Set(targets.map((target) => target.pid))
  const freedPorts = input.listeners.filter(
    (listener) => listener.pid !== null && targetPids.has(listener.pid),
  )

  return { targets, refused, freedPorts, untouched }
}
