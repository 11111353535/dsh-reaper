/**
 * Cross-platform enumeration of listening sockets and the processes behind
 * them. Everything here is read-only: no signals are sent from this module.
 *
 * The Windows path deliberately avoids FFI (`koffi`) and the deprecated
 * `wmic`; it shells out to PowerShell once per scan and parses CIM objects,
 * with a `netstat` + `tasklist` fallback for locked-down hosts where CIM is
 * unavailable. POSIX hosts use `ss` (Linux) or `lsof` (macOS).
 *
 * @module dsh-reaper/scan
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)

/** Hard cap so a runaway `netstat`/`ps` cannot blow up the tool result. */
const MAX_BUFFER = 8 * 1024 * 1024

/** Default per-command timeout, in milliseconds. */
const DEFAULT_TIMEOUT_MS = 20_000

/**
 * Run a command and return stdout, or `undefined` when the binary is missing
 * or the command fails. Enumeration is best-effort: one broken probe must not
 * take down the whole scan.
 *
 * @param {string} file - executable to run.
 * @param {string[]} args - argument vector.
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<string | undefined>} stdout, trimmed of a trailing newline.
 */
async function tryRun(file, args, options = {}) {
  try {
    const { stdout } = await run(file, args, {
      timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      windowsHide: true,
      signal: options.signal,
      encoding: 'utf8',
    })
    return stdout
  } catch {
    return undefined
  }
}

/**
 * Parse `netstat -ano` output into listening endpoints.
 *
 * Handles both the Windows table (`TCP  127.0.0.1:3000  0.0.0.0:0  LISTENING  4242`)
 * and the BSD/macOS table (`tcp4  0  0  127.0.0.1.3000  *.*  LISTEN`).
 *
 * @param {string} text - raw netstat output.
 * @param {{ includeUdp?: boolean }} [options]
 * @returns {Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>}
 */
export function parseNetstat(text, options = {}) {
  const includeUdp = options.includeUdp === true
  const found = []
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '') continue
    const parts = line.split(/\s+/u)
    if (parts.length < 4) continue

    const protocol = parts[0].toLowerCase()
    const isTcp = protocol.startsWith('tcp')
    const isUdp = protocol.startsWith('udp')
    if (!isTcp && !isUdp) continue
    if (isUdp && !includeUdp) continue

    /* Windows TCP table: proto, local, foreign, state, pid. */
    if (isTcp && parts.length >= 5 && /^\d+$/u.test(parts[4])) {
      if (parts[3].toUpperCase() !== 'LISTENING') continue
      const endpoint = splitEndpoint(parts[1])
      if (endpoint === undefined) continue
      found.push({
        protocol: 'tcp',
        localAddress: endpoint.address,
        port: endpoint.port,
        pid: Number(parts[4]),
      })
      continue
    }

    /* Windows UDP table has no state column: proto, local, foreign, pid. */
    if (isUdp && parts.length >= 4 && /^\d+$/u.test(parts[parts.length - 1])) {
      const endpoint = splitEndpoint(parts[1])
      if (endpoint === undefined) continue
      found.push({
        protocol: 'udp',
        localAddress: endpoint.address,
        port: endpoint.port,
        pid: Number(parts[parts.length - 1]),
      })
      continue
    }

    /* BSD/macOS table: proto, recvq, sendq, local, foreign, (state). */
    const state = parts[5] ?? ''
    if (isTcp && !/^LISTEN/iu.test(state)) continue
    const endpoint = splitEndpoint(parts[3])
    if (endpoint === undefined) continue
    found.push({
      protocol: isTcp ? 'tcp' : 'udp',
      localAddress: endpoint.address,
      port: endpoint.port,
      pid: null,
    })
  }
  return found
}

/**
 * Split `127.0.0.1:3000`, `[::1]:3000`, `127.0.0.1.3000` or `*:3000` into
 * address and port. Returns `undefined` when no numeric port is present.
 *
 * @param {string} value - endpoint token.
 * @returns {{ address: string, port: number } | undefined}
 */
export function splitEndpoint(value) {
  const token = value.trim()
  if (token === '') return undefined

  const bracketed = /^\[(?<address>[^\]]*)\]:(?<port>\d+)$/u.exec(token)
  if (bracketed?.groups !== undefined) {
    return { address: bracketed.groups.address, port: Number(bracketed.groups.port) }
  }

  const colon = /^(?<address>.*):(?<port>\d+)$/u.exec(token)
  if (colon?.groups !== undefined) {
    return { address: colon.groups.address, port: Number(colon.groups.port) }
  }

  const dotted = /^(?<address>.*)\.(?<port>\d+)$/u.exec(token)
  if (dotted?.groups !== undefined) {
    return { address: dotted.groups.address, port: Number(dotted.groups.port) }
  }

  return undefined
}

/**
 * Parse `ss -H -ltnp` / `ss -H -lunp` output.
 *
 * Example line:
 * `LISTEN 0  511  127.0.0.1:3000  0.0.0.0:*  users:(("node",pid=4242,fd=21))`
 *
 * @param {string} text - raw `ss` output.
 * @param {string} protocol - `tcp` or `udp`.
 * @returns {Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>}
 */
export function parseSs(text, protocol) {
  const found = []
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '') continue
    const parts = line.split(/\s+/u)
    /* Columns are: state, recv-q, send-q, local, peer, process. The peer column
     * is often `*:*`, which does not parse, so try the local column first. */
    let endpoint
    for (const candidate of [parts[3], parts[4]]) {
      if (candidate === undefined) continue
      const parsed = splitEndpoint(candidate)
      if (parsed !== undefined) {
        endpoint = parsed
        break
      }
    }
    if (endpoint === undefined) continue
    const pidMatch = /pid=(?<pid>\d+)/u.exec(line)
    found.push({
      protocol,
      localAddress: endpoint.address,
      port: endpoint.port,
      pid: pidMatch?.groups === undefined ? null : Number(pidMatch.groups.pid),
    })
  }
  return found
}

/**
 * Parse `lsof -nP -iTCP -sTCP:LISTEN -Fpcn` field output.
 *
 * @param {string} text - raw lsof output.
 * @param {string} protocol - `tcp` or `udp`.
 * @returns {Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>}
 */
export function parseLsof(text, protocol) {
  const found = []
  let pid = null
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '') continue
    if (line.startsWith('p')) {
      pid = Number(line.slice(1))
      continue
    }
    if (!line.startsWith('n')) continue
    const endpoint = splitEndpoint(line.slice(1).replace(/^\[/u, '['))
    if (endpoint === undefined) continue
    found.push({
      protocol,
      localAddress: endpoint.address,
      port: endpoint.port,
      pid: Number.isFinite(pid) ? pid : null,
    })
  }
  return found
}

/**
 * Parse `ps -eo pid=,ppid=,comm=,etimes=,args=` output.
 *
 * @param {string} text - raw ps output.
 * @returns {Array<{ pid: number, ppid: number, name: string, ageSeconds: number, commandLine: string }>}
 */
export function parsePs(text) {
  const rows = []
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '') continue
    const match = /^(?<pid>\d+)\s+(?<ppid>\d+)\s+(?<name>\S+)\s+(?<age>\d+)\s*(?<args>.*)$/u.exec(line)
    if (match?.groups === undefined) continue
    rows.push({
      pid: Number(match.groups.pid),
      ppid: Number(match.groups.ppid),
      name: match.groups.name,
      ageSeconds: Number(match.groups.age),
      commandLine: match.groups.args.trim(),
    })
  }
  return rows
}

/**
 * Parse `tasklist /FO CSV /NH` output.
 *
 * @param {string} text - raw tasklist output.
 * @returns {Map<number, string>} pid to image name.
 */
export function parseTasklist(text) {
  const table = new Map()
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('INFO:')) continue
    const match = /^"(?<name>(?:[^"]|"")*)"\s*,\s*"(?<pid>\d+)"/u.exec(line)
    if (match?.groups === undefined) continue
    table.set(Number(match.groups.pid), match.groups.name.replaceAll('""', '"'))
  }
  return table
}

/**
 * PowerShell script that emits one JSON document with processes and endpoints.
 * Written as a single here-string so the whole scan costs one process spawn.
 *
 * @param {boolean} includeUdp - whether to include UDP endpoints.
 * @returns {string} the script.
 */
function windowsScanScript(includeUdp) {
  const udpBlock = includeUdp
    ? `
  $udp = @()
  try {
    $udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ protocol = 'udp'; localAddress = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess }
    }
  } catch {}
`
    : '  $udp = @()\n'

  return `
$ErrorActionPreference = 'SilentlyContinue'
$listeners = @()
try {
  $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ protocol = 'tcp'; localAddress = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess }
  }
} catch { $listeners = @() }
${udpBlock}
$procs = @()
try {
  $procs = Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
    $started = $null
    if ($_.CreationDate) { try { $started = $_.CreationDate.ToUniversalTime().ToString('o') } catch {} }
    [pscustomobject]@{
      pid = [int]$_.ProcessId
      ppid = [int]$_.ParentProcessId
      name = [string]$_.Name
      commandLine = [string]$_.CommandLine
      startedAt = $started
      rssBytes = [int64]$_.WorkingSetSize
    }
  }
} catch { $procs = @() }
[pscustomobject]@{ listeners = @($listeners) + @($udp); processes = @($procs) } | ConvertTo-Json -Depth 5 -Compress
`
}

/**
 * Shell candidates for the Windows scan, most preferred first.
 *
 * @returns {string[]} executable names.
 */
function windowsShells() {
  return ['powershell.exe', 'pwsh.exe', 'powershell', 'pwsh']
}

/**
 * Enumerate processes and listening endpoints for the current platform.
 *
 * @param {{ includeUdp?: boolean, timeoutMs?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{
 *   platform: string,
 *   listeners: Array<{ protocol: string, localAddress: string, port: number, pid: number | null }>,
 *   processes: Array<{ pid: number, ppid: number, name: string, commandLine: string, startedAt: string | null, ageSeconds: number | null, rssBytes: number | null }>,
 *   degraded: string[],
 * }>}
 */
export async function scanSystem(options = {}) {
  const includeUdp = options.includeUdp === true
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const signal = options.signal
  const degraded = []

  if (process.platform === 'win32') {
    const result = await scanWindows({ includeUdp, timeoutMs, signal, degraded })
    return { platform: 'win32', ...dedupeListeners(result), degraded }
  }
  if (process.platform === 'darwin') {
    const result = await scanDarwin({ includeUdp, timeoutMs, signal, degraded })
    return { platform: 'darwin', ...dedupeListeners(result), degraded }
  }
  const result = await scanLinux({ includeUdp, timeoutMs, signal, degraded })
  return { platform: 'linux', ...dedupeListeners(result), degraded }
}

/**
 * Collapse one process's dual-stack bindings into a single endpoint row.
 *
 * A server that listens on both `::` and `0.0.0.0` reports two rows for one
 * port, and a report listing "49747" twice reads like two problems. They are
 * one problem held by one pid, so the second row is dropped and the surviving
 * row records every address the port is bound to.
 *
 * @param {{ listeners: any[], processes: any[] }} result - a platform scan.
 * @returns {{ listeners: any[], processes: any[] }} the same scan, deduplicated.
 */
export function dedupeListeners(result) {
  const byKey = new Map()
  for (const row of result.listeners) {
    const key = `${row.protocol}|${row.port}|${row.pid === null ? '?' : row.pid}`
    const existing = byKey.get(key)
    if (existing === undefined) {
      byKey.set(key, { ...row, addresses: [row.localAddress] })
      continue
    }
    if (!existing.addresses.includes(row.localAddress)) existing.addresses.push(row.localAddress)
  }
  return { listeners: [...byKey.values()], processes: result.processes }
}

/**
 * Windows scan: CIM first, `netstat` + `tasklist` as a fallback.
 *
 * @param {{ includeUdp: boolean, timeoutMs: number, signal?: AbortSignal, degraded: string[] }} options
 * @returns {Promise<{ listeners: unknown[], processes: unknown[] }>}
 */
async function scanWindows({ includeUdp, timeoutMs, signal, degraded }) {
  for (const shell of windowsShells()) {
    const stdout = await tryRun(
      shell,
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', windowsScanScript(includeUdp)],
      { timeoutMs, signal },
    )
    if (stdout === undefined) continue
    const start = stdout.indexOf('{')
    if (start < 0) continue
    try {
      const parsed = JSON.parse(stdout.slice(start))
      const listeners = asArray(parsed.listeners).map(normalizeListener).filter(isListener)
      const processes = asArray(parsed.processes).map(normalizeProcess).filter(isProcess)
      if (listeners.length > 0 || processes.length > 0) return { listeners, processes }
    } catch {
      degraded.push(`${shell}: CIM scan produced unparsable JSON`)
    }
  }

  degraded.push('CIM scan unavailable; fell back to netstat + tasklist')
  const [netstatOut, tasklistOut] = await Promise.all([
    tryRun('netstat', ['-ano'], { timeoutMs, signal }),
    tryRun('tasklist', ['/FO', 'CSV', '/NH'], { timeoutMs, signal }),
  ])
  const listeners = netstatOut === undefined ? [] : parseNetstat(netstatOut, { includeUdp })
  const names = tasklistOut === undefined ? new Map() : parseTasklist(tasklistOut)
  const processes = [...names].map(([pid, name]) => ({
    pid,
    ppid: 0,
    name,
    commandLine: '',
    startedAt: null,
    ageSeconds: null,
    rssBytes: null,
  }))
  return { listeners, processes }
}

/**
 * Linux scan via `ss` and `ps`.
 *
 * @param {{ includeUdp: boolean, timeoutMs: number, signal?: AbortSignal, degraded: string[] }} options
 * @returns {Promise<{ listeners: unknown[], processes: unknown[] }>}
 */
async function scanLinux({ includeUdp, timeoutMs, signal, degraded }) {
  const ssArgs = includeUdp ? ['-H', '-ltnup'] : ['-H', '-ltnp']
  const [ssOut, psOut] = await Promise.all([
    tryRun('ss', ssArgs, { timeoutMs, signal }),
    tryRun('ps', ['-eo', 'pid=,ppid=,comm=,etimes=,args='], { timeoutMs, signal }),
  ])
  if (ssOut === undefined) degraded.push('ss unavailable; listening sockets could not be enumerated')
  const listeners = ssOut === undefined ? [] : parseSs(ssOut, includeUdp ? 'tcp/udp' : 'tcp')
  if (psOut === undefined) degraded.push('ps unavailable; process details are missing')
  const processes = (psOut === undefined ? [] : parsePs(psOut)).map((row) => ({
    ...row,
    startedAt: null,
    rssBytes: null,
  }))
  return { listeners, processes }
}

/**
 * macOS scan via `lsof` and `ps`.
 *
 * @param {{ includeUdp: boolean, timeoutMs: number, signal?: AbortSignal, degraded: string[] }} options
 * @returns {Promise<{ listeners: unknown[], processes: unknown[] }>}
 */
async function scanDarwin({ includeUdp, timeoutMs, signal, degraded }) {
  const [tcpOut, udpOut, psOut] = await Promise.all([
    tryRun('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-Fpcn'], { timeoutMs, signal }),
    includeUdp ? tryRun('lsof', ['-nP', '-iUDP', '-Fpcn'], { timeoutMs, signal }) : Promise.resolve(undefined),
    tryRun('ps', ['-eo', 'pid=,ppid=,comm=,etimes=,args='], { timeoutMs, signal }),
  ])
  if (tcpOut === undefined) degraded.push('lsof unavailable; listening sockets could not be enumerated')
  const listeners = [
    ...(tcpOut === undefined ? [] : parseLsof(tcpOut, 'tcp')),
    ...(udpOut === undefined ? [] : parseLsof(udpOut, 'udp')),
  ]
  const processes = (psOut === undefined ? [] : parsePs(psOut)).map((row) => ({
    ...row,
    startedAt: null,
    rssBytes: null,
  }))
  return { listeners, processes }
}

/**
 * Coerce a JSON value that may be absent, scalar, or array into an array.
 *
 * @param {unknown} value - candidate.
 * @returns {any[]} the array form.
 */
function asArray(value) {
  if (value === undefined || value === null) return []
  return Array.isArray(value) ? value : [value]
}

/**
 * Normalize one listener row coming out of a shell probe.
 *
 * @param {any} row - raw row.
 * @returns {{ protocol: string, localAddress: string, port: number, pid: number | null }} normalized row.
 */
function normalizeListener(row) {
  return {
    protocol: String(row?.protocol ?? 'tcp'),
    localAddress: String(row?.localAddress ?? ''),
    port: Number(row?.port ?? 0),
    pid: Number.isFinite(Number(row?.pid)) ? Number(row.pid) : null,
  }
}

/**
 * Whether a normalized listener row is usable.
 *
 * @param {{ port: number }} row - normalized row.
 * @returns {boolean} true when a real port was parsed.
 */
function isListener(row) {
  return Number.isInteger(row.port) && row.port > 0
}

/**
 * Normalize one process row coming out of a shell probe.
 *
 * @param {any} row - raw row.
 * @returns {any} normalized row.
 */
function normalizeProcess(row) {
  const startedAt = typeof row?.startedAt === 'string' && row.startedAt !== '' ? row.startedAt : null
  const parsedStart = startedAt === null ? Number.NaN : Date.parse(startedAt)
  return {
    pid: Number(row?.pid ?? 0),
    ppid: Number(row?.ppid ?? 0),
    name: String(row?.name ?? ''),
    commandLine: String(row?.commandLine ?? ''),
    startedAt,
    ageSeconds: Number.isFinite(row?.ageSeconds)
      ? Number(row.ageSeconds)
      : Number.isFinite(parsedStart)
        ? Math.max(0, Math.round((Date.now() - parsedStart) / 1000))
        : null,
    rssBytes: Number.isFinite(Number(row?.rssBytes)) ? Number(row.rssBytes) : null,
  }
}

/**
 * Whether a normalized process row is usable.
 *
 * @param {{ pid: number }} row - normalized row.
 * @returns {boolean} true when a positive pid was parsed.
 */
function isProcess(row) {
  return Number.isInteger(row.pid) && row.pid > 0
}

/**
 * The pids above `startPid`, nearest first, stopping at pid 0 or a cycle.
 *
 * The starting pid is deliberately *not* included: callers that need "this
 * process and everything it sits under" add the start pid themselves. Keeping
 * the walk pure makes the cycle case obvious — `10 -> 11 -> 10` yields `[11]`
 * and terminates rather than spinning.
 *
 * @param {Array<{ pid: number, ppid: number }>} processes - process table.
 * @param {number} [startPid] - pid to walk up from; defaults to the current process.
 * @returns {number[]} ancestor pids, nearest first.
 */
export function ancestorChain(processes, startPid = process.pid) {
  const byPid = new Map(processes.map((row) => [row.pid, row]))
  const seen = new Set([startPid])
  const chain = []
  let cursor = byPid.get(startPid)?.ppid ?? 0
  for (let guard = 0; guard < 64 && cursor > 0 && !seen.has(cursor); guard += 1) {
    seen.add(cursor)
    chain.push(cursor)
    cursor = byPid.get(cursor)?.ppid ?? 0
  }
  return chain
}
