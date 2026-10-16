/**
 * Signalling, and the two safety properties that make it acceptable to expose
 * a kill switch to an agent at all:
 *
 *   1. **Preview is the default.** Nothing is signalled unless the caller
 *      passes `confirm: true` explicitly. A preview call returns the same
 *      structure a real call would, with `confirmed: false`.
 *   2. **Refusals are not negotiable.** The protected set — the harness's own
 *      ancestor chain, pid 0-4, `neverKill` patterns, `protectPorts` — is
 *      re-checked here, immediately before each signal, not only when the plan
 *      was built. A plan is a snapshot; a process tree is not.
 *
 * Termination is graceful-then-forced per target: signal, poll, escalate.
 * Descendants are signalled deepest-first so a supervisor cannot re-spawn a
 * child out from under the reap.
 *
 * @module dsh-reaper/kill
 */

/**
 * Signal a single pid, swallowing the errors that mean "already gone".
 *
 * @param {number} pid - target pid.
 * @param {NodeJS.Signals} signal - signal to send.
 * @returns {{ ok: boolean, reason?: string }} outcome.
 */
function signalPid(pid, signal) {
  try {
    process.kill(pid, signal)
    return { ok: true }
  } catch (error) {
    const code = /** @type {NodeJS.ErrnoException} */ (error).code
    if (code === 'ESRCH') return { ok: false, reason: 'already exited' }
    if (code === 'EPERM') return { ok: false, reason: 'permission denied' }
    return { ok: false, reason: code ?? String(error) }
  }
}

/**
 * Whether a pid is still alive.
 *
 * @param {number} pid - candidate pid.
 * @returns {boolean} true when the process still exists.
 */
export function isAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return /** @type {NodeJS.ErrnoException} */ (error).code === 'EPERM'
  }
}

/**
 * Sleep, honouring an abort signal.
 *
 * @param {number} ms - milliseconds to wait.
 * @param {AbortSignal} [signal] - cancellation signal.
 * @returns {Promise<void>} resolves after the wait or on abort.
 */
function delay(ms, signal) {
  if (signal?.aborted === true) return Promise.resolve()
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms)
    function done() {
      clearTimeout(timer)
      signal?.removeEventListener('abort', done)
      resolve()
    }
    signal?.addEventListener('abort', done, { once: true })
  })
}

/**
 * Terminate one process tree, deepest first.
 *
 * @param {{
 *   targets: Array<{ pid: number, name: string, depth: number }>,
 *   force?: boolean,
 *   graceMs?: number,
 *   signal?: AbortSignal,
 *   onEvent?: (event: { pid: number, name: string, action: string, detail?: string }) => void,
 * }} input
 * @returns {Promise<{ terminated: number[], survived: number[], failed: Array<{ pid: number, reason: string }> }>}
 */
export async function terminate(input) {
  const force = input.force === true
  const graceMs = Number.isFinite(input.graceMs) ? Number(input.graceMs) : 3000
  const emit = input.onEvent ?? (() => {})

  /* Deepest first: a supervisor re-spawns what it is watching, not what it is. */
  const ordered = [...input.targets].sort((a, b) => b.depth - a.depth)

  const terminated = []
  const survived = []
  const failed = []

  for (const target of ordered) {
    if (input.signal?.aborted === true) break
    if (!isAlive(target.pid)) {
      emit({ pid: target.pid, name: target.name, action: 'gone' })
      continue
    }

    const graceful = signalPid(target.pid, 'SIGTERM')
    if (!graceful.ok && graceful.reason !== 'already exited') {
      failed.push({ pid: target.pid, reason: graceful.reason ?? 'signal failed' })
      continue
    }
    emit({ pid: target.pid, name: target.name, action: 'sigterm' })

    const deadline = Date.now() + (force ? graceMs : graceMs)
    let alive = true
    while (Date.now() < deadline && alive) {
      await delay(100, input.signal)
      alive = isAlive(target.pid)
    }
    if (!alive) {
      terminated.push(target.pid)
      continue
    }

    if (!force) {
      survived.push(target.pid)
      emit({ pid: target.pid, name: target.name, action: 'survived', detail: 'needs force' })
      continue
    }

    const forced = signalPid(target.pid, 'SIGKILL')
    if (!forced.ok && forced.reason !== 'already exited') {
      failed.push({ pid: target.pid, reason: forced.reason ?? 'force signal failed' })
      continue
    }
    emit({ pid: target.pid, name: target.name, action: 'sigkill' })
    await delay(200, input.signal)
    if (isAlive(target.pid)) {
      survived.push(target.pid)
      emit({ pid: target.pid, name: target.name, action: 'survived', detail: 'unresponsive to SIGKILL' })
    } else {
      terminated.push(target.pid)
    }
  }

  return { terminated, survived, failed }
}

/**
 * Wait until a set of ports stops answering, or the deadline passes.
 *
 * @param {number[]} ports - ports expected to be released.
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{ released: number[], stillHeld: number[] }>}
 */
export async function waitForPortsReleased(ports, options = {}) {
  const timeoutMs = options.timeoutMs ?? 2000
  const { isPortHeld } = await import('./probe.js')
  const deadline = Date.now() + timeoutMs
  let held = new Set(ports)

  while (held.size > 0 && Date.now() < deadline && options.signal?.aborted !== true) {
    const next = new Set()
    for (const port of held) {
      if (await isPortHeld(port, options.signal)) next.add(port)
    }
    held = next
    if (held.size > 0) await delay(120, options.signal)
  }

  const released = ports.filter((port) => !held.has(port))
  return { released, stillHeld: [...held] }
}
