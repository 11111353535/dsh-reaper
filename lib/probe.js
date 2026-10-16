/**
 * Port probing: does anything still answer on this port?
 *
 * Deliberately separate from `scan.js`. A scan enumerates the whole machine
 * and costs a process spawn; a probe answers one yes/no question and is cheap
 * enough to poll in a loop while waiting for a socket to be released.
 *
 * @module dsh-reaper/probe
 */

import { createConnection } from 'node:net'

/** Default connect timeout for a liveness probe. */
const PROBE_TIMEOUT_MS = 400

/**
 * Whether a TCP port accepts a connection on the loopback interface.
 *
 * A refused connection means the port is free; a successful one means
 * something is listening. A timeout is treated as *held* — a filtered or
 * saturated listener is still a listener, and reporting it as free would let
 * the caller start a server that then fails to bind.
 *
 * @param {number} port - port to probe.
 * @param {AbortSignal} [signal] - cancellation signal.
 * @param {{ host?: string, timeoutMs?: number }} [options]
 * @returns {Promise<boolean>} true when something is listening.
 */
export function isPortHeld(port, signal, options = {}) {
  const host = options.host ?? '127.0.0.1'
  const timeoutMs = options.timeoutMs ?? PROBE_TIMEOUT_MS
  if (signal?.aborted === true) return Promise.resolve(false)

  return new Promise((resolve) => {
    let settled = false
    const socket = createConnection({ port, host })

    const finish = (held) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      socket.destroy()
      resolve(held)
    }

    const timer = setTimeout(() => finish(true), timeoutMs)
    function onAbort() {
      finish(false)
    }

    socket.once('connect', () => finish(true))
    socket.once('error', (error) => {
      const code = /** @type {NodeJS.ErrnoException} */ (error).code
      /* ECONNREFUSED is the one answer that proves the port is free. */
      if (code === 'ECONNREFUSED') finish(false)
      else if (code === 'EADDRNOTAVAIL' || code === 'ENETUNREACH') finish(false)
      else finish(true)
    })
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * Probe several ports and report which are held.
 *
 * @param {number[]} ports - ports to probe.
 * @param {{ signal?: AbortSignal, host?: string, timeoutMs?: number }} [options]
 * @returns {Promise<{ held: number[], free: number[] }>}
 */
export async function probePorts(ports, options = {}) {
  const results = await Promise.all(
    ports.map(async (port) => ({
      port,
      held: await isPortHeld(port, options.signal, options),
    })),
  )
  return {
    held: results.filter((row) => row.held).map((row) => row.port),
    free: results.filter((row) => !row.held).map((row) => row.port),
  }
}
