/**
 * Rendering: turning scan and plan structures into something a human reads at
 * a glance, in a terminal card.
 *
 * Kept separate from the tools so the text form is testable without a harness
 * and so the tools can return structured values while the card renders prose.
 *
 * @module dsh-reaper/format
 */

/**
 * Format a byte count for humans.
 *
 * @param {number | null} bytes - byte count.
 * @returns {string} a compact string, or `-` when unknown.
 */
export function humanBytes(bytes) {
  if (bytes === null || !Number.isFinite(bytes)) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  const rendered = unit > 0 && value < 10 ? value.toFixed(1).replace(/\.0$/u, '') : String(Math.round(value))
  return `${rendered}${units[unit]}`
}

/**
 * Format a duration for humans.
 *
 * @param {number | null} seconds - age in seconds.
 * @returns {string} a compact string, or `-` when unknown.
 */
export function humanAge(seconds) {
  if (seconds === null || !Number.isFinite(seconds)) return '-'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d${Math.floor((seconds % 86400) / 3600)}h`
}

/**
 * Shorten a command line to fit one row.
 *
 * @param {string} commandLine - full command line.
 * @param {number} [max] - maximum length.
 * @returns {string} the shortened form.
 */
export function shortenCommand(commandLine, max = 96) {
  const single = commandLine.replaceAll(/\s+/gu, ' ').trim()
  if (single.length <= max) return single
  return `${single.slice(0, max - 1)}…`
}

/**
 * Render the scan inventory.
 *
 * @param {{
 *   platform: string,
 *   scannedAt: string,
 *   workspaceRoot?: string,
 *   endpoints: Array<any>,
 *   summary: any,
 *   degraded?: string[],
 * }} scan
 * @returns {string} human-readable inventory.
 */
export function renderScan(scan) {
  const lines = []
  lines.push(`dsh-reaper · ${scan.platform} · ${scan.scannedAt}`)
  if (scan.workspaceRoot !== undefined) lines.push(`workspace: ${scan.workspaceRoot}`)
  lines.push('')

  const { summary } = scan
  lines.push(
    `${summary.listeners} listening endpoint(s) · ${summary.processes} process(es) · ` +
      `${summary.reapable} reclaimable`,
  )
  lines.push('')

  if (scan.endpoints.length === 0) {
    lines.push('Nothing is listening.')
  } else {
    const width = Math.max(...scan.endpoints.map((row) => String(row.port).length), 4)
    for (const row of scan.endpoints) {
      const port = String(row.port).padStart(width)
      const pid = row.pid === null ? '?' : String(row.pid)
      const name = row.process?.name ?? '(unknown)'
      const age = humanAge(row.process?.ageSeconds ?? null)
      lines.push(`${port}  ${row.protocol.padEnd(3)}  ${row.verdict.padEnd(13)} pid ${pid.padStart(6)}  ${age.padStart(5)}  ${name}`)
      const command = row.process?.commandLine ?? ''
      if (command !== '') lines.push(`      ${shortenCommand(command)}`)
      if (row.verdict === 'protected' || row.verdict === 'system') {
        lines.push(`      ↳ ${row.reasons.join('; ')}`)
      }
    }
  }

  if (Array.isArray(scan.degraded) && scan.degraded.length > 0) {
    lines.push('')
    lines.push(`degraded: ${scan.degraded.join('; ')}`)
  }
  return lines.join('\n')
}

/**
 * Render a kill plan (preview or executed).
 *
 * @param {{
 *   confirmed: boolean,
 *   force: boolean,
 *   targets: Array<any>,
 *   refused: Array<{ pid: number, reason: string }>,
 *   freedPorts: Array<{ protocol: string, port: number, localAddress: string }>,
 *   outcome?: { terminated: number[], survived: number[], failed: Array<{ pid: number, reason: string }> },
 *   portsReleased?: number[],
 *   portsStillHeld?: number[],
 * }} plan
 * @returns {string} human-readable plan.
 */
export function renderPlan(plan) {
  const lines = []
  lines.push(plan.confirmed ? (plan.force ? 'dsh-reaper · reaping (forced)' : 'dsh-reaper · reaping') : 'dsh-reaper · preview only (nothing signalled)')
  lines.push('')

  if (plan.targets.length === 0) {
    lines.push('No processes selected.')
  } else {
    lines.push(`${plan.targets.length} process(es) selected:`)
    for (const target of [...plan.targets].sort((a, b) => a.depth - b.depth)) {
      const marker = target.depth === 0 ? '●' : '└'
      lines.push(`  ${marker} pid ${String(target.pid).padStart(6)}  ${target.name}`)
      if (target.commandLine !== '') lines.push(`      ${shortenCommand(target.commandLine, 88)}`)
    }
  }

  if (plan.freedPorts.length > 0) {
    const ports = plan.freedPorts.map((row) => `${row.port}/${row.protocol}`).join(', ')
    lines.push('')
    lines.push(`port(s) released: ${ports}`)
  }

  if (plan.refused.length > 0) {
    lines.push('')
    lines.push('refused:')
    for (const row of plan.refused) lines.push(`  pid ${row.pid}: ${row.reason}`)
  }

  if (plan.outcome !== undefined) {
    lines.push('')
    lines.push(
      `terminated ${plan.outcome.terminated.length} · survived ${plan.outcome.survived.length} · failed ${plan.outcome.failed.length}`,
    )
    for (const row of plan.outcome.failed) lines.push(`  pid ${row.pid}: ${row.reason}`)
    if (plan.outcome.survived.length > 0) {
      lines.push(`  still alive: ${plan.outcome.survived.join(', ')} (retry with force: true)`)
    }
    if (Array.isArray(plan.portsStillHeld) && plan.portsStillHeld.length > 0) {
      lines.push(`  ports still held: ${plan.portsStillHeld.join(', ')}`)
    } else if (Array.isArray(plan.portsReleased) && plan.portsReleased.length > 0) {
      lines.push(`  ports confirmed free: ${plan.portsReleased.join(', ')}`)
    }
  } else {
    lines.push('')
    lines.push('This was a preview. Re-run with confirm: true to actually signal these processes.')
  }

  return lines.join('\n')
}
