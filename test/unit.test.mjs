/**
 * Unit tests for the pure parts: parsing, attribution, plan building, and the
 * entry module's registration surface.
 *
 * Everything here runs with `node --test` and no harness. The pieces are
 * separated precisely so this is possible: `scan.js` parses text, `attribute.js`
 * grades structures, `kill.js` signals pids. Only `index.js` knows about
 * cordis, and it is tested through a stub context.
 *
 * @module dsh-reaper/test
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  buildKillPlan,
  classify,
  descendantClosure,
  devServerMarker,
  isAutoSelectable,
  isDevPort,
  mentionsPath,
  verdictRank,
} from '../lib/attribute.js'
import { humanAge, humanBytes, renderPlan, renderScan, shortenCommand } from '../lib/format.js'
import {
  ancestorChain,
  dedupeListeners,
  parseLsof,
  parseNetstat,
  parsePs,
  parseSs,
  parseTasklist,
  splitEndpoint,
} from '../lib/scan.js'
import { defaultProtectedPorts, inject, name as pluginName, selectRoots } from '../lib/index.js'

/** A process table with a harness tree, a dev server, and an unrelated daemon. */
const PROCESSES = [
  { pid: 1, ppid: 0, name: 'systemd', commandLine: '/sbin/init', ageSeconds: 90_000 },
  { pid: 500, ppid: 1, name: 'node', commandLine: 'node dsh-web-server.js', ageSeconds: 600 },
  { pid: 501, ppid: 500, name: 'node', commandLine: 'node /repo/node_modules/.bin/vite', ageSeconds: 300 },
  { pid: 502, ppid: 501, name: 'esbuild', commandLine: 'esbuild --service', ageSeconds: 300 },
  { pid: 700, ppid: 1, name: 'postgres', commandLine: '/usr/lib/postgresql/bin/postgres -D /var/lib/pg', ageSeconds: 80_000 },
  { pid: 900, ppid: 1, name: 'nginx', commandLine: 'nginx: master process', ageSeconds: 70_000 },
]

/** Endpoints held by the processes above, plus one with an unknown holder. */
const LISTENERS = [
  { protocol: 'tcp', localAddress: '127.0.0.1', port: 5173, pid: 501 },
  { protocol: 'tcp', localAddress: '127.0.0.1', port: 5432, pid: 700 },
  { protocol: 'tcp', localAddress: '0.0.0.0', port: 80, pid: 900 },
  { protocol: 'tcp', localAddress: '127.0.0.1', port: 9999, pid: 12345 },
  { protocol: 'tcp', localAddress: '127.0.0.1', port: 5000, pid: 500 },
]

/**
 * Classify the fixture with the harness rooted at pid 500.
 *
 * @param {any} [overrides] - classification overrides.
 * @returns {any} graded endpoints.
 */
function gradeFixture(overrides = {}) {
  return classify({
    listeners: LISTENERS,
    processes: PROCESSES,
    hostPid: 500,
    selfChain: new Set([500, 1]),
    workspaceRoot: '/repo',
    protectPorts: [],
    neverKill: [],
    ...overrides,
  })
}

test('splitEndpoint handles ipv4, bracketed ipv6, and BSD dot form', () => {
  assert.deepEqual(splitEndpoint('127.0.0.1:3000'), { address: '127.0.0.1', port: 3000 })
  assert.deepEqual(splitEndpoint('[::1]:3000'), { address: '::1', port: 3000 })
  assert.deepEqual(splitEndpoint('*:3000'), { address: '*', port: 3000 })
  assert.deepEqual(splitEndpoint('127.0.0.1.3000'), { address: '127.0.0.1', port: 3000 })
  assert.equal(splitEndpoint('nothing-here'), undefined)
})

test('parseNetstat reads the Windows table and keeps only listeners', () => {
  const text = [
    '',
    '  Proto  Local Address          Foreign Address        State           PID',
    '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1024',
    '  TCP    127.0.0.1:5173         0.0.0.0:0              LISTENING       8899',
    '  TCP    127.0.0.1:5173         127.0.0.1:52000        ESTABLISHED     8899',
    '  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       700',
    '  UDP    0.0.0.0:5353           *:*                                    2200',
    '',
  ].join('\r\n')

  const rows = parseNetstat(text)
  assert.equal(rows.length, 3, 'established connections and UDP are excluded by default')
  assert.deepEqual(
    rows.map((row) => row.port),
    [135, 5173, 5432],
  )
  assert.equal(rows[1].pid, 8899)

  const withUdp = parseNetstat(text, { includeUdp: true })
  assert.equal(withUdp.length, 4)
  assert.equal(withUdp.at(-1).protocol, 'udp')
})

test('parseNetstat reads the BSD table and reports a null pid', () => {
  const text = [
    'Active Internet connections',
    'Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)',
    'tcp4       0      0  127.0.0.1.5173         *.*                    LISTEN',
    'tcp4       0      0  127.0.0.1.5173         127.0.0.1.52000        ESTABLISHED',
    'tcp6       0      0  ::1.5432               *.*                    LISTEN',
  ].join('\n')

  const rows = parseNetstat(text)
  assert.equal(rows.length, 2)
  assert.deepEqual(rows.map((row) => row.port), [5173, 5432])
  assert.equal(rows[0].pid, null)
})

test('parseSs extracts the endpoint and the pid annotation', () => {
  const text = [
    'LISTEN 0      511          127.0.0.1:5173       0.0.0.0:*    users:(("node",pid=501,fd=21))',
    'LISTEN 0      244          127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=700,fd=7))',
    'LISTEN 0      4096                 *:80              *:*    users:(("nginx",pid=900,fd=6))',
  ].join('\n')

  const rows = parseSs(text, 'tcp')
  assert.deepEqual(rows.map((row) => row.port), [5173, 5432, 80])
  assert.deepEqual(rows.map((row) => row.pid), [501, 700, 900])
})

test('parseLsof pairs each name row with the most recent pid row', () => {
  const text = ['p501', 'cnode', 'n127.0.0.1:5173', 'p700', 'cpostgres', 'n127.0.0.1:5432'].join('\n')
  const rows = parseLsof(text, 'tcp')
  assert.deepEqual(rows, [
    { protocol: 'tcp', localAddress: '127.0.0.1', port: 5173, pid: 501 },
    { protocol: 'tcp', localAddress: '127.0.0.1', port: 5432, pid: 700 },
  ])
})

test('parsePs reads pid, ppid, name, age and the remainder as the command line', () => {
  const text = '  501   500 node  300 node /repo/node_modules/.bin/vite --host\n  502   501 esbuild  299 esbuild --service\n'
  const rows = parsePs(text)
  assert.equal(rows.length, 2)
  assert.deepEqual(rows[0], {
    pid: 501,
    ppid: 500,
    name: 'node',
    ageSeconds: 300,
    commandLine: 'node /repo/node_modules/.bin/vite --host',
  })
})

test('parseTasklist maps pids to image names and skips the INFO banner', () => {
  const text = ['INFO: No tasks are running which match the specified criteria.', '"node.exe","8899","Console","1","120,000 K"', '"chrome.exe","2200","Console","1","90,000 K"'].join('\r\n')
  const table = parseTasklist(text)
  assert.equal(table.size, 2)
  assert.equal(table.get(8899), 'node.exe')
})

test('ancestorChain walks up, stops at zero, and survives a cycle', () => {
  assert.deepEqual(ancestorChain(PROCESSES, 502), [501, 500, 1])
  assert.deepEqual(ancestorChain(PROCESSES, 1), [])
  const cyclic = [
    { pid: 10, ppid: 11 },
    { pid: 11, ppid: 10 },
  ]
  assert.deepEqual(ancestorChain(cyclic, 10), [11])
})

test('descendantClosure returns roots first, breadth-first', () => {
  assert.deepEqual(descendantClosure(new Map(PROCESSES.map((row) => [row.pid, row])), [501]), [501, 502])
  assert.deepEqual(descendantClosure(new Map(PROCESSES.map((row) => [row.pid, row])), [500]), [500, 501, 502])
  assert.deepEqual(descendantClosure(new Map(PROCESSES.map((row) => [row.pid, row])), []), [])
})

test('dedupeListeners collapses dual-stack binds into one row per pid and port', () => {
  const scan = dedupeListeners({
    listeners: [
      { protocol: 'tcp', localAddress: '::', port: 49747, pid: 21720 },
      { protocol: 'tcp', localAddress: '0.0.0.0', port: 49747, pid: 21720 },
      { protocol: 'tcp', localAddress: '::', port: 3306, pid: 9168 },
      { protocol: 'tcp', localAddress: '127.0.0.1', port: 49747, pid: 21720 },
    ],
    processes: [],
  })

  assert.equal(scan.listeners.length, 2, 'one row per protocol/port/pid')
  const wide = scan.listeners.find((row) => row.port === 49747)
  assert.deepEqual(wide.addresses, ['::', '0.0.0.0', '127.0.0.1'])
  assert.equal(wide.localAddress, '::', 'the first address stays in localAddress')
})

test('dedupeListeners keeps the same port on different pids apart', () => {
  /* Two processes fighting over one port is the actual conflict this plugin
   * reports, so they must not be merged into a single line. */
  const scan = dedupeListeners({
    listeners: [
      { protocol: 'tcp', localAddress: '127.0.0.1', port: 3000, pid: 111 },
      { protocol: 'tcp', localAddress: '127.0.0.1', port: 3000, pid: 222 },
    ],
    processes: [],
  })
  assert.equal(scan.listeners.length, 2)
})

test('devServerMarker and isDevPort recognize the usual suspects', () => {
  assert.equal(devServerMarker('node /repo/node_modules/.bin/vite --host'), 'vite')
  assert.equal(devServerMarker('python -m uvicorn app:app'), 'uvicorn')
  assert.equal(devServerMarker('/usr/bin/postgres -D /var/lib/pg'), undefined)
  assert.equal(isDevPort(5173), true)
  assert.equal(isDevPort(5432), false)
  assert.equal(isDevPort(3000), true)
})

test('mentionsPath normalizes separators in both directions', () => {
  assert.equal(mentionsPath('node C:\\work\\repo\\server.js', '/work/repo'), true)
  assert.equal(mentionsPath('node /work/repo/server.js', 'C:\\work\\repo'), true)
  assert.equal(mentionsPath('node /other/place/server.js', '/work/repo'), false)
  assert.equal(mentionsPath('anything', ''), false)
})

test('classify grades a harness-spawned dev server as agent-spawned', () => {
  const { endpoints } = gradeFixture()
  const byPort = new Map(endpoints.map((row) => [row.port, row]))

  assert.equal(byPort.get(5173).verdict, 'agent-spawned')
  assert.match(byPort.get(5173).reasons.join(' '), /descends from the harness process/)
  assert.equal(byPort.get(80).verdict, 'system')
  assert.equal(byPort.get(9999).verdict, 'unattributed')
  assert.match(byPort.get(9999).reasons.join(' '), /no process details/)
})

test('classify grades a well-known service port as system, and says which port', () => {
  /* postgres on 5432 has no session tie at all — but 5432 is how postgres
   * announces itself, so "the machine's own" is the honest grade, and the
   * reason line has to name the port that produced it. */
  const { endpoints } = gradeFixture()
  const postgres = endpoints.find((row) => row.port === 5432)

  assert.equal(postgres.verdict, 'system')
  assert.match(postgres.reasons.join(' '), /port 5432 is a well-known service port/)
  assert.equal(isAutoSelectable(postgres.verdict), false)
})

test('classify lets a session tie outrank the well-known-port grade', () => {
  /* The same port number on a process that *does* descend from the harness must
   * stay reapable: an agent that starts its own service on 8080 left it behind,
   * and grading it "system" would hide the very thing this plugin looks for. */
  const processes = [
    { pid: 500, ppid: 1, name: 'node', commandLine: 'node dsh-web-server.js', ageSeconds: 600 },
    { pid: 501, ppid: 500, name: 'node', commandLine: 'node /repo/server.js', ageSeconds: 60 },
  ]
  const listeners = [{ protocol: 'tcp', localAddress: '127.0.0.1', port: 8080, pid: 501 }]
  const { endpoints } = classify({
    listeners,
    processes,
    hostPid: 500,
    selfChain: new Set([500, 1]),
    protectPorts: [],
    neverKill: [],
  })

  assert.equal(endpoints[0].verdict, 'agent-spawned')
  assert.match(endpoints[0].reasons.join(' '), /well-known service port/)
})

test('classify marks the harness port protected and never auto-selects it', () => {
  const { endpoints } = gradeFixture({ protectPorts: [5000] })
  const harness = endpoints.find((row) => row.port === 5000)
  assert.equal(harness.verdict, 'protected')
  assert.equal(isAutoSelectable(harness.verdict), false)
})

test('classify honours neverKill on both name and command line', () => {
  const byName = gradeFixture({ neverKill: ['postgres'] }).endpoints.find((row) => row.port === 5432)
  assert.equal(byName.verdict, 'protected')
  assert.match(byName.reasons.join(' '), /neverKill pattern "postgres"/)

  const byLine = gradeFixture({ neverKill: ['/var/lib/pg'] }).endpoints.find((row) => row.port === 5432)
  assert.equal(byLine.verdict, 'protected')
})

test('classify attributes by workspace mention when ancestry is silent', () => {
  const { endpoints } = gradeFixture({ hostPid: 4242 })
  const vite = endpoints.find((row) => row.port === 5173)
  assert.equal(vite.verdict, 'workspace')
  assert.match(vite.reasons.join(' '), /names this workspace/)
})

test('classify falls back to dev-server when nothing ties it to the session', () => {
  const { endpoints } = gradeFixture({ hostPid: 4242, workspaceRoot: undefined })
  const vite = endpoints.find((row) => row.port === 5173)
  assert.equal(vite.verdict, 'dev-server')
  assert.match(vite.reasons.join(' '), /dev range|dev server/)
})

test('verdictRank orders most-reapable first and protected last', () => {
  const ranked = ['protected', 'system', 'unattributed', 'dev-server', 'workspace', 'agent-spawned'].map(verdictRank)
  assert.deepEqual(ranked, [...ranked].sort((a, b) => b - a))
})

test('buildKillPlan includes the descendant closure so no child is orphaned', () => {
  const plan = buildKillPlan({
    processes: PROCESSES,
    listeners: LISTENERS,
    roots: [500],
    selfChain: new Set([999_999]),
    protectPorts: [],
    neverKill: [],
  })
  assert.deepEqual(
    plan.targets.map((target) => target.pid).sort((a, b) => a - b),
    [500, 501, 502],
  )
  assert.equal(plan.targets.find((target) => target.pid === 502).depth, 2)
  assert.equal(plan.targets.find((target) => target.pid === 501).root, 500)
  assert.deepEqual(plan.freedPorts.map((row) => row.port).sort((a, b) => a - b), [5000, 5173])
})

test('buildKillPlan refuses the harness tree, pid 0-4, neverKill, and protected ports', () => {
  const plan = buildKillPlan({
    processes: PROCESSES,
    listeners: LISTENERS,
    roots: [1, 501, 700, 900],
    selfChain: new Set([501]),
    protectPorts: [80],
    neverKill: ['postgres'],
  })

  const refused = new Map(plan.refused.map((row) => [row.pid, row.reason]))
  assert.match(refused.get(1), /operating-system process/)
  assert.match(refused.get(501), /harness process tree/)
  assert.match(refused.get(700), /neverKill pattern "postgres"/)
  assert.match(refused.get(900), /protected port 80/)
  assert.deepEqual(plan.targets, [])
})

test('buildKillPlan excludes protected descendants but keeps the rest of the tree', () => {
  const plan = buildKillPlan({
    processes: PROCESSES,
    listeners: LISTENERS,
    roots: [500],
    selfChain: new Set(),
    protectPorts: [],
    neverKill: ['esbuild'],
  })
  assert.deepEqual(
    plan.targets.map((target) => target.pid).sort((a, b) => a - b),
    [500, 501],
  )
  assert.deepEqual(plan.untouched, [502])
})

test('buildKillPlan reports an unknown root rather than throwing', () => {
  const plan = buildKillPlan({
    processes: PROCESSES,
    listeners: LISTENERS,
    roots: [987_654],
    selfChain: new Set(),
  })
  assert.deepEqual(plan.refused, [{ pid: 987_654, reason: 'no such process' }])
  assert.deepEqual(plan.targets, [])
})

test('selectRoots resolves ports and reports ones nothing holds', () => {
  const scan = { endpoints: gradeFixture().endpoints }
  const { roots, notes } = selectRoots(scan, { ports: [5173, 1234] })
  assert.deepEqual(roots, [501])
  assert.deepEqual(notes, ['port 1234: nothing is listening'])
})

test('selectRoots with all:true takes only confident verdicts and explains the rest', () => {
  const scan = { endpoints: gradeFixture().endpoints }
  const { roots, notes } = selectRoots(scan, { all: true })
  assert.deepEqual(roots, [501])
  assert.ok(notes.some((note) => /port 5432: system/.test(note)))
  assert.ok(notes.some((note) => /port 9999: unattributed/.test(note)))
})

test('selectRoots never invites an override of infrastructure', () => {
  /* The note next to nginx must not read like a hint to name it explicitly —
   * that sentence is how an agent talks itself into killing the machine's own
   * web server. Infrastructure is reported as left alone, full stop. */
  const scan = { endpoints: gradeFixture().endpoints }
  const { notes } = selectRoots(scan, { all: true })

  const nginx = notes.find((note) => /port 80/.test(note))
  assert.ok(nginx !== undefined, 'the system endpoint is still reported')
  assert.match(nginx, /left alone/)
  assert.ok(!/name it explicitly/.test(nginx), 'infrastructure notes carry no override hint')

  const unattributed = notes.find((note) => /port 9999/.test(note))
  assert.match(unattributed, /name it explicitly/, 'merely-unattributed endpoints do offer an override')
})

test('selectRoots refuses a port whose holder pid is unknown', () => {
  const scan = { endpoints: [{ port: 7777, pid: null, verdict: 'unattributed' }] }
  const { roots, notes } = selectRoots(scan, { ports: [7777] })
  assert.deepEqual(roots, [])
  assert.deepEqual(notes, ['port 7777: holder pid unknown, refusing'])
})

test('defaultProtectedPorts reads the harness web port out of the URL', () => {
  assert.deepEqual(defaultProtectedPorts('http://127.0.0.1:19387'), [19387])
  assert.deepEqual(defaultProtectedPorts('http://127.0.0.1'), [])
  assert.deepEqual(defaultProtectedPorts('not a url'), [])
  assert.deepEqual(defaultProtectedPorts(undefined), [])
})

test('humanBytes and humanAge format usefully at every scale', () => {
  assert.equal(humanBytes(null), '-')
  assert.equal(humanBytes(512), '512B')
  assert.equal(humanBytes(2048), '2KB')
  assert.equal(humanBytes(1024 * 1024 * 3.5), '3.5MB')
  assert.equal(humanAge(null), '-')
  assert.equal(humanAge(45), '45s')
  assert.equal(humanAge(600), '10m')
  assert.equal(humanAge(7200), '2h0m')
})

test('shortenCommand collapses whitespace and truncates with an ellipsis', () => {
  assert.equal(shortenCommand('a   b\n c'), 'a b c')
  assert.equal(shortenCommand('x'.repeat(200)).length, 96)
  assert.ok(shortenCommand('x'.repeat(200)).endsWith('…'))
})

test('renderScan states the verdict for every endpoint and flags degraded probes', () => {
  const text = renderScan({
    platform: 'linux',
    scannedAt: '2026-01-01T00:00:00.000Z',
    workspaceRoot: '/repo',
    endpoints: gradeFixture().endpoints,
    summary: { listeners: 5, processes: 6, reapable: 1 },
    degraded: ['ss unavailable'],
  })
  assert.match(text, /5173\s+tcp\s+agent-spawned/)
  assert.match(text, /protected/)
  assert.match(text, /degraded: ss unavailable/)
  assert.match(text, /1 reclaimable/)
})

test('renderScan says so plainly when nothing is listening', () => {
  const text = renderScan({
    platform: 'linux',
    scannedAt: 'now',
    endpoints: [],
    summary: { listeners: 0, processes: 3, reapable: 0 },
  })
  assert.match(text, /Nothing is listening\./)
})

test('renderPlan refuses to look like it did something on a preview', () => {
  const preview = renderPlan({
    confirmed: false,
    force: false,
    targets: [{ pid: 501, ppid: 500, name: 'node', commandLine: 'vite', depth: 0, root: 501 }],
    refused: [{ pid: 1, reason: 'operating-system process' }],
    freedPorts: [{ protocol: 'tcp', port: 5173, localAddress: '127.0.0.1' }],
  })
  assert.match(preview, /preview only \(nothing signalled\)/)
  assert.match(preview, /pid 1: operating-system process/)
  assert.match(preview, /Re-run with confirm: true/)
})

test('renderPlan reports survived processes and still-held ports after a real run', () => {
  const text = renderPlan({
    confirmed: true,
    force: true,
    targets: [{ pid: 501, ppid: 500, name: 'node', commandLine: 'vite', depth: 0, root: 501 }],
    refused: [],
    freedPorts: [{ protocol: 'tcp', port: 5173, localAddress: '127.0.0.1' }],
    outcome: { terminated: [501], survived: [502], failed: [{ pid: 503, reason: 'permission denied' }] },
    portsReleased: [],
    portsStillHeld: [5173],
  })
  assert.match(text, /reaping \(forced\)/)
  assert.match(text, /terminated 1 · survived 1 · failed 1/)
  assert.match(text, /pid 503: permission denied/)
  assert.match(text, /retry with force: true/)
  assert.match(text, /ports still held: 5173/)
})

test('the plugin declares a name and injects exactly the services apply() touches', () => {
  assert.equal(pluginName, 'dsh-reaper')
  assert.ok(Array.isArray(inject), 'inject must be a static array, not a function')
  assert.deepEqual([...inject].sort(), ['commands', 'tools'])
})
