/**
 * Load the plugin entry point against a stub host and assert what it registers.
 *
 * The unit tests cover the pure modules; this covers the seam the harness
 * actually uses — that `apply()` runs to completion against a minimal context,
 * registers exactly the documented tools and command, and never touches a
 * service it did not declare in `inject`.
 *
 * @module dsh-reaper/test/plugin.test
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import * as plugin from '../lib/index.js'

/**
 * A minimal host: records registrations and fails loudly on undeclared access.
 *
 * `inject` is the contract that makes this checkable — the real runtime hands
 * `apply()` only the services listed there, so anything else this stub rejects
 * is something that would throw in production.
 *
 * @returns {any} a stub context plus the recorded registrations.
 */
function stubHost() {
  const tools = []
  const commands = []
  const declared = new Set(plugin.inject)

  const guard = (name) => {
    if (!declared.has(name)) {
      throw new Error(`plugin touched undeclared service "${name}"`)
    }
  }

  const ctx = {
    tools: {
      register(definition) {
        tools.push(definition)
        return () => {}
      },
    },
    commands: {
      register(definition) {
        commands.push(definition)
        return () => {}
      },
    },
    effect(fn) {
      return fn()
    },
    /* `get` is the documented way to reach an optional service, so it must
     * answer for anything — including services that are simply absent here. */
    get(name) {
      void name
      return undefined
    },
  }

  return {
    ctx: new Proxy(ctx, {
      get(target, property) {
        if (typeof property === 'string' && !(property in target)) guard(property)
        return Reflect.get(target, property)
      },
    }),
    tools,
    commands,
  }
}

test('apply registers the documented tools and the /reap command', () => {
  const { ctx, tools, commands } = stubHost()
  plugin.apply(ctx, { neverKill: [], protectPorts: [], includeUdp: false, graceMs: 3000, scanTimeoutMs: 20_000 })

  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    ['reaper_free_port', 'reaper_reap', 'reaper_scan'],
  )
  assert.deepEqual(commands.map((command) => command.name), ['reap'])
})

test('every registered tool satisfies the defineTool contract', () => {
  const { ctx, tools } = stubHost()
  plugin.apply(ctx, { neverKill: [], protectPorts: [], includeUdp: false, graceMs: 3000, scanTimeoutMs: 20_000 })

  for (const tool of tools) {
    assert.equal(typeof tool.name, 'string')
    assert.ok(tool.name.length > 0, `${tool.name} has a name`)
    assert.equal(typeof tool.description, 'string')
    assert.ok(tool.description.length > 20, `${tool.name} has a real description`)
    assert.equal(typeof tool.execute, 'function', `${tool.name} has an execute`)
    assert.ok(Number.isFinite(tool.timeoutMs) && tool.timeoutMs > 0, `${tool.name} declares a positive timeout`)
    /* The compiled parameters must be a JSON Schema object — this is what the
     * model is shown, so a malformed one silently degrades the tool. */
    assert.equal(tool.parameters.type, 'object', `${tool.name} parameters compile to an object schema`)
    assert.equal(typeof tool.parameters.properties, 'object')
  }
})

test('the destructive tools document that they preview by default', () => {
  const { ctx, tools } = stubHost()
  plugin.apply(ctx, { neverKill: [], protectPorts: [], includeUdp: false, graceMs: 3000, scanTimeoutMs: 20_000 })

  for (const name of ['reaper_reap', 'reaper_free_port']) {
    const tool = tools.find((candidate) => candidate.name === name)
    assert.match(tool.description, /confirm/, `${name} tells the model about confirm`)
    assert.equal(tool.parameters.properties.confirm.type, 'boolean', `${name} exposes confirm`)
  }
})

test('the command declares the documented flags and returns a CommandResult', async () => {
  const { ctx, commands } = stubHost()
  plugin.apply(ctx, { neverKill: [], protectPorts: [], includeUdp: false, graceMs: 3000, scanTimeoutMs: 20_000 })

  const reap = commands[0]
  assert.equal(typeof reap.handler, 'function')
  assert.match(reap.input.hint, /--all/)
  assert.match(reap.input.hint, /--confirm/)

  /* A handler must resolve to { kind: 'success' | 'error' } and nothing else.
   * `--all` is used here because it reaches the plan path without a live scan. */
  const result = await reap.handler({ rawInput: ' --all ', agent: undefined, signal: undefined })
  assert.ok(result.kind === 'success' || result.kind === 'error', `unexpected kind ${result.kind}`)
  if (result.kind === 'success') assert.equal(typeof result.text, 'string')
  else assert.ok(result.text.length > 0)
})

test('a bare /reap renders the inventory, not a plan', async () => {
  const { ctx, commands } = stubHost()
  plugin.apply(ctx, { neverKill: [], protectPorts: [], includeUdp: false, graceMs: 3000, scanTimeoutMs: 20_000 })

  /* No ports and no --all means "show me the inventory". That is the common
   * case, so it must not fall through to the plan renderer. */
  const result = await commands[0].handler({ rawInput: '', agent: undefined, signal: undefined })
  assert.equal(result.kind, 'success')
  assert.doesNotMatch(result.text, /preview only/)
})
