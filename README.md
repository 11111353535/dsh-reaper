# dsh-reaper

**Reclaim the ports your agent forgot to give back.**

An agent starts `vite`, `next dev`, a watcher, a tunnel. The turn ends. The session ends. The process does not — it keeps holding 5173, and the next run dies with `EADDRINUSE` while you go hunting through Task Manager for a `node.exe` you cannot identify.

`dsh-reaper` inventories every listening endpoint on the machine, **attributes each holder to this session**, shows you exactly what it would kill, and only then — when you say `confirm: true` — reclaims the ports.

```
$ /reap

dsh-reaper · win32 · 2026-10-16T10:57:26.626Z
workspace: E:\work\shop-frontend

51 listening endpoint(s) · 432 process(es) · 3 reclaimable

 5173  tcp  agent-spawned  pid   8899   18m  node.exe
      node E:\work\shop-frontend\node_modules\.bin\vite --host
 3001  tcp  workspace      pid   9120   42m  node.exe
      node E:\work\shop-frontend\server.js
 3306  tcp  system         pid   9168  9h29m  mysqld.exe
      ↳ port 3306 is a well-known service port
19387  tcp  protected      pid  11664   2h9m  DeepSeek Harness.exe
      ↳ holds the harness process tree
```

## Why it is not just "kill by port"

Port tools tell you *what* holds a port. The hard part is deciding **whether you are allowed to kill it**, and that answer depends on facts a port number does not carry:

- Did this process descend from **the harness that is running the scan**? Killing it takes down the session.
- Is it **the machine's own infrastructure** — `mysqld` on 3306, `nginx` on 80?
- Is it a leftover **dev server** with no session tie at all?
- Is it something the user explicitly said to leave alone?

`dsh-reaper` answers that per endpoint and grades the result, so a `--all` sweep can be safe:

| verdict | meaning | auto-selected by `all: true` |
| --- | --- | --- |
| `agent-spawned` | descends from the harness host process | ✅ |
| `workspace` | command line names the current workspace | ✅ |
| `dev-server` | looks like a dev server, watcher or tunnel | ❌ |
| `unattributed` | listening, but nothing ties it to this session | ❌ |
| `system` | OS process, or holds a well-known service port | ❌ |
| `protected` | matched `neverKill` / `protectPorts`, or holds the harness tree | ❌ |

Two rules make that table trustworthy:

1. **The harness never kills itself.** The scan walks up from its own pid and refuses the whole ancestor chain, plus the process tree it is running inside.
2. **Infrastructure is not "unattributed".** A holder of a well-known service port is graded `system` — the same hands-off grade as an OS process — so `all: true` never reaches it, and its note says `left alone` rather than hinting at an override.

## Safety properties

Reaping is destructive, so the defaults are conservative and the refusals are absolute:

- **Nothing is signalled without `confirm: true`.** The default call computes the plan and returns it.
- **The plan is the full descendant closure.** Killing an `npm run dev` shim without its child leaves the port held — the exact failure this plugin exists to prevent. Descendants are ordered deepest-first so children die before their parents.
- **Refusals cannot be overridden by naming a pid.** The harness process tree, pid 0–4, `neverKill` matches and `protectPorts` holders are refused even when passed explicitly, with the reason reported.
- **`SIGTERM` first, `SIGKILL` only if you ask.** `force: true` escalates, and even then survivors are reported rather than hidden.
- **The result is verified, not assumed.** After signalling, the plugin re-probes each freed port and reports `ports confirmed free` or `ports still held`.

## Install

```
dsh plugin add https://github.com/11111353535/dsh-reaper
```

From a checkout instead of a git host, pass the absolute path:

```
dsh plugin add /absolute/path/to/dsh-reaper
```

The package declares no `dsh-*` peer dependency on purpose: it imports only `node:*` plus `@deepseek-ai/dsh-tools`, which the harness resolves from its own installation. Nothing is bundled that could shadow the host's copy.

To tune it per profile, add a `config` block to the row the installer inserted in `~/.dsh/profiles/<profile>/cordis.patch.yml`:

```yaml
- insert:
    - id: reaper
      name: 'dsh-reaper'
      config:
        neverKill: ['my-precious-daemon']
        protectPorts: [80, 443, 19387]
        includeUdp: false
        graceMs: 3000
        scanTimeoutMs: 20000
```

| key | default | meaning |
| --- | --- | --- |
| `neverKill` | `[]` | Process-name or command-line substrings that must never be signalled. |
| `protectPorts` | `[]` | Ports whose holder is refused even when named explicitly. The harness's own web port is added automatically. |
| `includeUdp` | `false` | Also enumerate UDP endpoints. Off by default: dev servers are TCP. |
| `graceMs` | `3000` | How long `SIGTERM` gets before the process is reported as surviving. |
| `scanTimeoutMs` | `20000` | Wall-clock ceiling for one system enumeration. |

## Tools

### `reaper_scan`

Read-only inventory. Signals nothing. Grades every listening endpoint and returns the full scan.

| argument | type | meaning |
| --- | --- | --- |
| `includeUdp` | boolean | Also enumerate UDP endpoints. |
| `workspace` | string | Workspace root used for attribution. Defaults to the session workspace. |

### `reaper_reap`

Compute a plan and, only with `confirm: true`, execute it.

| argument | type | meaning |
| --- | --- | --- |
| `pids` | integer[] | Explicit root pids. Their descendants are included automatically. |
| `ports` | integer[] | Reap whatever holds these ports. |
| `all` | boolean | Also select every endpoint confidently attributable to this session (`agent-spawned` and `workspace` only). |
| `force` | boolean | Escalate to `SIGKILL` for processes that ignore `SIGTERM`. |
| `confirm` | boolean | Actually signal the plan. Defaults to `false`. |

### `reaper_free_port`

Reclaim one specific port. If the port is already free it says so and does nothing; if the holder cannot be attributed or is protected, it reports why instead of guessing.

| argument | type | meaning |
| --- | --- | --- |
| `port` | integer *(required)* | The TCP port to reclaim. |
| `force` | boolean | Escalate to `SIGKILL` if `SIGTERM` is ignored. |
| `confirm` | boolean | Actually signal the holder. Defaults to `false`. |

## Slash command

```
/reap                  # inventory
/reap --all            # preview everything confidently attributable to this session
/reap --all --confirm  # and actually do it
/reap 5173             # preview reclaiming one port
/reap 5173 3001 --confirm --force
```

## How the scan works

| platform | endpoints | process table |
| --- | --- | --- |
| Windows | `Get-NetTCPConnection -State Listen` (+ `Get-NetUDPEndpoint`) | `Get-CimInstance Win32_Process` |
| Windows (fallback) | `netstat -ano` | `tasklist /FO CSV /NH` |
| Linux | `ss -H -ltnp` | `ps -eo pid=,ppid=,comm=,etimes=,args=` |
| macOS | `lsof -nP -iTCP -sTCP:LISTEN -Fpcn` | `ps` |

Every probe is best-effort: a missing binary or a failed command degrades that one source and is reported in `degraded: ...` at the end of the scan. A scan that falls back to `netstat` still works — it just loses command lines, and therefore attribution gets weaker, which the report tells you.

One process listening on both `::` and `0.0.0.0` is one problem, not two: dual-stack bindings are collapsed into a single row per `protocol`/`port`/`pid`, with every address kept in `addresses`.

## Development

```
npm test          # 42 unit tests, no harness needed
npm run test:live # a real read-only scan of this machine
npm run setup:deps
```

`lib/` is plain ESM JavaScript with no build step, and the unit tests cover the parsers against recorded fixtures — Windows and BSD `netstat` tables, `ss`, `lsof`, `ps`, `tasklist`, the classifier, the plan builder, and the renderers. `test:live` covers what fixtures cannot: that the real enumeration works on the host you are on. It signals nothing.

`setup:deps` links the three host packages `lib/` imports (`cordis`, `dsh-tools`, `schemastery`) into a local `node_modules` so a bare checkout can run the tests. Set `DSH_HOST_NODE_MODULES` if the harness is not in a standard location.

## License

MIT
