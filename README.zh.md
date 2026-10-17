# dsh-reaper

**把 agent 忘记归还的端口收回来。**

Agent 起了 `vite`、`next dev`、watcher、隧道。回合结束了，会话结束了，进程没有——它继续占着 5173，下一次运行直接 `EADDRINUSE`，而你要在任务管理器里翻一个认不出来的 `node.exe`。

`dsh-reaper` 枚举机器上所有正在监听的端点，**把每个持有者归因到当前会话**，先让你看清它到底会杀什么，只有你说了 `confirm: true` 之后，才真正回收端口。

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

## 为什么它不只是「按端口杀进程」

端口工具告诉你**谁**占着端口。真正难的是判断**你到底有没有资格杀它**——而这个答案取决于端口号本身根本不携带的信息：

- 这个进程是不是从**正在扫描的 harness** 继承下来的？杀了它，会话当场一起没。
- 它是不是**机器自己的基础设施**——3306 上的 `mysqld`、80 上的 `nginx`？
- 它是不是一个跟当前会话毫无关系的、被遗弃的 **dev server**？
- 它是不是用户明确交代过不许动的东西？

`dsh-reaper` 对每个端点回答这个问题并给出分级，所以 `--all` 这种一把梭才可能是安全的：

| verdict | 含义 | `all: true` 会自动选中 |
| --- | --- | --- |
| `agent-spawned` | 从 harness 宿主进程继承下来 | ✅ |
| `workspace` | 命令行里点名了当前工作区 | ✅ |
| `dev-server` | 长得像 dev server / watcher / 隧道 | ❌ |
| `unattributed` | 在监听，但没有任何线索把它和本会话连起来 | ❌ |
| `system` | 操作系统进程，或占着众所周知的service 端口 | ❌ |
| `protected` | 命中 `neverKill` / `protectPorts`，或占着 harness 进程树 | ❌ |

有两条规则让这张表可信：

1. **harness 永远不会杀掉自己。** 扫描从自己的 pid 往上走，整条祖先链连同它所在的进程树一起被无条件拒绝。
2. **基础设施不算「无法归因」。** 占着众所周知service 端口的进程被判为 `system`——和操作系统进程同级的「别碰」——所以 `all: true` 永远够不到它，而且它的说明写的是 `left alone`，不是一句诱导你去覆盖的提示。

## 安全性质

回收是破坏性操作，所以默认值一律保守，拒绝项一律绝对：

- **没有 `confirm: true` 就什么信号都不发。** 默认调用只计算计划并把它返回。
- **计划是完整的后代闭包。** 只杀 `npm run dev` 外壳而不杀它的子进程，端口依然被占——这正是本插件存在的意义。后代按深度降序执行，子进程先于父进程死。
- **拒绝项无法通过点名 pid 绕过。** harness 进程树、pid 0–4、`neverKill` 命中、`protectPorts` 持有者，即使被显式传入也照样拒绝，并给出原因。
- **先 `SIGTERM`，只有你要求时才 `SIGKILL`。** `force: true` 才升级；即便如此，活下来的进程会被如实报告，而不是被藏起来。
- **结果是验证过的，不是假设的。** 发完信号后重新探测每个被释放的端口，报告 `ports confirmed free` 或 `ports still held`。

## 安装

```
dsh plugin add https://github.com/11111353535/dsh-reaper
```

想从本地检出装，就直接给绝对路径：

```
dsh plugin add /absolute/path/to/dsh-reaper
```

本包**故意不声明任何 `dsh-*` peer 依赖**：它只 import `node:*` 和 `@deepseek-ai/dsh-tools`，后者由 harness 从自己的安装目录解析。不带任何可能遮蔽宿主的打包副本。

按 profile 调参时，给安装器写入 `~/.dsh/profiles/<profile>/cordis.patch.yml` 的那一行加 `config`：

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

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `neverKill` | `[]` | 进程名或命令行子串，命中即绝不发信号。 |
| `protectPorts` | `[]` | 持有者被拒绝的端口，即使被显式点名也一样。harness 自己的 web 端口会自动加入。 |
| `includeUdp` | `false` | 是否同时枚举 UDP 端点。默认关闭：dev server 是 TCP。 |
| `graceMs` | `3000` | `SIGTERM` 之后等多久就把进程报告为「仍在运行」。 |
| `scanTimeoutMs` | `20000` | 单次系统枚举的墙钟上限。 |

## 工具

### `reaper_scan`

只读清单，不发任何信号。给每个监听端点分级并返回完整扫描结果。

| 参数 | 类型 | 含义 |
| --- | --- | --- |
| `includeUdp` | boolean | 同时枚举 UDP 端点。 |
| `workspace` | string | 用于归因的工作区根目录，默认为当前会话工作区。 |

### `reaper_reap`

计算计划，并且只在 `confirm: true` 时执行。

| 参数 | 类型 | 含义 |
| --- | --- | --- |
| `pids` | integer[] | 显式的根 pid，其后代会自动包含。 |
| `ports` | integer[] | 回收这些端口的持有者。 |
| `all` | boolean | 额外选中所有能确信归因到本会话的端点（仅 `agent-spawned` 与 `workspace`）。 |
| `force` | boolean | 对无视 `SIGTERM` 的进程升级为 `SIGKILL`。 |
| `confirm` | boolean | 真正发信号。默认 `false`。 |

### `reaper_free_port`

回收某一个指定端口。端口已经空闲就直接说明并且什么都不做；持有者无法归因或被保护时，说明原因而不是猜。

| 参数 | 类型 | 含义 |
| --- | --- | --- |
| `port` | integer *(必填)* | 要回收的 TCP 端口。 |
| `force` | boolean | 若 `SIGTERM` 被无视则升级为 `SIGKILL`。 |
| `confirm` | boolean | 真正发信号。默认 `false`。 |

## 斜杠命令

```
/reap                  # 清单
/reap --all            # 预览所有能确信归因到本会话的目标
/reap --all --confirm  # 并真正执行
/reap 5173             # 预览回收单个端口
/reap 5173 3001 --confirm --force
```

## 扫描是怎么做的

| 平台 | 端点 | 进程表 |
| --- | --- | --- |
| Windows | `Get-NetTCPConnection -State Listen`（+ `Get-NetUDPEndpoint`） | `Get-CimInstance Win32_Process` |
| Windows（降级） | `netstat -ano` | `tasklist /FO CSV /NH` |
| Linux | `ss -H -ltnp` | `ps -eo pid=,ppid=,comm=,etimes=,args=` |
| macOS | `lsof -nP -iTCP -sTCP:LISTEN -Fpcn` | `ps` |

每个探测都是 best-effort：某个二进制缺失或命令失败，只会降级那一个来源，并在扫描末尾的 `degraded: ...` 里如实报告。退到 `netstat` 的扫描依然能用——只是拿不到命令行，归因因此变弱，而报告会把这一点告诉你。

一个进程同时监听 `::` 和 `0.0.0.0` 是一个问题而不是两个：双栈绑定会被合并成每个 `protocol`/`port`/`pid` 一行，所有地址保留在 `addresses` 里。

## 开发

```
npm test          # 42 个单测，不需要 harness
npm run test:live # 对本机做一次真实的只读扫描
npm run setup:deps
```

`lib/` 是无构建步骤的纯 ESM JavaScript，单测用录制好的 fixture 覆盖各个解析器——Windows 与 BSD 的 `netstat` 表、`ss`、`lsof`、`ps`、`tasklist`、分类器、计划构建器和渲染器。`test:live` 覆盖 fixture 覆盖不了的部分：真实枚举在你所在的主机上确实能跑。它不发任何信号。

`setup:deps` 把 `lib/` 依赖的三个宿主包（`cordis`、`dsh-tools`、`schemastery`）链接进本地 `node_modules`，让裸检出也能跑测试。harness 不在标准位置时，设置 `DSH_HOST_NODE_MODULES`。

## 许可证

MIT
