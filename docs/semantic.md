# 语义文档：dsh-blue-team（蓝队防御工具面）

> 版本 v0.1 · 2026-09-14 · 作者：爱丽丝 · 状态：**draft**
> 开发方式：语义文档优先（先写清「是什么/什么关系/怎么裁决」，再让实现逼近，最后用实践回修）
> 实现落点：`self-plugins/dsh-blue-team/src/index.ts`（工具面）+ `src/net.ts`（资产发现）+ `src/host.ts`（主机取证）+ `src/intel.ts`（威胁情报）

| 项 | 值 |
|----|----|
| 能力名 | dsh-blue-team（插件内 `name = 'dsh-blue-team'`） |
| 主副本路径 | `self-plugins/dsh-blue-team/docs/semantic.md` |
| 实现落点 | `src/index.ts`(291 行) / `src/net.ts`(74) / `src/host.ts`(119) / `src/intel.ts`(119) |
| 版本 | `package.json` = 0.1.1 |
| 组合行 | `E:\alice\.dsh\profiles\web\cordis.patch.yml` 行 173–175，`id: agent-blue-team`，**无 config** |
| 状态 | **draft**（实现已上线并挂载；本文为 2026-09-14 补课产物） |

---

## 1 · 定位与反定位

**定位**：以 MITRE ATT&CK 为能力地图的**防御侧**工具面（8 工具）：资产发现 → 漏洞评估 → 威胁情报 → 主机取证 → 加固基线。它回答「我这台机器/这个自有资产有什么暴露面、有没有被动过的痕迹」。

**反定位（本文不管什么）**：
- 不管**攻击/利用**（那是 `dsh-red-team` / `dsh-exploit-kit` / `dsh-cyber-range` 的领地）
- 不管**持续监控/告警**（无守护进程、无定时任务、无告警通道——它是**按需快照**，不是 HIDS）
- 不管**日志长期存储**（只读 Windows 事件日志的最近 N 天，不落库）
- **不是**授权/合规系统：**「仅自有或已授权资产」是使用纪律，由调用者承担，插件不做技术强制**（见 §5）

## 2 · 术语表

| 术语 | 含义 |
|------|------|
| TCP connect 扫描 | 完整三次握手判活；不做 SYN 半开（无声称的隐蔽性，误报低但**会留连接日志**） |
| `safe()` 包装 | 统一把异常转成 `{ok:false, error}`，**工具不抛异常**（`src/index.ts:30`） |
| `runPs` | 经 `powershell.exe -NoProfile -NonInteractive -Command` 执行脚本，UTF-8 双向编码前置（`src/host.ts:6`） |
| 经典事件 ID | 4625/4624/4672/4720/4726/4732/7045/1102/4698/4104（`EVENT_IDS` 映射表） |
| IOC | 失陷指标（域名/URL/hash），本插件经 urlscan.io 查证 |
| ATT&CK 映射 | README 表格里每个工具对应的战术编号（TA0043 侦察 / TA0003 持久化 / TA0011 C2 等） |
| 生效判据 | 「当前 web 进程真的在跑这份构建」的进程级判据（见 §6） |

## 3 · 概念模型

```
爱丽丝 / windows-security-hardening 技能
   │  8 工具（blue_*）
   ▼
dsh-blue-team · apply(ctx, config)
   ├─ net.ts   blue_port_scan ─► scanPorts(host, ports, timeout=1000, concurrency=200)
   │                              parsePorts("22,80" | "1-1000" | 混合) ∩ [1,65535]
   ├─ intel.ts blue_cve_lookup  ─► NVD API v2  keywordSearch, resultsPerPage = min(limit,20)
   │           blue_ioc_query   ─► urlscan.io   /api/v1/search/?q=domain:<v>（top 5）
   ├─ host.ts  blue_hash_lookup ─► powershell Get-FileHash(MD5/SHA1/SHA256) → NOT_FOUND / JSON
   │           blue_process_audit   ─► Get-NetTCPConnection（Listen|Established）+ 进程名映射
   │           blue_autoruns_check  ─► Run 键 ×5 + 计划任务(≤40) + 自启动服务(≤30)
   │           blue_event_log_query ─► Get-WinEvent FilterHashtable{LogName,Id,StartTime}
   │           blue_baseline_check  ─► 防火墙/共享/RDP/管理员组/自动登录 5 项
   ▼ safe() 包装 → {ok:true, 数据} | {ok:false, error}
   ▼ render（每个工具自带）：人读摘要，如 `[PASS] Firewall_Domain  Inbound=Block`
```

不变量（invariants）：
1. **I1 工具不抛异常**：任何失败都收敛为 `{ok:false, error}`（8 个工具全部经 `safe()`）。
2. **I2 只读优先**：8 个工具中**无任何写/改/删本地状态的操作**——`blue_port_scan` 的对外连接是唯一「离开本机」的行为（可用「审计期间注册表/文件 mtime 无变化」一次测量判真假）。
3. **I3 情报源零 key**：`blue_cve_lookup`（NVD）、`blue_ioc_query`（urlscan.io）均免费无 key；**不引入需要凭据的第三方**（VirusTotal 类只留接口）。
4. **I4 PowerShell 5.1 兼容**：脚本只用 `powershell.exe` 5.1 可用语法（本机无 pwsh 7，`src/host.ts:5` 注释明示）。
5. **I5 输出结构化**：主机侧脚本统一 `ConvertTo-Json -Compress`，工具层 `JSON.parse` 后再裁剪——不把 PowerShell 原文本直接塞给模型。

## 4 · 契约

### 4.1 配置（`Config`）

| 字段 | 类型 | 默认 | 语义 |
|------|------|------|------|
| `enabled` | boolean | `true` | **只门控末尾一行 `logger.info`，不门控工具注册**（见 §8 缺口①） |

### 4.2 工具契约（8 个）

| 工具 | 关键入参 | 默认 | 实现落点 |
|------|---------|------|---------|
| `blue_port_scan` | `host` / `ports` / `timeout` | `127.0.0.1` / `DEFAULT_PORTS`（44 个常见端口）/ `1000` ms | `net.ts:scanPorts`（并发 200） |
| `blue_cve_lookup` | `keyword`(必填) / `limit` | —/`10`（最大 20） | `intel.ts:searchCveNvd` |
| `blue_hash_lookup` | `path`(必填) | — | `host.ts:hashFile` → `runPs` |
| `blue_ioc_query` | `value`(必填) | — | `intel.ts:queryUrlscan`（域名提取：剥协议与路径） |
| `blue_process_audit` | `limit` | `200` | `host.ts:auditConnections` |
| `blue_autoruns_check` | `limit` | `100` | `host.ts:auditAutoruns` |
| `blue_event_log_query` | `eventIds`/`days`/`logName`/`limit` | `4625,4624,4672,4720,7045,1102` / `7` / `Security` / `100` | `host.ts:queryEventLog` |
| `blue_baseline_check` | — | — | `host.ts:baselineCheck`（5 检查项，状态 PASS/WARN/FAIL/INFO） |

超时：`runPs` 30s；NVD 20s（`AbortSignal.timeout`）；urlscan.io 15s。

### 4.3 调用点清单 `[MUST]`

| 调用方 | 调用点（文件:符号） | 时机 |
|-------|------------------|------|
| web 组合 | `.dsh/profiles/web/cordis.patch.yml:174`（`id: agent-blue-team`，无 config） | web 启动装载（**唯一挂载点**） |
| 插件自身 | `src/index.ts:29` `const reg = (tool) => ctx.tools.register(defineTool(tool))` → 8 次调用（行 41/71/98/130/162/190/220/260） | 装载时注册全部 8 个 |
| 插件自身 | `src/index.ts:288` `if (config.enabled) logger.info('蓝队工具面就绪（8 工具）')` | 装载末尾（**只门控日志**） |
| 依赖服务 | `src/index.ts:inject = ['tools']` | cordis 激活门 |
| 模块依赖 | `import { scanPorts, parsePorts, DEFAULT_PORTS } from './net.js'`；`{runPs, auditConnections, auditAutoruns, queryEventLog, baselineCheck, hashFile} from './host.js'`；`{searchCveNvd, queryUrlscan} from './intel.js'`（`src/index.ts:9-13`） | 模块加载 |
| 技能（消费方） | `alice-self-assets/skills/windows-security-hardening/SKILL.md:12`（「跑安全基线：`blue_baseline_check`、`blue_process_audit`、`blue_autoruns_check`、`blue_port_scan`」） | 设备加固流程第一步 |
| 外部端点 | `https://services.nvd.nist.gov/rest/json/cves/2.0`（GET）；`https://urlscan.io/api/v1/search/?q=domain:…`（GET） | 每次情报类调用 |
| 外部子进程 | `powershell.exe -NoProfile -NonInteractive -Command <script>`（`src/host.ts:9`） | 5 个主机侧工具 |
| 落盘产物 | **无**——结果只回模型，不留痕、不落库 | — |
| 日志 | `ctx.logger('blue-team')`：仅装载时一行（**宿主 logger 不落盘**） | — |

## 5 · 边界与信任

- **能力边界 ≠ 沙箱**：`blue_port_scan` 可对**任意 host** 发起 TCP 连接扫描（无白名单、无速率限制、无授权校验）。**「仅自有/已授权资产」是纪律，不是技术强制**——违反时插件不会拦。同理 `blue_hash_lookup` 可对任意路径取哈希（只读，但会暴露路径存在性）。
- 不越界清单：不写改删任何本地状态（I2）、不持久化结果、不做持续监控、不做漏洞利用、不接需要凭据的第三方（I3）、不绕过任何认证。
- 失败面：
  - 主机侧 PowerShell 失败 → `runPs` reject → `safe()` 转 `{ok:false, error:'PowerShell 执行失败: …'}`（拒绝 + 报错）
  - 哈希目标不存在 → 脚本输出 `NOT_FOUND` → 返回 `{ok:true, hash:null}`（render 显示「文件不存在」）——**语义为「查询成功、目标不存在」，不是错误**（正确区分「不存在」与「失败」，符合整体语义纪律）
  - 情报 API 非 2xx → throw → `{ok:false, error:'NVD API HTTP <status>' / 'urlscan.io HTTP <status>'}`（拒绝 + 报错）
  - urlscan.io 无记录 → `{ok:true, ioc:{total:0, results:[]}}`（render：情报盲区提示，非错误）
  - 空结果（无连接/无自启动项/无事件）→ `{ok:true, results:[]}`（**「没有」与「失败」严格分离**）
  - stderr 泄漏面：`runPs` 只取 stdout，PowerShell 的 stderr **被丢弃**——诊断信息损失（§10 U2）
- 权限面：读 `Security` 日志通常需管理员权限；无权限时 `Get-WinEvent` 静默失败（脚本前置 `$ErrorActionPreference='SilentlyContinue'`）→ 表现为**空结果**而非报错（**静默面**，见 U2）。

## 6 · 与既有机制的关系

- **AGENTS.md §5.1（命令准则）的**显式例外**：默认走 WSL2，但本插件属「Windows 权限墙场景」（安全事件日志、注册表、SMB 共享、防火墙配置**只有** Windows 原生 API 可达）——因此全链走 `powershell.exe`，符合 §5.1 的例外条件。
- **AGENTS.md 须请示边界**：本插件**只读**，不触发「删数据/动凭据/动核心引擎」三类须请示项；若未来新增写操作（如自动加固），须先过裁决链。
- **与 `dsh-cyber-range` / `dsh-red-team` 的分工**：攻防分离——本插件不出攻击载荷、不做利用。
- **组合变更纪律（§5.11）**：改源码 = 组合变更，须重建 + 完整预检 + 哨兵重启。
- **生效判据（改代码后怎么证明真的生效）**：
  1. 进程级：`self-plugins/dsh-blue-team/lib/index.js` mtime 必须早于 3080 监听进程启动时间。本轮实测：lib = `2026-08-23 12:17:35`，web（PID 7080）启动 = `2026-09-14 10:05:47` → **已生效**。
  2. 环境级：`powershell.exe` 可用（否则 5 个主机侧工具全废，且**报错是明确的** `PowerShell 执行失败`）。
  3. 工具级：`blue_baseline_check` 返回 5 条 `[PASS|WARN|FAIL|INFO]` 检查行（一次调用即判真假）。
- **回退（出问题怎么退）**：
  1. 组合级：`plugin_stop dsh-blue-team` / 删 patch 行 → 工具面消失；**本插件无破坏性副作用，回退零风险**（I2）。
  2. 情报源回退：NVD/urlscan 若改版不可用 → `intel.ts` 内 `queryUrlhaus`（URLhaus POST 版）**已实现但未接线**，可作为备用源改接线（见 §8 缺口②）。
  3. 代码级：`git -C E:/alice/self-plugins/dsh-blue-team log --oneline` → `git revert <sha>` → `pnpm build` → 预检 → 哨兵重启。

## 7 · 可证伪验收清单

| # | 可证伪命题 | 证据（单测名/命令/日志行/HTTP） | 状态 |
|---|-----------|------------------------------|------|
| A1 | 工具面恰为 8 个（`blue_*`） | 会话工具列表 `blue_` 前缀命中 8；源码 `reg({...})` 计数 = 8 | 已实测（源码计数） |
| A2 | 本机基线可查 | `blue_baseline_check` → `ok:true` 且 `results.length === 5` | **待验收** |
| A3 | 「不存在」≠「失败」（哈希） | `blue_hash_lookup path='C:/__nope__.exe'` → `ok:true, hash:null`（**不是** `ok:false`） | **待验收** |
| A4 | 「没有」≠「失败」（空结果） | `blue_port_scan ports='1'`（本机未监听）→ `ok:true, open:0, results:[]` | **待验收** |
| A5 | 工具不抛异常（I1） | 传非法 `ports='abc'` → 返回 `{ok:false, error:'端口规格无效'}`，调用链不崩 | **待验收** |
| A6 | `enabled:false` 不关工具面 | patch 加 `config: {enabled: false}` → 8 工具**仍可调用**（只少一行日志） | **待验收** |
| A7 | 当前进程加载最新构建 | lib mtime `2026-08-23 12:17:35` < web PID 7080 启动 `2026-09-14 10:05:47` | 已实测（2026-09-14 读数） |
| A8 | 挂载行唯一 | `grep -n "dsh-blue-team" cordis.patch.yml` → 1 命中（行 175） | 已实测 |
| A9 | URLhaus 通道未接线 | `grep -rn "queryUrlhaus" src/` → 命中 `intel.ts` 定义处，`index.ts` **无 import** | 已实测（死代码确认） |
| A10 | 纯逻辑有离线单测且覆盖失败路径 | `npm test` → `tests/logic.test.mjs` **15 例**全过（`resolvePorts`/`parseEventIds`/`psJsonRows`/`psHashOutcome`/`psQuote`；含非法规格、越界、逆序区间、空值、类型不符、损坏 JSON、`NOT_FOUND` 哨兵） | **已实测（2026-09-14，25/25 pass）** |
| A11 | 外来字符串不得逃逸 PS 字面量（注入防线） | `npm test` → `tests/ps-contract.test.mjs`：`assertEscaped` 对 `queryEventLog`/`hashFile` 断言「未转义形态不存在、转义形态存在」；**尸体已取得**（修复前该断言真实失败，见 §9） | **已实测（2026-09-14）** |
| A12 | PS 脚本可离线确定性复现（时间注入） | `npm test` → 同一 `nowMs` 两次 `queryEventLog(...)` 逐字节相同；不同 `nowMs` 必须不同 | **已实测（2026-09-14）** |
| A13 | 限额参数真的进入脚本（防「参数被吞」静默退化） | `npm test` → `auditConnections(7)` 含 `Select-Object -First 7`；`queryEventLog(...,42,...)` 含 `-MaxEvents 42` | **已实测（2026-09-14）** |

## 8 · 与实现的关系

- 主实现：`self-plugins/dsh-blue-team/src/`（4 文件，无同语义副本）。
- 未实现/未验证部分**显式标注**：
  - **缺口① `enabled` 门控失效（已实测）**：`Config.enabled` 只包住末尾 `logger.info`，8 个 `reg()` 在它之前无条件执行 → `enabled:false` 仅少一行日志，**工具面照常全量注册**。与 `dsh-code-search` 的 `enabled` 死字段同类（两处登记，供统一处置）。
  - **缺口② `queryUrlhaus` 未接线（已实测）**：`src/intel.ts:53` 完整实现了 URLhaus 查证（host/url/hash 三态分流），但 `index.ts:13` 只 import 了 `searchCveNvd, queryUrlscan` → 该函数**从装载到运行都不会被调用**。README §已知边界说明了原因（本网络被反爬：空 200），故属**有意保留的备用通道**，但代码里没有注释标注这一点。
  - **缺口③ PowerShell stderr 被丢弃**：`runPs` 只 resolve stdout，`execFile` 回调的 stderr 未取 → 失败原因只剩 `err.message`。
  - **缺口④ 静默空结果**：`$ErrorActionPreference='SilentlyContinue'` + 无权限时 `Get-WinEvent` 无输出 → 表现为「最近 N 天无匹配事件」（与「无权限」不可区分）。
  - **单测（2026-09-14 补课已补）**：`tests/logic.test.mjs`（15）+ `tests/ps-contract.test.mjs`（10）= **25/25 全过**；`npm test` 一条命令可复跑。A2–A6 仍需**真实主机环境**的线上验收（离线单测不能替代），但纯逻辑与注入防线已机器锁死。
  - README 的 ATT&CK 表格与 8 工具**一致**（已逐项核对，无漂移）。

## 9 · 实践修订记录

- **2026-09-14 · PowerShell 注入缺陷（`logName` 未转义，已修 + 加机器守卫）**
  - **症状**：`blue_event_log_query` 的 `logName` 是自由字符串参数，被**原样**插进 PS 单引号字面量
    （`LogName='${logName}'`）。传 `logName = "x'; <任意命令>; '"` 即可闭合字面量并在**当前 PowerShell 上下文**
    执行任意命令——而 `$ErrorActionPreference='SilentlyContinue'` 还会把噪声压掉。
    同文件的 `hashFile` **做了** `'` → `''` 转义，说明作者知道该做，只是漏了一处（**防线只覆盖了一半**）。
  - **证伪证据（修前）**：`node --test "tests/*.test.mjs"` → `tests/ps-contract.test.mjs` 真实失败：
    `AssertionError: queryEventLog: 未转义宿主串原样进入 PS 字面量 → 可逃逸执行任意命令`。
  - **修复**：新增 `src/logic.ts:psQuote()`（单一真源的 PS 单引号转义），`queryEventLog` 的 `logName`
    与 `hashFile` 的 `filePath` 统一走它。
  - **语义被补充（新不变量）**：**任何进入 PS 单引号字面量的外来字符串必须先 `psQuote()`**——
    由 `tests/ps-contract.test.mjs:assertEscaped` 机器守卫，**尸体样本**为修复前的未转义形态。
  - **教训（回写技能 `dsh-plugin-testability`）**：**同类调用点只护住一处 = 半吊子防线**。
    引入转义 helper 后必须 grep 全部「外来串 → PS 字面量」的调用点（本次两处：`logName`/`filePath`），
    并让测试对**每一个**调用点断言——只测一处，另一处会安静地留着。

- **2026-09-14 · 逻辑可测试化（纯函数抽取，零行为变更）**
  - **语义被确认**：`resolvePorts`/`parseEventIds`/`psJsonRows`/`psHashOutcome` 的语义从 `apply()` 闭包
    移入 `src/logic.ts`（无 IO、时间注入）——**行为逐条对齐原实现**（含 `spec` 真值判定、
    `Number('')===0` 不过滤、`JSON.parse(null)===null` 等真实语义，已由测试钉住）。
  - **语义被补充**：`queryEventLog` 新增第 5 参 `nowMs`（缺省 `Date.now()`）——时间注入点，
    使脚本构建可离线确定性断言；**默认行为不变**。
  - **语义被修正（我自己的预期错）**：首版测试断言脚本含 `Id=@(4625,4624)`——实测 id 列表先落
    `$idArr` 变量、过滤表引用 `Id=$idArr`。**预期写错就改预期并把真实语义写进注释**，不是改代码。
  - **行为变更清单（本次唯一一处）**：`queryEventLog` 的 `logName` 由「原样内插」改为「转义后内插」——
    仅影响**含单引号**的输入（此前会语法错误或注入）；正常输入（`Security`/`System`/`Application`）
    产物逐字节不变，已由 A12 的确定性断言覆盖。

- **2026-09-14 补课：本插件此前无语义文档（可维护性工程）**
  - 语义**被确认**：8 工具 ATT&CK 地图；`safe()` 统一错误收敛（I1）；只读优先（I2）；零 key 情报源（I3）；PowerShell 5.1 兼容（I4）；「不存在」与「失败」严格分离。
  - 语义**被补充**：组合挂载点（patch 行 173–175）、消费方技能 `windows-security-hardening:12`、URLhaus「已实现未接线」的真实状态与原因。
  - 语义**被修正**：无（此前无文档）；实测登记 4 处实现级缺口（`enabled` 门控失效 / 死代码 / stderr 丢弃 / 静默空结果）。
  - 教训（同时回写技能 `semantic-doc-first`）：**只读型安全工具的语义重心在「能力边界 ≠ 授权边界」**——不写清这一条，工具会被当成「自带合规」的能力。

## 10 · 未决问题

- **U1 授权纪律是否要技术化**：`blue_port_scan` 目前对任意 host 无限制。倾向**保持不拦**（技术强制会带来误伤且易绕过），但要求调用方在 AGENTS.md/技能层面留痕；是否需要「非私网目标需显式确认参数」？需主人裁决。
- **U2 静默面收口**：PowerShell stderr 丢弃 + `SilentlyContinue` → 「无权限/脚本失败/真的没有」三态同形。倾向：`runPs` 同时收集 stderr，并在 `results` 为空时附 `diagnostics` 字段（§5.22 五问中的「断在哪一段」）。需实现者裁决。
- **U3 情报源冗余**：urlscan 单点（URLhaus 已废）。是否把 `queryUrlhaus` 接成 fallback（urlscan 失败时试 URLhaus）？倾向**接**——已是死代码，接上即为零成本冗余。需裁决。
- **U4 `enabled` 与 `dsh-code-search` 的同类缺口统一处置**：两插件各有 `enabled` 字段但门控语义不同（一个不门控注册、一个只门控日志）。倾向统一为「删除字段，停用只走组合 `disabled`」（§5.19 单点所有权）。需裁决。
- **U5 `parseEventIds('')` 产出 `[0]`（2026-09-14 补课实测登记，未决）**：`Number('')===0` 且 `0` 非 `NaN`，
  故 `eventIds=''` 或含空项（`'4625,,4711'`）会产出 **0**，脚本即查询 `Id=0`——0 不是合法 Windows 事件 ID，
  表现为「静默空结果」而非报错，与 U2 的静默面同源。倾向：过滤 `n > 0` 并对「全被过滤」显式报错。
  **不阻塞本次交付**（真实语义已由 `tests/logic.test.mjs` 钉住，改动即会红）。需裁决。
