<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: 蓝队防御插件：以 MITRE ATT&CK 为能力地图的防御侧工具面 8 工具——资产发现（port scan）/漏洞评估（NVD CVE）/威胁情报（urlscan IOC）/主机取证（哈希/进程审计/事件日志/自启动）/加固基线，全部经 safe() 收敛为 {ok,error} 不抛异常
  inject: 'tools'
  tools: blue_port_scan,blue_cve_lookup,blue_hash_lookup,blue_ioc_query,blue_process_audit,blue_autoruns_check,blue_event_log_query,blue_baseline_check
  runtime: host-only
  envDeps: Windows powershell.exe（5 个主机侧工具）+ 网络可达 NVD API / urlscan.io（情报类）；不依赖 pwsh 7、不需要任何 API key
  boundary: blue_port_scan 可扫任意 host（无白名单/授权校验）——「仅自有/授权资产」是使用纪律不由插件技术强制；全部工具只读（无写/改/删本地状态）
  compat: cordis ^4.0.1 / schemastery ^3.18.1-rc.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-blue-team

<p align="center">
  <a href="https://github.com/jonah791/dsh-blue-team"><img src="https://img.shields.io/badge/version-0.1.2-blue" alt="version"></a>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/TypeScript-3178C6" alt="TypeScript">
  <img src="https://img.shields.io/badge/tests-44%20passed-brightgreen" alt="tests">
</p>

**一句话**：以 MITRE ATT&CK 为能力地图的**防御侧**工具面（8 工具）——从「这台机器有什么暴露面」到「有没有被动过的痕迹」，资产发现 → 漏洞评估 → 威胁情报 → 主机取证 → 加固基线一次查完。

**为什么值得用**：Windows 主机的安全取证离不开 PowerShell 原生 API，而裸手写 PS 脚本有三个坑——**注入**（外来字符串进单引号字面量）、**静默**（`SilentlyContinue` 把失败吞成空结果）、**难读**（原文本输出）。本插件把这三件事都做了工程化处理：转义统一走 `psQuote()` 且有机器守卫、结果统一 `ConvertTo-Json` 结构化后再渲染、每次调用落一行 `blue-team-trace.jsonl` 自证轨迹（查了什么/命中几条/断在哪/花了多久）。

> ⚠ **仅用于自有/授权资产**：本插件不做技术强制（见「边界与信任」），授权纪律由调用者承担。攻击/利用侧能力在 `dsh-red-team` / `dsh-exploit-kit`，本插件只防御。

## 能力

| 工具 | 用途（ATT&CK 战术） |
|------|---------------------|
| `blue_port_scan` | 端口/服务扫描（TCP connect，并发 200，默认本机 44 常见端口）。资产暴露面盘点（侦察 TA0043） |
| `blue_cve_lookup` | CVE 漏洞查询（NVD API v2 免费）：按软件名/关键词查已知漏洞，返回 CVE ID/CVSS/严重性/描述/受影响 CPE（漏洞评估） |
| `blue_hash_lookup` | 计算文件 MD5/SHA1/SHA256 哈希，供恶意库比对/完整性基线；目标不存在返回 `ok:true, hash:null`（**「不存在」≠「失败」**） |
| `blue_ioc_query` | IOC 威胁情报查证（urlscan.io 免费）：域名/URL 的 malicious 判定/分数/历史扫描记录 |
| `blue_process_audit` | 进程 + 网络连接审计：监听端口与外部连接含所属进程（可疑监听/异常外联 = C2 信号，TA0011） |
| `blue_autoruns_check` | 自启动审计：注册表 Run 键 ×5 / 计划任务（≤40）/ 自启动服务（≤30）——持久化检测（TA0003） |
| `blue_event_log_query` | Windows 安全事件日志查询：经典事件 ID（4625 登录失败/4672 提权/4720 新用户/7045 新服务/1102 日志清除/4104 脚本块等 10 类），检测入侵痕迹 |
| `blue_baseline_check` | 安全基线快检 5 项：防火墙状态/非默认共享/RDP 开启/管理员组成员/自动登录，输出 `[PASS|WARN|FAIL|INFO]` 行（加固 TA0004 起点） |

## 快速开始

**1) 装依赖**：

```jsonc
"dsh-blue-team": "link:<工作区>/self-plugins/dsh-blue-team"
```

**2) 挂组合**（无必配项；`enabled` 只门控一行日志，不门控工具注册）：

```yaml
- id: agent-blue-team
  name: dsh-blue-team
```

**3) 30 秒验证**：调 `blue_baseline_check` → 期望返回 5 行 `[PASS/WARN/FAIL/INFO]` 检查结果；调 `blue_port_scan {ports:'1', host:'127.0.0.1'}` → 期望 `ok:true, open:0`（「没有」≠「失败」）。若报 `PowerShell 执行失败`，说明环境无 `powershell.exe`。

## 配置

| 项 | 默认 | 说明 |
|----|------|------|
| `enabled` | `true` | 门控装载末尾的 ready 日志。**已知缺口：不门控工具注册**（8 工具照常全量注册）——停用请用组合级 `disabled: true`（与 `dsh-code-search` 同款缺口，统一处置中） |

## 落盘与自证（出问题时先看这里）

每次工具调用落两行 JSONL 到 **`<DSH_HOME>/blue-team-trace.jsonl`**（一次调用 = `begin` → `end`；写盘吞错返回 `false`，绝不反噬调用）：

| 字段 | 含义 |
|------|------|
| `atMs` / `phase` | 写入时刻；阶段枚举 `begin`/`end` |
| `action` / `build` | 动作 = 工具名；`build` = `<版本>@<lib mtime ms>`（① 线上跑的是哪个构建） |
| `pid` / `target` | 进程 pid；调查对象（host/path/value/domain，截断 120 字符） |
| `query` | 查询摘要（脱敏：log/ids/days/limit/ports 保留；hash/password/user/token 类只记 `<N chars>`） |
| `durationMs` | `begin`=0；`end`=全程实耗（⑤ 耗时） |
| `ok` / `count` / `resultBytes` | 工具返回的 `ok`；命中条数（④ 结果质量）；结果 JSON 字节量级——**只记量级，绝不落结果正文**（蓝队结果天然含哈希原文/管理员名） |
| `break` / `error` | 仅 `ok=false`：断点分类（③ 断在哪一段）+ 已 `scrub` 的截断 200 字符错误 |

**一条命令答五问**：

```bash
tail -3 "$DSH_HOME/blue-team-trace.jsonl"
# ① 跑的是哪个构建 → build = "<版本>@<lib/index.js mtime ms>"
# ② 谁发起/调了什么 → action（工具名）+ target + query 摘要
# ③ 断在哪一段      → break 分类：empty / ps-timeout / ps-spawn / ps-exit / json / not-found / bad-args / other
# ④ 结果质量        → count（命中条数，0 是合法值）+ resultBytes（量级，正文不落盘）
# ⑤ 耗时           → end 行的 durationMs
```

诚实声明：轨迹**没有 `exitCode` 字段**——`runPs()` 把子进程错误折叠成字符串，数字退出码在到达返回值前已丢失；以 `break: 'ps-exit'` 表达子进程失败（见 `docs/semantic.md` §10 U6）。

## 生效判据与回退

**生效判据**（三选一，按可靠性排序）：
1. `lib/index.js` 的 mtime**早于** web 进程（3080 监听进程）的启动时间 ⇒ 进程在跑当前构建；
2. 生态级：`plugin_boot_status`（`dsh-plugin-bootreport`）返回 `liveNow` 含本插件；
3. 行为级：`blue_baseline_check` 返回 5 条 `[PASS|WARN|FAIL|INFO]` 行（一次调用即判真假）。

> 注意：**重新构建 ≠ 生效**——产物 mtime 新只证明「构建过」，进程启动时间晚于产物 mtime 才算「在跑它」。

**回退**（三档，均零风险——本插件全只读，无破坏性副作用）：
- 源码级：`git -C self-plugins/dsh-blue-team revert <commit>` → 重新构建 → 预检 → 哨兵重启；
- 组合级：preset 给 `agent-blue-team` 行加 `disabled: true`（或删行）→ 工具面消失，没有任何状态残留；
- 运行期：无持久业务状态（结果只回模型不落库；轨迹文件可随时删除）。

## 测试

```bash
npm test        # = node --test "tests/*.test.mjs"
```

**44 例离线测试**（`tests/logic.test.mjs` 15 + `tests/ps-contract.test.mjs` 10 + `tests/trace.test.mjs` 19），覆盖：
- `logic.test.mjs` — 纯逻辑：端口规格解析（非法/越界/逆序区间）、事件 ID 解析、`psJsonRows`/`psHashOutcome`（损坏 JSON、`NOT_FOUND` 哨兵）、`psQuote`；
- `ps-contract.test.mjs` — **注入防线尸体测试**：外来字符串不得逃逸 PowerShell 字面量（每条命令的转义形态断言）、PS 脚本离线确定性复现（时间注入）、限额参数真进脚本；
- `trace.test.mjs` — 轨迹层：**隐私尸体测试**（哈希原文/管理员名/错误文本里的凭据绝不落盘）、`count` 三来源投影、断点分类、坏行容错、观测不反噬（不可写路径 → `false` 且不抛、异常原样重抛）。

**无网络、无 PowerShell、无真实主机依赖**（子进程与 API 均以桩替代；PowerShell 注入防线直接把生成脚本与期望转义形态对拍）。跑通业务才需要 `powershell.exe`（Windows 5.1 语法）+ 网络可达 NVD/urlscan.io。

## 设计要点

- **psQuote 单一真源（安全边界）**：任何进入 PowerShell 单引号字面量的外来字符串**必须先转义**（`'` → `''`）。历史上 `hashFile` 转义了而 `logName` 漏掉——防线只覆盖一半＝没有防线。现在凭 `assertEscaped` 对**每个**调用点机器守卫，尸体样本就是修复前的未转义形态。
- **`safe()` 收敛 + 语义分离**：所有异常收敛为 `{ok:false, error}`，工具永不抛（I1）；「文件不存在」是 `ok:true, hash:null`，「没有记录」是 `ok:true, results:[]`——**「没有」与「失败」严格分离**，不是把失败粉饰成空结果（静默面见语义文档 §10 U2）。
- **零 key 情报源**：NVD + urlscan.io 均免费无 key；URLhaus 通道已实现但保持未接线（备用源）。**不引入需要凭据的第三方**。
- **能力边界 ≠ 授权边界**：`blue_port_scan` 能扫任意 host，插件不拦——「仅自有/授权资产」是使用纪律。把合规责任写进工具描述（模型可见），不假装技术强制。
- **只读铁律**：8 工具无任何写/改/删本地状态的操作；唯一「离开本机」的行为是端口扫描的对外连接。未来若加自动加固类写操作，须先过「删数据」裁决链。
- **观测只记形状不记正文**：轨迹记 `count`/`resultBytes` 量级；`error` 落盘前过 `scrub()`——因为 `runPs` 的错误文本会携带**整条 PowerShell 脚本**（含 path/logName），这是本插件最大的泄漏面。

## 相关文档

| 文档 | 内容 |
|------|------|
| [`docs/semantic.md`](docs/semantic.md) | **权威契约**：定位与反定位、8 工具契约（含默认值/超时）、轨迹行 schema、边界与信任（能力≠沙箱）、可证伪验收清单（A1–A20）、实践修订记录（PS 注入缺陷 + 轨迹层）、未决问题（U1–U7） |
| [alice-digital-life](https://github.com/jonah791/alice-digital-life) | 本插件所属生态的中心索引（全部自研插件） |
| 技能 `windows-security-hardening` | 设备安全加固方法论（本插件的消费方：加固流程第一步 = 跑本插件的基线/审计工具） |
| 技能 `cyber-range` | 攻防靶场方法论（红队视角的互补知识；本插件是其防御侧对偶） |
| 技能 `plugin-maintainability` | 插件可维护性工程（自证轨迹 / 注入防线尸体测试 / 离线可测化） |

## License

MIT © jonah791

---

本插件属于我的数字生命爱丽丝（[alice-digital-life](https://github.com/jonah791/alice-digital-life)）的 DSH 自研插件生态。