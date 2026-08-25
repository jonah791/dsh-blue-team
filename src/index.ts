/** dsh-blue-team：蓝队防御插件
 *  资产发现/漏洞评估/威胁检测/日志取证/加固基线 —— 8 工具，ATT&CK 能力地图
 *  仅用于自有/授权资产的安全评估与防御
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { scanPorts, parsePorts, DEFAULT_PORTS } from './net.js'
import {
  runPs, auditConnections, auditAutoruns, queryEventLog, baselineCheck, hashFile,
} from './host.js'
import { searchCveNvd, queryUrlscan } from './intel.js'

export const name = 'dsh-blue-team'
export const inject = ['tools'] as const

export interface Config { enabled: boolean }
export const Config = z.object({ enabled: z.boolean().default(true) })

const EVENT_IDS: Record<number, string> = {
  4625: '登录失败(暴力破解信号)', 4624: '登录成功', 4672: '特权登录(管理员)',
  4720: '创建新用户', 4726: '删除用户', 4732: '用户加入组', 7045: '安装新服务',
  1102: '安全日志被清除(攻击信号)', 4698: '创建计划任务', 4104: 'PowerShell 脚本块',
}

export function apply(ctx: Context, config: Config): void {
  const logger = ctx.logger('blue-team')
  const reg = (tool: any) => ctx.tools.register(defineTool(tool as any))
  const safe = async <T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> => {
    try { return { ok: true, value: await fn() } }
    catch (e: any) { return { ok: false, error: String(e?.message ?? e) } }
  }
  const baseProps: Record<string, any> = {
    ok: { type: 'boolean', required: true }, error: { type: 'string' }, note: { type: 'string' },
  }
  const rows = (v: any, fields: string[] = []) => (v.results ?? []).map((r: any, i: number) =>
    `  ${i + 1}. ${fields.map((f) => r[f]).filter(Boolean).join(' | ')}`).join('\n')

  /* ── 1 · blue_port_scan：端口/服务扫描（资产发现 TA0007/TA0043） ── */
  reg({
    name: 'blue_port_scan',
    description: '端口/服务扫描（TCP connect，并发）：资产暴露面盘点。仅限自有/授权资产。默认扫描本机常见端口；可指定目标主机与端口范围。',
    parameters: {
      host: { type: 'string', description: '目标主机（IP/主机名，默认 127.0.0.1 本机）' },
      ports: { type: 'string', description: '端口规格："22,80,443" / "1-1000" / 混合（默认常见端口 ~44 个）' },
      timeout: { type: 'number', description: '单端口超时 ms（默认 1000）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, host: { type: 'string' }, scanned: { type: 'number' }, open: { type: 'number' }, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '扫描失败' }]
        if (!v.open) return [{ type: 'text', text: `未发现开放端口（扫描 ${v.scanned} 个，目标 ${v.host}）` }]
        return [{ type: 'text', text: `目标 ${v.host}：发现 ${v.open} 个开放端口\n${rows(v, ['port', 'service'])}` }]
      },
    },
    async execute(args: any) {
      const host = String(args.host ?? '127.0.0.1')
      const ports = args.ports ? parsePorts(String(args.ports)) : DEFAULT_PORTS
      if (!ports.length) return { ok: false, error: '端口规格无效' }
      const r = await safe(() => scanPorts(host, ports, Number(args.timeout ?? 1000)))
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, host, scanned: ports.length, open: r.value.length, results: r.value }
    },
  })

  /* ── 2 · blue_cve_lookup：CVE 漏洞查询（漏洞评估） ── */
  reg({
    name: 'blue_cve_lookup',
    description: 'CVE 漏洞查询（NVD API v2 免费）：按软件名/关键词查已知漏洞，返回 CVE ID/CVSS 分数/严重性/描述/受影响 CPE。漏洞评估用。',
    parameters: {
      keyword: { type: 'string', required: true, description: '软件名或关键词（如 "nginx"、"openssl 3.0"）' },
      limit: { type: 'number', description: '条数上限（默认 10，最大 20）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '查询失败' }]
        if (!v.results?.length) return [{ type: 'text', text: '未找到相关 CVE' }]
        return [{ type: 'text', text: v.results.map((c: any) =>
          `[${c.id}] CVSS ${c.cvss ?? 'N/A'} (${c.severity}) ${c.published}\n   ${c.description}`).join('\n') }]
      },
    },
    async execute(args: any) {
      const r = await safe(() => searchCveNvd(String(args.keyword), Number(args.limit ?? 10)))
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, results: r.value }
    },
  })

  /* ── 3 · blue_hash_lookup：文件哈希计算（完整性/恶意样本比对） ── */
  reg({
    name: 'blue_hash_lookup',
    description: '计算文件 MD5/SHA1/SHA256 哈希（可后续比对已知恶意库/完整性基线）。取证与恶意软件检测用。',
    parameters: {
      path: { type: 'string', required: true, description: '文件绝对路径' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, hash: { type: 'object', additionalProperties: true } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '计算失败' }]
        const h = v.hash
        if (!h) return [{ type: 'text', text: '文件不存在' }]
        return [{ type: 'text', text: `文件: ${h.Path}\n大小: ${h.Size} B\nMD5:   ${h.MD5}\nSHA1:  ${h.SHA1}\nSHA256:${h.SHA256}` }]
      },
    },
    async execute(args: any) {
      const p = String(args.path ?? '')
      if (!p) return { ok: false, error: 'path 必填' }
      const r = await safe(async () => {
        const out = await runPs(hashFile(p))
        if (out === 'NOT_FOUND') return null
        return JSON.parse(out)
      })
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, hash: r.value }
    },
  })

  /* ── 4 · blue_ioc_query：IOC 威胁情报查证 ── */
  reg({
    name: 'blue_ioc_query',
    description: 'IOC 威胁情报查证（urlscan.io 免费）：输入域名/URL，查是否被公开扫描记录标记为恶意（malicious 判定/分数/历史扫描）。',
    parameters: {
      value: { type: 'string', required: true, description: 'IOC：域名或 URL（如 evil.com、http://x.y/payload）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, ioc: { type: 'object', additionalProperties: true } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '查询失败' }]
        const i = v.ioc ?? {}
        if (!i.total) return [{ type: 'text', text: 'urlscan.io 无该域名的扫描记录（未被公开分析，或情报盲区）' }]
        const lines = [`urlscan.io 命中 ${i.total} 条扫描记录:`]
        for (const r of i.results ?? []) {
          lines.push(`  ${r.malicious ? '⚠ 恶意标记' : '· 未见恶意'} score=${r.score ?? '-'}  ${r.time}\n      ${r.url}`)
        }
        return [{ type: 'text', text: lines.join('\n') }]
      },
    },
    async execute(args: any) {
      const v = String(args.value ?? '').trim()
      if (!v) return { ok: false, error: 'value 必填' }
      const r = await safe(() => queryUrlscan(v))
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, ioc: r.value }
    },
  })

  /* ── 5 · blue_process_audit：进程 + 网络连接审计（威胁检测 TA0009/TA0011） ── */
  reg({
    name: 'blue_process_audit',
    description: '进程 + 网络连接审计：列出监听端口与外部连接（含所属进程）。发现可疑监听/异常外联（C2 信号）。',
    parameters: { limit: { type: 'number', description: '返回条数上限（默认 200）' } },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '审计失败' }]
        if (!v.results?.length) return [{ type: 'text', text: '无监听/连接记录' }]
        return [{ type: 'text', text: '状态 | 本地 | 远程 | 进程\n' + v.results.map((r: any) =>
          `  ${r.State}  ${r.Local}  ${r.Remote}  ${r.Proc}(${r.PID})`).join('\n') }]
      },
    },
    async execute(args: any) {
      const r = await safe(async () => {
        const out = await runPs(auditConnections(Number(args.limit ?? 200)))
        if (!out) return []
        const parsed = JSON.parse(out)
        return Array.isArray(parsed) ? parsed : [parsed]
      })
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, results: r.value }
    },
  })

  /* ── 6 · blue_autoruns_check：自启动审计（持久化检测 TA0003） ── */
  reg({
    name: 'blue_autoruns_check',
    description: '自启动审计：注册表 Run 键 / 计划任务 / 自启动服务。发现持久化机制（恶意软件常驻信号）。',
    parameters: { limit: { type: 'number', description: '返回条数上限（默认 100）' } },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '审计失败' }]
        if (!v.results?.length) return [{ type: 'text', text: '未发现自启动项' }]
        return [{ type: 'text', text: v.results.map((r: any) =>
          `  [${r.Type}] ${r.Name}\n      ${r.Command} (${r.Source})`).join('\n') }]
      },
    },
    async execute(args: any) {
      const r = await safe(async () => {
        const out = await runPs(auditAutoruns(Number(args.limit ?? 100)))
        if (!out) return []
        const parsed = JSON.parse(out)
        return Array.isArray(parsed) ? parsed : [parsed]
      })
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, results: r.value }
    },
  })

  /* ── 7 · blue_event_log_query：安全事件日志查询（日志取证） ── */
  reg({
    name: 'blue_event_log_query',
    description: 'Windows 安全事件日志查询：经典事件 ID（4625 登录失败/4672 提权/4720 新用户/7045 新服务/1102 日志清除等）。检测入侵痕迹。',
    parameters: {
      eventIds: { type: 'string', description: '事件 ID 逗号分隔（默认 4625,4624,4672,4720,7045,1102）' },
      days: { type: 'number', description: '查询最近 N 天（默认 7）' },
      logName: { type: 'string', description: '日志名（Security/System/Application，默认 Security）' },
      limit: { type: 'number', description: '条数上限（默认 100）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '查询失败' }]
        if (!v.results?.length) return [{ type: 'text', text: `最近 ${v.days} 天无匹配事件（ID: ${v.eventIds}）` }]
        return [{ type: 'text', text: v.results.map((r: any) => {
          const hint = EVENT_IDS[Number(r.Id)]
          return `  ${r.Time}  [${r.Id}] ${r.Level}${hint ? ` ${hint}` : ''}\n      ${r.Msg}`
        }).join('\n') }]
      },
    },
    async execute(args: any) {
      const ids = String(args.eventIds ?? '4625,4624,4672,4720,7045,1102').split(',').map(Number).filter((n) => !Number.isNaN(n))
      const days = Number(args.days ?? 7)
      const log = String(args.logName ?? 'Security')
      const limit = Number(args.limit ?? 100)
      const r = await safe(async () => {
        const out = await runPs(queryEventLog(ids, days, log, limit))
        if (!out) return []
        const parsed = JSON.parse(out)
        return Array.isArray(parsed) ? parsed : [parsed]
      })
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, eventIds: ids.join(','), days, results: r.value }
    },
  })

  /* ── 8 · blue_baseline_check：安全基线快检（加固） ── */
  reg({
    name: 'blue_baseline_check',
    description: '安全基线快检：防火墙状态/非默认共享/RDP 开启/管理员组成员/自动登录。发现加固缺口。',
    parameters: {},
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: { ...baseProps, results: { type: 'array', items: { type: 'object', additionalProperties: true } } },
      },
      render: (_a: any, v: any) => {
        if (!v.ok) return [{ type: 'text', text: v.error ?? '检查失败' }]
        if (!v.results?.length) return [{ type: 'text', text: '无检查项' }]
        return [{ type: 'text', text: v.results.map((r: any) =>
          `  [${r.Status}] ${r.Check}\n      ${r.Detail ?? ''}`).join('\n') }]
      },
    },
    async execute() {
      const r = await safe(async () => {
        const out = await runPs(baselineCheck())
        if (!out) return []
        const parsed = JSON.parse(out)
        return Array.isArray(parsed) ? parsed : [parsed]
      })
      if (!r.ok) return { ok: false, error: r.error }
      return { ok: true, results: r.value }
    },
  })

  if (config.enabled) {
    logger.info('蓝队工具面就绪（8 工具）')
  }
}
