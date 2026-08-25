<!--
  DSH 插件生态公约声明（plugin-ecosystem-convention · 组合优先/声明清晰/兼容优先）
  purpose: 蓝队防御插件：资产发现/漏洞评估/威胁检测/日志取证/加固基线（8 工具，ATT&CK 能力地图）
  inject: 'tools'
  tools: blue_*
  runtime: host-only
  envDeps: PowerShell（Windows 宿主）
  boundary: 仅限自有/授权资产的安全评估
  compat: cordis ^4.0.1 / dsh-tools ^0.1.0-rc.6
-->
# dsh-blue-team

蓝队防御插件——**爱丽丝的防御之手**。以 MITRE ATT&CK 为能力地图，覆盖资产发现→漏洞评估→威胁检测→日志取证→加固基线全链路。

## 工具面（8 工具）

| 组 | 工具 | 能力 | ATT&CK 映射 |
|----|------|------|-------------|
| 资产与暴露面 | `blue_port_scan` | 端口/服务扫描（并发 TCP connect） | TA0043 侦察 |
| | `blue_cve_lookup` | CVE 漏洞查询（NVD API v2 免费） | 漏洞评估 |
| 威胁情报 | `blue_ioc_query` | IOC 查证（urlscan.io，恶意标记/分数） | 情报 |
| | `blue_hash_lookup` | 文件 MD5/SHA1/SHA256 哈希（恶意样本比对） | 取证 |
| 主机安全 | `blue_process_audit` | 进程+网络连接审计（可疑监听/外联） | TA0011 C2 |
| | `blue_autoruns_check` | 自启动审计（Run 键/计划任务/服务） | TA0003 持久化 |
| 日志与基线 | `blue_event_log_query` | 安全事件日志（4625/4672/4720/7045/1102 等） | 取证 |
| | `blue_baseline_check` | 安全基线快检（防火墙/共享/RDP/管理员/自动登录） | 加固 |

## 技术路线

- **主机侧**：PowerShell 5.1（`powershell.exe`，本机无 pwsh 7），UTF-8 输出
- **情报侧**：免费公开 API（NVD、urlscan.io），零 API key 起步；URLhaus 在本网络被反爬屏蔽（空 200），已切换 urlscan.io
- **仅限自有/授权资产**的安全评估与防御用途

## 已知边界

- URLhaus API 在当前网络返回空响应（反爬），blue_ioc_query 用 urlscan.io（实测可用）
- 文件哈希的恶意库比对需 VirusTotal 等 key（留接口）
- 端口扫描仅 TCP connect（不做 SYN 半开，需管理员权限且可能误报）

## 使用示例

```
blue_port_scan                            # 本机常见端口扫描
blue_port_scan host="192.168.1.10" ports="1-1000"
blue_cve_lookup keyword="nginx"
blue_process_audit                        # 找可疑监听/外联
blue_autoruns_check                       # 找持久化机制
blue_event_log_query eventIds="4625,4720" days="7"
blue_baseline_check                       # 加固基线
blue_ioc_query value="evil.com"
blue_hash_lookup path="C:\temp\sample.exe"
```
