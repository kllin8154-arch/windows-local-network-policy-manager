# 网络策略安全、备份与恢复设计

## 1. 总体原则

网络策略属于高影响配置。正确流程固定为：

发现真实状态 → 审计 → 生成计划 → 用户确认 → 创建快照 → 执行 → 再验证。

规则文件表示“希望系统怎么走”，manager-state.json 表示“管理器认为自己拥有了什么”，Windows 实际路由/代理状态才是事实来源。

## 2. 三类状态严格分开

### 规则定义

文件：NetworkPolicyManager/network-rules.json。

### 管理器所有权状态

文件：NetworkPolicyManager/manager-state.json。

它只记录管理器创建或明确接管的路由/代理项，不能作为 Windows 路由表的备份。

### Windows 真实状态

每次通过 Get-NetAdapter、Get-NetIPAddress、Get-NetRoute 和 WinINET ProxyOverride 重新读取。

## 3. 安全快照

目录：NetworkPolicyManager/backups/。

每个快照包含：

- 当前规则定义；
- 当前 manager state；
- 当前规则相关的真实路由；
- 当前默认路由（只记录，不管理）；
- 当前 ProxyOverride；
- 机器名、用户、时间、原因、关联 RuleId。

每个 JSON 对应一个 .sha256 文件。默认保留最近 50 份。

自动创建时机：Apply 前、Remove 前、CLI/MCP SaveRule 前、RestoreRules 前。

## 4. 为什么恢复规则和恢复系统网络必须分开

直接回放旧路由表非常危险，因为网卡 InterfaceIndex、VPN、Hiddify、USB 网卡、第三方路由、ProxyOverride 都可能已变化。

因此当前自动恢复只恢复规则定义，不直接恢复旧 Windows 路由。RestoreRules 还会：

- 校验 SHA256；
- 拒绝其他计算机生成的快照；
- 先备份当前状态；
- 清除 OwnExistingRoute / OwnExistingProxy；
- 不覆盖当前 manager-state.json；
- 恢复后要求重新 Audit / Plan。

## 5. 高风险操作保护

### 默认路由保护

0.0.0.0/0 为硬保护目标，规则配置直接拒绝。

### 外部已有路由

同目标存在不同网卡/网关时默认拒绝覆盖；只有管理器之前确实拥有的旧路由才允许替换。

扫描发现的外部路由不会自动接管。

### ProxyOverride

撤销代理绕过前必须确认该 token 由管理器拥有，并检查是否仍有其他规则使用。

### 并发写

GUI、CLI、MCP 共用命名 Mutex。同一时刻只允许一个写操作，最多等待 15 秒。

## 6. Plan Fingerprint

高风险操作采用两阶段执行：

1. PlanRule 读取实时网络，输出期望网卡、网关、已有路由、代理状态、Warnings、Errors 和 Fingerprint。
2. 用户查看计划并确认。
3. ApplyRule / RemoveRule 提交同一个 Fingerprint。

Fingerprint 绑定规则关键字段、网卡 GUID/Index/Status、解析网关、同目标路由、ProxyOverride 和 manager ownership state。

任何相关状态在 Plan 后变化，旧 Fingerprint 都会失效，必须重新计划。

## 7. 规则重叠

CIDR 重叠不一定是错误，例如：172.16.0.0/16、172.16.11.0/24、172.16.11.25/32。Windows 使用最长前缀优先。

当前策略：

- 完全重复目标：禁止保存；
- 重叠且同出口：Info；
- 重叠但不同出口：Warning；
- 真实系统同目标存在不同出口：Apply 时 Conflict 并拒绝。

## 8. 常见异常及应对

| 情况 | 应对 |
| --- | --- |
| 网卡名称变化 | 优先硬件 GUID，Description 仅回退 |
| InterfaceIndex 变化 | 每次实时解析，不持久依赖旧 Index |
| 网线断开 | Audit / Plan 告警或拒绝 |
| Auto 网关不存在 | Error，不执行 |
| 同目标存在外部路由 | Conflict，拒绝覆盖 |
| 规则网段重叠 | Audit 告警，按最长前缀解释 |
| GUI 与 MCP 同时修改 | 单写锁 |
| JSON 写入时进程中断 | 临时文件 + 原子替换 |
| 快照被改/损坏 | SHA256 失败，拒绝恢复 |
| 快照来自其他电脑 | 拒绝自动恢复 |
| manager-state 丢失 | 不猜测所有权，重新发现并人工确认 |
| ProxyOverride 被其他软件修改 | Fingerprint 失效，重新 Plan |
| 删除程序但持久路由仍在 | 删除前必须先撤销管理器拥有的规则 |

## 9. 推荐日常流程

普通操作：启动 → Discover → Audit → 搜索/筛选 → Plan → 查看 Changes/Warnings → 用户确认 → 自动快照 → Apply/Remove → TestRule。

批量变更：先 CreateBackup；Audit 必须无 Critical/Error；小批量执行；每批后重新 Discover；不要让 AI 一次接管大量未知外部路由。

## 10. CLI

创建安全快照：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command CreateBackup

列出快照：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command ListBackups

恢复规则定义（不直接改系统网络）：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command RestoreRules -BackupId <id> -Approved

审计：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command Audit

生成 Apply 计划：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command PlanRule -RuleId <id> -Action Apply

带 Fingerprint 执行：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\本地网络策略管理器.ps1 -Command ApplyRule -RuleId <id> -ExpectedFingerprint <fingerprint> -Approved
