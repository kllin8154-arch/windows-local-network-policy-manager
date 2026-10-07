# 优化方向与优先级

## P0：安全与可恢复性

本次已经落实：

- 变更前自动安全快照；
- SHA256 快照完整性校验；
- 规则/状态 JSON 原子写入；
- GUI / CLI / MCP 共用单写锁；
- Apply / Remove 两阶段 Plan Fingerprint；
- 默认路由 0.0.0.0/0 硬保护；
- CIDR 重叠规则审计；
- 安全恢复规则定义，且恢复时清除已有路由/代理的所有权声明；
- 自动保留最近 50 个安全快照。

下一步建议：

1. 增加“安全中心”UI：集中显示 Audit、最近快照、完整性状态、状态漂移与恢复 Diff。
2. 启动时发现 manager-state 与真实 Windows 路由不一致时进入“修复模式”，不自动猜测或修复。
3. 为 network-rules.json / manager-state.json 增加 SchemaVersion 与显式迁移。
4. 正式发布时增加 Authenticode 或至少 Release SHA256 清单。

## P1：复杂规则的可理解性

规则数量增加后，仅靠搜索和普通状态筛选仍不足以解释最终选路。建议：

- 已完成：输入单个 IPv4 后解释最长前缀候选、Windows 最终路由、匹配规则和精确代理绕过；
- 已完成：GUI / CLI / User MCP 共用选路解释与 Current → Planned Diff；
- 已完成：GUI 单条 Apply/Remove 使用 Plan Fingerprint，批量 Apply 先计划并在计划失效后停止；
- 进行中：把异常进一步拆分为外部冲突、内部重叠、网卡不可用、网关不可用、状态漂移；
- 待完成：规则优先级树形视图，例如 172.16.0.0/16 > 172.16.11.0/24 > 172.16.11.25/32；
- 已完成：规则分组/标签，支持老规则无迁移读取、分组/标签搜索、分组筛选和安全的整组 Plan；GUI 分组批量应用仍逐条校验 Fingerprint。

## P1：MCP 与 AI 安全边界

本次拆成两套独立 MCP：

- NetworkPolicyManager/mcp-user：最终用户/AI 实际管理网络；
- NetworkPolicyManager/mcp-dev：开发者/Coding Agent 维护项目；
- NetworkPolicyManager/mcp：旧版兼容目录，后续淘汰。

后续原则：

- User MCP 的高风险写操作必须 Plan Fingerprint + 用户明确批准；
- Dev MCP 永远不加入 ApplyRule / RemoveRule；
- 批量 AI 操作后续应增加单次最大规则数；
- 日志后续增加 Source=GUI|USER_MCP|CLI，便于审计。

## P2：代码架构

当前核心 PowerShell 文件已经较大，建议逐步拆成：

Core/Adapter.ps1、Route.ps1、Proxy.ps1、Rule.ps1、Audit.ps1、Safety.ps1、State.ps1，
以及 UI/MainWindow.ps1、DiscoveryDialog.ps1、SafetyCenter.ps1。

拆分原则：先抽纯函数和安全模块，再拆 UI，不进行一次性大重写。

## P2：测试体系

建议补充：

- CIDR 重叠单元测试；
- 默认路由保护测试；
- OwnExistingRoute 所有权测试；
- ProxyOverride 多规则共享测试；
- 快照损坏/跨机器恢复测试；
- GUI 与 MCP 并发写测试；
- 中断写文件恢复测试；
- 100/125/150/175% DPI UI Smoke Test。

## 不建议做

- 不默认修改系统默认路由；
- 不让 AI 自动接管扫描到的未知外部路由；
- 不把 manager-state.json 当作 Windows 真实状态；
- 不用恢复旧 manager-state.json 的方式“恢复网络”；
- 不把 Node.js、MCP 或大模型强行打进普通用户免安装包。
