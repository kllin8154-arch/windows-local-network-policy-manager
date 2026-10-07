# MCP INDEX

本项目将 MCP 明确拆成两套。不要混用角色。

## 🟢 USER MCP — 实际使用网络策略

目录：NetworkPolicyManager/mcp-user/

标识：windows-local-network-policy-manager-user

用途：
- 发现当前网络；
- 审计规则风险；
- 查询/诊断规则；
- 创建与查看安全快照；
- 保存普通规则定义；
- 经 Plan Fingerprint + 用户批准后应用/撤销；
- 安全恢复规则定义。

限制：
- 不暴露 OwnExistingRoute / OwnExistingProxy；
- 不允许 AI 直接接管扫描到的外部路由；
- Apply / Remove 必须先 Plan；
- 恢复规则不会回放旧系统路由。

完整说明：mcp-user/README.md

---

## 🛠 DEV MCP — 开发与维护项目

目录：NetworkPolicyManager/mcp-dev/

标识：windows-local-network-policy-manager-dev

用途：
- SelfTest；
- Policy Audit；
- 只读验证 / UI Smoke Test；
- User / Dev MCP TypeScript 检查；
- 构建 EXE；
- 构建免安装包。

明确禁止：
- 不提供 ApplyRule；
- 不提供 RemoveRule；
- 不提供 ProxyOverride 修改；
- 不提供 Existing Route 接管。

完整说明：mcp-dev/README.md

---

## ⚠ LEGACY MCP

目录：NetworkPolicyManager/mcp/

这是早期单体 MCP，为兼容旧配置暂时保留。新配置请迁移到 mcp-user 或 mcp-dev。

## 为什么必须拆开

用户 MCP 的主要风险是改错系统网络；开发 MCP 的主要风险是 Coding Agent 在开发过程中顺手调用了系统网络写工具。

因此不能只靠提示词约束，必须在工具暴露层直接隔离。
