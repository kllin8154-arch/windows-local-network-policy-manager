# 🟢 USER MCP · Windows Local Network Policy Manager

> 标识：USER / 实际网络策略管理

这个 MCP 给最终用户或日常 AI 助手使用。它可以读取真实 Windows 网络，也可以在严格确认流程下应用或撤销规则。

开发项目请使用相邻的 mcp-dev/。

## 安全工作流

任何真实网络修改固定按以下顺序：

Discover → Audit → 必要时 ExplainAddress → PlanRule → 展示 Diff / Warnings → 用户明确确认 → Apply / Remove + 同一 Fingerprint → TestRule

如果网络状态在 Plan 后发生变化，Fingerprint 会失效，必须重新计划。

## 安装

需要 Windows、Windows PowerShell 5.1 和 Node.js 20+。

PowerShell：

Set-Location .\NetworkPolicyManager\mcp-user
.\setup.ps1
npm run start

## 工具

| Tool | 风险 | 说明 |
| --- | --- | --- |
| network_policy_discover | 只读 | 当前网卡、路由、代理、管理状态 |
| network_policy_audit | 只读 | 重叠、网卡、网关、所有权风险 |
| network_policy_explain_address | 只读 | 输入 IPv4，解释最终 Windows 选路、候选路由、匹配规则与代理绕过 |
| network_policy_list_rules | 只读 | 规则定义 |
| network_policy_plan | 只读 | Apply / Remove 的 Current → Planned Diff、系统变更数与 Fingerprint |
| network_policy_test_rule | 只读 | 规则实际选路诊断 |
| network_policy_create_backup | 低 | 创建安全快照，不改网络 |
| network_policy_list_backups | 只读 | 快照及完整性状态 |
| network_policy_save_rule | 中 | 保存规则定义，不改网络 |
| network_policy_apply_rule | 高 | 修改持久路由/代理绕过 |
| network_policy_remove_rule | 高 | 撤销本程序拥有的网络项 |
| network_policy_restore_rules | 中 | 恢复规则定义，不回放旧路由 |

## USER MCP 特别限制

### 不允许 AI 接管已有路由

network_policy_save_rule 固定 OwnExistingRoute=false、OwnExistingProxy=false。

已有外部路由如需接管，只能在 GUI 自动识别窗口中由用户人工确认。

### 高风险操作必须使用实时 Fingerprint

先调用 network_policy_plan，action=Apply 或 Remove，取得 Fingerprint。

再经用户明确同意后调用 network_policy_apply_rule / network_policy_remove_rule，并提交相同 planFingerprint 与 approved=true。

### 恢复不是旧路由 replay

network_policy_restore_rules 只恢复规则配置；恢复后会清除接管标记。

## MCP Host 示例

{
  "mcpServers": {
    "windows-network-policy-user": {
      "command": "cmd.exe",
      "args": [
        "/d",
        "/s",
        "/c",
        "cd /d D:\\path\\windows-local-network-policy-manager\\NetworkPolicyManager\\mcp-user && npm run start"
      ]
    }
  }
}

只需要诊断时可用普通权限启动 Host。需要 Apply/Remove 时，Host 必须处于管理员权限环境；即使有管理员权限，仍必须满足 Plan Fingerprint + approved=true。

## AI 行为要求

- 优先解释现状，不急于修改；
- 有 Warning 时明确告诉用户；
- 有 Critical/Error 时不执行；
- 规则重叠时说明最长前缀优先；
- 不建议“一键接管全部未知路由”；
- Apply 后必须 TestRule；
- 批量修改前先 CreateBackup。

完整安全模型：../../docs/SAFETY_BACKUP_RECOVERY.md
