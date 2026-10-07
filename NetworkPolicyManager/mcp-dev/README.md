# 🛠 DEV MCP · Windows Local Network Policy Manager

> 标识：DEV / 项目开发维护

这个 MCP 只给开发者或 Coding Agent 使用。

它故意没有任何应用/撤销系统网络的工具。

需要实际管理网络时，请使用 mcp-user/。

## 能做什么

- 读取项目基本信息；
- Manager SelfTest；
- Policy Audit；
- 只读验证 / UI Smoke Test；
- TypeScript 检查 User MCP；
- TypeScript 检查 Dev MCP；
- 构建 C# Launcher；
- 生成免安装 ZIP。

## 明确不能做什么

Dev MCP 不暴露 ApplyRule、RemoveRule、SaveRule、ProxyOverride 修改、Existing Route 接管和 RestoreRules。

这是工具层权限隔离，不是提示词约定。

## 安装

Set-Location .\NetworkPolicyManager\mcp-dev
.\setup.ps1
npm run start

需要 Node.js 20+。

## 工具

| Tool | 类型 | 说明 |
| --- | --- | --- |
| dev_project_info | 只读 | README、关键目录和安全边界 |
| dev_manager_self_test | 只读 | PowerShell / 配置自检 |
| dev_policy_audit | 只读 | 回归规则安全审计 |
| dev_run_validation | 测试产物 | test.ps1，可选 UI Smoke |
| dev_typecheck_user_mcp | 只读检查 | mcp-user TypeScript |
| dev_typecheck_dev_mcp | 只读检查 | mcp-dev TypeScript |
| dev_build_launcher | 构建产物 | approved=true |
| dev_package_portable | 构建产物 | approved=true |

## MCP Host 示例

{
  "mcpServers": {
    "windows-network-policy-dev": {
      "command": "cmd.exe",
      "args": [
        "/d",
        "/s",
        "/c",
        "cd /d D:\\path\\windows-local-network-policy-manager\\NetworkPolicyManager\\mcp-dev && npm run start"
      ]
    }
  }
}

## Coding Agent 推荐流程

dev_project_info → 阅读 README / UI_STYLE / 安全文档 → 修改代码 → dev_manager_self_test → dev_policy_audit → dev_typecheck_user_mcp → dev_typecheck_dev_mcp → dev_run_validation → dev_build_launcher → dev_package_portable

不要为了自动化方便把 User MCP 的高风险工具复制进 Dev MCP。
