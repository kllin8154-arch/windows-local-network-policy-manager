# Windows Local Network Policy Manager MCP

这个 MCP 服务把“本地网络策略管理器”的同一套 PowerShell 核心能力暴露给支持 MCP 的 AI 客户端。

## 设计原则

- AI 先读取当前机器状态，再提出或保存规则。
- 自动发现不会自动接管系统里原有的路由。
- 保存规则不会立即修改 Windows 路由。
- 真正应用/撤销必须显式传入 `approved=true`。
- 应用/撤销仍由主程序执行，所以沿用原有的冲突检测、所有权判断和回滚逻辑。
- MCP 进程若不是管理员权限，修改路由的工具会失败；读取、发现和测试仍可使用。

## 环境

需要 Windows 和 Node.js 20+。

```powershell
Set-Location .\NetworkPolicyManager\mcp
.\setup.ps1
npm run start
```

`setup.ps1` 会检查 Node.js 20+、安装依赖，并执行 `npm run check` 完成 TypeScript 类型检查。

stdio 模式启动后会等待 MCP Host 连接，不会显示普通交互界面。

## 提供的工具

| Tool | 类型 | 作用 |
| --- | --- | --- |
| `network_policy_discover` | 只读 | 自动识别网卡、默认路由、特定目标路由、代理绕过和管理状态 |
| `network_policy_list_rules` | 只读 | 读取管理器当前规则 |
| `network_policy_save_rule` | 配置写入 | 新增/修改规则定义，不立即改系统路由 |
| `network_policy_test_rule` | 只读 | 查看 Windows 对规则目标实际选择的路由 |
| `network_policy_apply_rule` | 系统修改 | 应用规则；要求 `approved=true` 和管理员权限 |
| `network_policy_remove_rule` | 系统修改 | 撤销本程序拥有的路由/代理项；要求 `approved=true` 和管理员权限 |

## 推荐 AI 工作流

1. 调用 `network_policy_discover`。
2. 判断目标地址当前走哪张网卡、哪个网关，是否已经由管理器接管。
3. 需要新规则时调用 `network_policy_save_rule`，默认不要设置 `ownExistingRoute=true`。
4. 调用 `network_policy_test_rule` 做只读验证。
5. 只有用户明确要求执行后，才调用 `network_policy_apply_rule` 并传 `approved=true`。
6. 撤销时同样需要用户明确批准。

## MCP Host 配置示例

先在本目录执行一次 `npm install`。随后在支持 MCP 的客户端中，把服务配置为本地 stdio 进程。示例中的路径请替换为实际仓库路径：

```json
{
  "mcpServers": {
    "windows-network-policy": {
      "command": "cmd.exe",
      "args": [
        "/d",
        "/s",
        "/c",
        "cd /d D:\\path\\windows-local-network-policy-manager\\NetworkPolicyManager\\mcp && npm run start"
      ]
    }
  }
}
```

如果希望 AI 能应用/撤销路由，需要让启动该 MCP Host 的进程具备管理员权限。建议普通情况下只开放读取、规则编辑和测试；确实需要系统修改时再提升权限。
