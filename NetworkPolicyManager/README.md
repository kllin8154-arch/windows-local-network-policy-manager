# 本地网络策略管理器

双击根目录的 `本地网络策略管理器.exe`，在 UAC 窗口选择“是”即可使用。

如果是从 GitHub 克隆的源码，请先在仓库根目录运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\NetworkPolicyManager\build.ps1"
```

构建完成后会在仓库根目录生成 `本地网络策略管理器.exe`。

程序支持：

- 启动时自动扫描当前 IPv4 网卡、默认路由、特定目标路由和 IPv4 代理绕过项；
- 首屏用 4 个状态卡展示“规则状态 / 已连接网卡 / 当前默认出口 / 待处理现有策略”；
- 对未纳入管理的现有路由进行只读展示，并支持 Ctrl / Shift 多选后批量“导入”或“导入并接管”；
- 自动识别窗口按“特定路由 / 网卡概览 / 代理绕过”三个视角展示，并可导出完整诊断快照；
- 主规则列表支持名称、目标地址、网卡、网关和状态搜索，以及按“已应用 / 未应用 / 异常 / 已禁用”过滤；
- 右侧规则详情区集中展示期望出口、实际状态、代理绕过和所有权，并提供应用、诊断、修改、撤销、删除与复制详情；
- 新增、修改、删除 IPv4 主机或 CIDR 网段规则；
- 按网卡硬件 GUID 识别设备，不依赖会变化的接口编号或“网络 235”名称；
- 使用网卡当前默认网关，或手动指定离线网络网关；
- 为浏览器访问的精确 IPv4 地址增加/移除系统代理绕过；
- 支持增强诊断：检查期望网卡、实际选路、下一跳、代理绕过和管理状态；
- 支持规则备份与安全导入；导入前自动备份当前规则，且导入不会立即修改 Windows 网络；
- 支持 15 秒可选自动刷新、日志折叠和 F5 / Ctrl+F / Ctrl+N / Ctrl+D 快捷键；
- 只管理精确路由，不修改默认路由、IP、DHCP 或接口跃点。

数据文件：

- `network-rules.json`：用户规则；
- `manager-state.json`：程序实际应用的路由状态；
- `network-policy-manager.log`：操作日志。

旧脚本仍保留作历史备份。开始使用管理器后，不要再交叉运行旧脚本的 `Apply/Rollback`，避免双方状态不一致。


## 命令行 / MCP 接口

主脚本同时提供供程序调用的命令入口：

```powershell
.\本地网络策略管理器.ps1 -Command Discover
.\本地网络策略管理器.ps1 -Command ListRules
.\本地网络策略管理器.ps1 -Command TestRule -RuleId <id>
```

`ApplyRule` 和 `RemoveRule` 会修改系统网络，除管理员权限外还必须显式带 `-Approved`。

MCP 服务位于 `mcp/`，使用官方 MCP TypeScript SDK，通过 stdio 向 AI 客户端提供上述能力。详见 `mcp/README.md`。

## 界面视觉规范

界面采用深色美式复古配色与统一控件规范。后续 UI 修改请先阅读 `UI_STYLE.md`，并复用主脚本内的主题变量与控件样式函数。


## 常用快捷键

- `F5`：刷新当前规则和网络状态；
- `Ctrl+F`：定位到规则搜索框；
- `Ctrl+N`：新增规则；
- `Ctrl+D`：重新识别当前 Windows 网络策略。

自动识别在启动时执行，但不会强制弹窗或自动接管已有系统路由；主界面的“待处理现有策略”卡片会提示数量，点击后再由用户决定是否导入或接管。


## 只读验证

日常开发后可直接运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\NetworkPolicyManager\test.ps1"
```

增加 `-Ui` 会生成 `ui-smoke-test.png` 检查真实 WinForms 布局；增加 `-Mcp` 会同时执行 MCP TypeScript 类型检查。测试流程只读取网络状态，不应用或撤销路由。

`build.ps1` 现在也会在编译启动 EXE 前自动执行管理器 `SelfTest`，配置或 PowerShell 语法异常时会直接停止构建。
