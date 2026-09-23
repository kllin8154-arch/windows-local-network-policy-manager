# 本地网络策略管理器

双击根目录的 `本地网络策略管理器.exe`，在 UAC 窗口选择“是”即可使用。

如果是从 GitHub 克隆的源码，请先在仓库根目录运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\NetworkPolicyManager\build.ps1"
```

构建完成后会在仓库根目录生成 `本地网络策略管理器.exe`。

程序支持：

- 新增、修改、删除 IPv4 主机或 CIDR 网段规则；
- 按网卡硬件 GUID 识别设备，不依赖会变化的接口编号或“网络 235”名称；
- 使用网卡当前默认网关，或手动指定离线网络网关；
- 为浏览器访问的精确 IPv4 地址增加/移除系统代理绕过；
- 应用、撤销和测试规则，并显示当前实际路由状态；
- 只管理精确路由，不修改默认路由、IP、DHCP 或接口跃点。

数据文件：

- `network-rules.json`：用户规则；
- `manager-state.json`：程序实际应用的路由状态；
- `network-policy-manager.log`：操作日志。

旧脚本仍保留作历史备份。开始使用管理器后，不要再交叉运行旧脚本的 `Apply/Rollback`，避免双方状态不一致。
