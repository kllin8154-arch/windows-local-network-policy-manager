# MSTSC 外接主网线策略

系统远程桌面（`mstsc.exe`）在 Windows 中不能直接按进程选择网卡，因此这里按远程服务器 IP 添加精确的 `/32` 主机路由。

目标服务器：

- `192.168.2.122`
- `192.168.2.223`
- `192.168.2.224`
- `192.168.2.225`
- `172.16.23.120`

已于 2026-09-08 应用：以上目标经“外接主网线”接口 `11`、下一跳 `172.16.21.254`，并写入持久路由。其中 `172.16.23.120` 是用户后续追加的远程桌面服务器；添加前它会误走普通互联网默认路由。应用后实测 `172.16.23.120:3389` 连通，使用源地址 `172.16.21.114` 和“外接主网线”；测试未登录，也未使用远程桌面凭据。

脚本按 Realtek 网卡的硬件 GUID 和描述识别“外接主网线”，不依赖会变化的“网络 235 / 网络 34”等网络配置文件编号，也不依赖可能变化的接口索引。每次运行 `Apply` 时都会读取这块网卡当前的 IPv4 网关；若外接网络发生变化，只更新本脚本先前创建的路由。

管理员 PowerShell 7：

```powershell
Set-Location 'D:\Desktop\个人\本地网络策略'
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\MSTSC外接主网线.ps1" -Action Apply
```

只查看当前路由选择（无需管理员）：

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\MSTSC外接主网线.ps1" -Action Status
```

撤销本脚本创建的路由：

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File ".\MSTSC外接主网线.ps1" -Action Rollback
```

此策略不修改 RDP 保存的服务器、用户名或凭据，也不修改系统默认路由、代理、IP、DHCP、网卡跃点和 Hiddify。`localhost:端口` 类型的远程桌面历史记录仍走本机回环，不纳入分流。
