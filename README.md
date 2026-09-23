# 本地双网策略

## 推荐入口：可视化管理器

现在优先使用桌面的 **“本地网络策略管理器”** 快捷方式，或双击本目录的
`本地网络策略管理器.exe`。程序可新增、修改、删除、应用、撤销和测试 IPv4/CIDR
分流规则，并按网卡硬件 GUID 自动适应会变化的接口编号。

从 GitHub 克隆源码后，先在 PowerShell 中运行
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\NetworkPolicyManager\build.ps1"`，
即可在根目录生成 `本地网络策略管理器.exe`。编译产物和本机运行状态不纳入版本控制。

管理器只维护精确路由和选定的系统代理绕过，不修改默认路由、IP、DHCP 或网卡跃点。
详细说明见 `NetworkPolicyManager/README.md`。

> 开始使用管理器后，不要再交叉运行旧脚本的 `Apply/Rollback`；旧脚本继续保留作历史备份。

> 历史脚本 `特殊地址直连.ps1`、`MSTSC外接主网线.ps1` 和 `本地网络策略.ps1` 仅保留作备份；不要再运行它们的 `Apply/Rollback`，其中旧版 `本地网络策略.ps1 -Action Apply` 还包含修改静态 IP/DHCP 的历史方案。

## 目标

两张网卡保持同时启用，无需反复禁用或启用：

- `Remote NDIS based Internet Sharing Device`（当前显示为“以太网 / 网络 297”）作为普通互联网和 Hiddify 的默认出口。
- `Realtek PCIe GbE Family Controller`（当前显示为“外接主网线”）只承载离线服务器网段流量。
- Xshell 8、XTerminal 直接连离线服务器，AI 工具继续通过 Hiddify 使用网络 297。

脚本按网卡的设备描述自动识别当前实例，不依赖会变化的“网络 297”、“网络 298”或“以太网 2”等名称。

## 已核实的网络信息

| 用途 | 网卡 | 当前 IPv4 | 网关/下一跳 |
| --- | --- | --- | --- |
| 互联网、Hiddify | `以太网` | `192.168.10.100/24` | `192.168.10.1` |
| 离线服务器 | Realtek 外接网卡 | `172.16.21.114/24`（静态） | 无默认网关；离线路由下一跳为 `172.16.21.254` |
| Xshell 服务器 | `172.16.11.0/24` | `172.16.11.205` ~ `.208` | 经 `172.16.21.254` |

策略将 NDIS 互联网网卡的 IPv4 接口跃点设为 `10`，将 Realtek 离线网卡设为无默认网关的 `172.16.21.114/24`，并添加：

```text
172.16.11.0/24 -> 172.16.21.254 -> 外接主网线
```

精确的 `/24` 路由优先于 `0.0.0.0/0` 默认路由，因此两条链路不会互相抢流量。

> 说明：现场中 Realtek 网卡的 DHCP 请求持续超时并退回到 `169.254.90.206`，因此本策略不再依赖该线路的 DHCP。

## 使用方法

先在普通 PowerShell 中只读查看：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\本地网络策略.ps1" -Action Status
```

确认后，打开“以管理员身份运行”的 PowerShell，执行：

```powershell
Set-Location 'D:\Desktop\个人\本地网络策略'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\本地网络策略.ps1" -Action Apply
```

然后在两根线都接好的情况下验证：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\本地网络策略.ps1" -Action Test
```

## Hiddify 建议

保持当前的“系统代理”模式即可。“绕过局域网 / Bypass LAN”只影响使用系统代理的应用，不能修复网卡没有 IPv4 地址或 Windows 路由缺失。Xshell 和 XTerminal 未单独配置代理时，SSH 会按 Windows 路由表直连。

2026-09-08 核验当前 Hiddify 4.1.1 配置：服务模式为 `system-proxy`，地区为 `cn`。生成的 sing-box 路由将 `.cn`、`geosite-cn` 和 `geoip-cn` 交给 `direct`，其余流量交给代理选择器。因此抖音等国内网站直连，AI 与海外网站继续经 Hiddify；无需为每个国内域名单独修改 Windows 代理例外。实测 `https://www.douyin.com/` 返回 HTTP 200，海外出口经 Hiddify 与直接连接不同。不要把 Hiddify 地区切离 `cn`，也不要改成纯全局代理规则。

## XTerminal 如果还有其他网段

XTerminal 的会话数据是加密存储的，本次无法可靠读取其中的主机地址。如果它还要访问其他离线网段，可在首次 `Apply` 时显式传入，例如：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& ".\本地网络策略.ps1" -Action Apply `
  -OfflinePrefixes @('172.16.11.0/24', '10.35.0.0/16')
```

不要为省事直接添加过大的 `10.0.0.0/8` 或 `172.16.0.0/12`；应只添加实际需要的网段。

## 回滚

`Apply` 首次执行时会把原接口跃点保存到 `.network-policy-state.json`。需要恢复时，以管理员身份执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\本地网络策略.ps1" -Action Rollback
```

回滚只删除本脚本新建的路由，原本已存在的同类路由不会被删除。
