# 多网络环境模型

本项目不能假设电脑只有一张有线网卡。Windows 现场环境可能同时存在：

- 物理以太网 / 网线；
- Wi-Fi；
- USB 网卡；
- Hyper-V vEthernet；
- VMware / VirtualBox Host-Only、NAT、Bridged；
- WSL / Docker 虚拟网络；
- Wintun / WireGuard；
- TAP / TUN / OpenVPN；
- ZeroTier / Tailscale；
- 企业 VPN；
- 多个默认路由同时存在。

## 1. 最重要的原则

**网卡类型只用于解释，不用于决定选路。**

程序不会因为“这是 Realtek”就认为它一定是现场网线，也不会因为“这是虚拟网卡”就忽略它。

实际状态始终以 Windows 为准：

1. 目标地址先按最长前缀匹配路由；
2. 同前缀候选再比较 Metric；
3. 默认出口按 Route Metric + Interface Metric 展示有效优先级；
4. ExplainAddress 优先读取 Find-NetRoute 的实际结果；
5. 规则仍通过 Adapter GUID 绑定，不依赖会变化的 ifIndex 或“网络 235”名称。

## 2. Adapter Kind

Discover 会给适配器增加解释性分类：

- Ethernet
- Wi-Fi
- Virtual
- Tunnel/VPN
- Bluetooth
- Loopback / Other

VirtualProvider 可能识别：

- Hyper-V
- VMware
- VirtualBox
- WSL
- Docker
- Wintun/WireGuard
- TAP/TUN
- ZeroTier
- Tailscale
- VPN

分类只是提示。任何修改仍然必须重新读取真实网卡 GUID、Status、路由、网关和 Fingerprint。

## 3. 多默认出口

网线和 Wi-Fi 同时连接、VPN 接管流量、虚拟交换机存在时，系统可能有多条 0.0.0.0/0。

Discover 的“默认出口”页会展示：

- 网卡；
- 类型；
- 虚拟/VPN Provider；
- Gateway；
- Route Metric；
- Interface Metric；
- Effective Metric。

Effective Metric 用于解释优先级：

Route Metric + Interface Metric

如果多个已连接默认出口具有相同最低有效 Metric，Audit 会给出 Warning。程序仍不会自行修改默认路由或接口 Metric。

## 4. On-Link 虚拟网络

Hyper-V Internal/Private、VMware Host-Only、VirtualBox Host-Only 等经常出现：

NextHop = 0.0.0.0

这表示 On-Link，并不等同于“网关是 0.0.0.0”。

当前策略：

- Discover 可见；
- ExplainAddress 可见；
- 标记 RouteType=OnLink；
- 不允许通过“导入/接管”把它变成普通 Gateway 规则；
- 不使用 route.exe -p add 盲目重建。

以后若需要管理 On-Link 路由，应设计独立 RouteMode，而不是复用 Manual Gateway。

## 5. 网卡状态变化

### 网线拔出 / Wi-Fi 断开

- 规则仍按 GUID 保留；
- Audit / Plan 识别 Status 非 Up；
- Apply 被阻止；
- Remove 可以撤销 manager-state 明确拥有的旧资源，不依赖当前网卡仍可解析。

### ifIndex 变化

ifIndex 不是稳定身份。

程序恢复和漂移检测同时使用：

- 持久保存的 Adapter GUID；
- 当前 GUID 对应的新 ifIndex；
- 旧 state 中记录的 ifIndex。

只删除与 manager-state 中 Destination + Gateway + 可接受 Index 相符的已拥有资源。

## 6. VPN / Tunnel

VPN/Tunnel 可以：

- 提供默认路由；
- 提供更具体的目标路由；
- 动态改变 Metric；
- 在连接/断开时让旧 Plan 失效。

所以所有高风险执行都需要实时 Plan Fingerprint。

DEV MCP 不具备写网络能力；USER MCP 也不能自动接管扫描到的 VPN/虚拟路由。

## 7. 漂移修复

Drift 会对比：

规则定义 + manager-state + Windows 实际路由 + ProxyOverride

常见类型：

- OwnedRouteMissing
- OwnedRouteReplacedExternally
- ExternalRouteMissing
- DesiredRouteChanged
- OwnedProxyMissing
- ExternalProxyMissing
- DesiredProxyChanged
- DisabledRuleStillManaged
- OrphanState
- ExternalMatchWithoutState

修复固定为：

Detect → PlanRepair → 展示 Diff/Fingerprint → 用户确认 → 自动快照 → Apply/Remove → 再验证

孤儿 state、外部匹配等不明确所有权的情况只报告，不自动清理或接管。

## 8. 当前范围

当前规则管理核心仍以 IPv4 精确路由/CIDR 为主。

IPv6、Windows 防火墙策略、DNS 接口优先级、NRPT、系统默认路由和接口 Metric 都不由本程序自动修改。发现这些需求时应单独建模，不能混入 IPv4 路由规则。
