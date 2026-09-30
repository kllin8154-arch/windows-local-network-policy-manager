# 本地网络策略管理器 · Windows 免安装版

适用于 Windows 10/11 x64。解压整个 ZIP 到可写的文件夹，双击 `本地网络策略管理器.exe`，在系统的管理员权限提示中选择“是”。需要系统自带的 Windows PowerShell 5.1 和 .NET Framework 4.x；无需安装 Node.js 或运行构建脚本。

首次启动时，程序从 `NetworkPolicyManager/network-rules.default.json` 生成 `network-rules.json`。之后在界面中新增、修改、删除的规则保存在 `network-rules.json`；应用状态保存在 `manager-state.json`，操作记录保存在 `network-policy-manager.log`。启动和识别不会自动修改 Windows 路由，只有点击应用或撤销才会修改对应策略。

升级时先关闭程序，再把新版 ZIP 解压到原文件夹。压缩包不包含 `network-rules.json`、`manager-state.json` 或日志，因此不会覆盖已有规则和应用状态。升级前也可以在界面点“备份规则”另存一份。

压缩包中的默认规则包含当前机器的离线服务器地址、外接网线网关和网卡标识；换电脑使用时，请先在界面确认网卡与网关，再应用规则。

如要移除程序，先在界面撤销由它管理的规则，再删除解压文件夹；已应用的持久路由不会因删除文件夹而自动消失。

此包只包含可视化管理器。MCP 开发组件位于源码仓库，不是免安装版运行所需内容。
