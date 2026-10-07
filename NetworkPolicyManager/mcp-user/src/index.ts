import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const managerScript = path.resolve(here, "..", "..", "本地网络策略管理器.ps1");
const powershell = process.env.SystemRoot
  ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
  : "powershell.exe";

async function runManager(command: string, extraArgs: string[] = []): Promise<unknown> {
  const args = [
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", managerScript,
    "-Command", command,
    ...extraArgs,
  ];
  try {
    const { stdout, stderr } = await execFileAsync(powershell, args, {
      windowsHide: true,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    if (stderr.trim()) console.error(stderr.trim());
    const output = stdout.trim();
    return output ? JSON.parse(output) : {};
  } catch (error) {
    const e = error as Error & { stdout?: string; stderr?: string };
    throw new Error([e.message, e.stderr, e.stdout].filter(Boolean).join("\n").trim());
  }
}

function result(data: unknown) {
  const structuredContent =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : { value: data };
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
    structuredContent,
  };
}

const server = new McpServer({
  name: "windows-local-network-policy-manager-user",
  version: "0.3.0",
});

server.registerTool("network_policy_discover", {
  title: "发现当前 Windows 网络策略",
  description: "只读。读取网卡、IPv4、默认路由、特定路由、代理绕过和管理状态。任何修改前都应先调用。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("Discover")));

server.registerTool("network_policy_audit", {
  title: "审计网络策略风险",
  description: "只读。检查网卡不可用、自动网关缺失、规则网段重叠、危险所有权声明和默认路由保护等问题。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("Audit")));

server.registerTool("network_policy_drift", {
  title: "检测管理状态漂移",
  description: "只读。对比 manager-state、规则定义和真实 Windows 路由/ProxyOverride，分类缺失、被外部替换、规则已变化、孤儿状态等漂移。不会自动修复。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("Drift")));

server.registerTool("network_policy_plan_repair", {
  title: "生成漂移修复计划",
  description: "只读。为指定规则把漂移项映射到现有 Apply/Remove Plan，返回同一套 Diff 与 Fingerprint。真正修复仍必须使用现有逐条写工具并再次明确批准。",
  inputSchema: z.object({
    ruleId: z.string().min(1),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ ruleId }) =>
  result(await runManager("PlanRepair", ["-RuleId", ruleId])));


server.registerTool("network_policy_explain_address", {
  title: "解释 IPv4 最终选路",
  description: "只读。输入一个 IPv4，解释 Windows 当前最终选择的路由、最长前缀候选、匹配的管理器规则以及精确代理绕过状态。",
  inputSchema: z.object({
    address: z.string().min(7).max(15).describe("单个 IPv4 地址，例如 172.16.11.205"),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ address }) =>
  result(await runManager("ExplainAddress", ["-Address", address])));


server.registerTool("network_policy_list_rules", {
  title: "读取已配置规则",
  description: "只读。返回管理器保存的所有规则定义。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("ListRules")));

server.registerTool("network_policy_list_groups", {
  title: "读取规则分组",
  description: "只读。返回分组名称、规则数、启用数和分组内标签汇总；空 Group 表示未分组。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("ListGroups")));

server.registerTool("network_policy_plan_group", {
  title: "生成整组规则计划",
  description: "只读。对一个分组中的启用规则逐条生成独立 Plan/Fingerprint，并汇总是否全部允许执行和预计系统变更数。该工具本身不会批量应用。",
  inputSchema: z.object({
    group: z.string().max(60).describe("精确分组名；空字符串表示未分组。"),
    action: z.enum(["Apply", "Remove"]),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ group, action }) => {
  const args = group
    ? ["-Group", group, "-Action", action]
    : ["-Action", action];
  return result(await runManager("PlanGroup", args));
});


server.registerTool("network_policy_plan", {
  title: "生成规则变更计划",
  description: "只读。对应用或撤销生成实时计划和 Fingerprint。真正执行时必须提交同一个 Fingerprint；网络状态变化后旧计划会失效。",
  inputSchema: z.object({
    ruleId: z.string().min(1),
    action: z.enum(["Apply", "Remove"]),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ ruleId, action }) =>
  result(await runManager("PlanRule", ["-RuleId", ruleId, "-Action", action])));

server.registerTool("network_policy_test_rule", {
  title: "诊断单条规则",
  description: "只读。检查期望网卡/网关、Windows 实际选路、代理绕过和管理所有权。",
  inputSchema: z.object({ ruleId: z.string().min(1) }),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ ruleId }) =>
  result(await runManager("TestRule", ["-RuleId", ruleId])));

server.registerTool("network_policy_create_backup", {
  title: "创建安全快照",
  description: "创建带 SHA256 校验的本机安全快照，包含规则、管理状态、相关路由、默认路由和代理绕过。不会修改网络。",
  inputSchema: z.object({ ruleId: z.string().optional() }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
}, async ({ ruleId }) =>
  result(await runManager("CreateBackup", ruleId ? ["-RuleId", ruleId] : [])));

server.registerTool("network_policy_list_backups", {
  title: "列出安全快照",
  description: "只读。列出最近安全快照及 SHA256 完整性校验结果。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await runManager("ListBackups")));

server.registerTool("network_policy_save_rule", {
  title: "保存规则定义",
  description: "保存规则配置但不应用到 Windows。执行前自动创建安全快照。用户版 MCP 不允许 AI 声明接管已有路由/代理。",
  inputSchema: z.object({
    approved: z.literal(true).describe("用户明确同意保存规则定义后必须为 true。"),
    id: z.string().optional(),
    name: z.string().min(1),
    group: z.string().max(60).optional().default(""),
    tags: z.array(z.string().min(1).max(40)).max(20).optional().default([]),
    destination: z.string().min(1),
    adapterGuid: z.string().min(1),
    adapterDescription: z.string().min(1),
    gatewayMode: z.enum(["Auto", "Manual"]),
    gateway: z.string().optional().default(""),
    bypassProxy: z.boolean().optional().default(false),
    enabled: z.boolean().optional().default(true),
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
}, async (input) => {
  const payload = {
    Id: input.id ?? "",
    Name: input.name,
    Group: input.group ?? "",
    Tags: input.tags ?? [],
    Destination: input.destination,
    AdapterGuid: input.adapterGuid,
    AdapterDescription: input.adapterDescription,
    GatewayMode: input.gatewayMode,
    Gateway: input.gateway ?? "",
    BypassProxy: input.bypassProxy ?? false,
    Enabled: input.enabled ?? true,
    OwnExistingRoute: false,
    OwnExistingProxy: false,
  };
  return result(await runManager("SaveRule", ["-RuleJson", JSON.stringify(payload)]));
});

server.registerTool("network_policy_apply_rule", {
  title: "应用规则到 Windows",
  description: "高风险写操作。必须先调用 network_policy_plan(action=Apply)，向用户展示变化，并提交同一 Fingerprint 与 approved=true。执行前自动创建安全快照。",
  inputSchema: z.object({
    ruleId: z.string().min(1),
    planFingerprint: z.string().length(64),
    approved: z.literal(true),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
}, async ({ ruleId, planFingerprint }) =>
  result(await runManager("ApplyRule", [
    "-RuleId", ruleId,
    "-ExpectedFingerprint", planFingerprint,
    "-Approved",
  ])));

server.registerTool("network_policy_remove_rule", {
  title: "撤销已管理规则",
  description: "高风险写操作。只撤销管理器拥有的路由/代理项。必须先调用 network_policy_plan(action=Remove)，并提交实时 Fingerprint 与 approved=true。",
  inputSchema: z.object({
    ruleId: z.string().min(1),
    planFingerprint: z.string().length(64),
    approved: z.literal(true),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
}, async ({ ruleId, planFingerprint }) =>
  result(await runManager("RemoveRule", [
    "-RuleId", ruleId,
    "-ExpectedFingerprint", planFingerprint,
    "-Approved",
  ])));

server.registerTool("network_policy_restore_rules", {
  title: "从安全快照恢复规则定义",
  description: "恢复指定本机安全快照中的规则定义，不直接修改 Windows 路由。还原前再次自动备份当前配置，并清除 OwnExistingRoute/OwnExistingProxy 所有权声明。",
  inputSchema: z.object({
    backupId: z.string().min(1),
    approved: z.literal(true),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
}, async ({ backupId }) =>
  result(await runManager("RestoreRules", ["-BackupId", backupId, "-Approved"])));

void serveStdio(() => server);
console.error("USER MCP: Windows Local Network Policy Manager running on stdio");
