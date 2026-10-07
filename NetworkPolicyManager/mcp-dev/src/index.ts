import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const managerRoot = path.resolve(here, "..", "..");
const repoRoot = path.resolve(managerRoot, "..");
const managerScript = path.join(managerRoot, "本地网络策略管理器.ps1");
const testScript = path.join(managerRoot, "test.ps1");
const buildScript = path.join(managerRoot, "build.ps1");
const packageScript = path.join(managerRoot, "package-portable.ps1");
const powershell = process.env.SystemRoot
  ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
  : "powershell.exe";
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

async function run(executable: string, args: string[], cwd = repoRoot) {
  try {
    const { stdout, stderr } = await execFileAsync(executable, args, {
      cwd,
      windowsHide: true,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
    return { ok: true, stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (error) {
    const e = error as Error & { stdout?: string; stderr?: string; code?: number | string };
    return {
      ok: false,
      code: e.code ?? null,
      stdout: e.stdout?.trim() ?? "",
      stderr: e.stderr?.trim() ?? "",
      error: e.message,
    };
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
  name: "windows-local-network-policy-manager-dev",
  version: "0.3.0",
});

server.registerTool("dev_project_info", {
  title: "DEV · 项目信息",
  description: "开发专用，只读。读取项目 README 和关键路径。此 MCP 不提供应用/撤销网络策略的能力。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => {
  const readme = await readFile(path.join(repoRoot, "README.md"), "utf8");
  return result({
    repoRoot,
    managerRoot,
    managerScript,
    firstReadmeLines: readme.split(/\r?\n/).slice(0, 30),
    safetyBoundary: "DEV MCP intentionally has no route/proxy mutation tools.",
  });
});

server.registerTool("dev_manager_self_test", {
  title: "DEV · 管理器 SelfTest",
  description: "开发专用，只读。运行 PowerShell 配置/规则自检。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await run(powershell, [
  "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", managerScript, "-SelfTest",
])));

server.registerTool("dev_policy_audit", {
  title: "DEV · 网络策略审计",
  description: "开发专用，只读。运行核心 Audit，用于回归检查规则重叠、网卡/网关问题和安全保护。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await run(powershell, [
  "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", managerScript, "-Command", "Audit",
])));

server.registerTool("dev_run_validation", {
  title: "DEV · 运行只读验证",
  description: "开发专用。运行 test.ps1；默认只读。ui=true 时额外生成 WinForms smoke-test 图片。",
  inputSchema: z.object({ ui: z.boolean().optional().default(false) }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async ({ ui }) => {
  const args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", testScript];
  if (ui) args.push("-Ui");
  return result(await run(powershell, args));
});

server.registerTool("dev_typecheck_user_mcp", {
  title: "DEV · 类型检查 User MCP",
  description: "开发专用。运行 mcp-user 的 npm run check，不安装依赖。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await run(npm, ["run", "check"], path.join(managerRoot, "mcp-user"))));

server.registerTool("dev_typecheck_dev_mcp", {
  title: "DEV · 类型检查 Dev MCP",
  description: "开发专用。运行 mcp-dev 自身 npm run check，不安装依赖。",
  inputSchema: z.object({}),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}, async () => result(await run(npm, ["run", "check"], path.join(managerRoot, "mcp-dev"))));

server.registerTool("dev_build_launcher", {
  title: "DEV · 构建 Windows 启动器",
  description: "开发专用。生成根目录 EXE，构建前会执行 SelfTest。不会修改系统网络。",
  inputSchema: z.object({ approved: z.literal(true) }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
}, async () => result(await run(powershell, [
  "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", buildScript,
])));

server.registerTool("dev_package_portable", {
  title: "DEV · 构建免安装包",
  description: "开发专用。执行 portable 打包和干净解压首次运行验证。不会应用/撤销系统路由。",
  inputSchema: z.object({
    version: z.string().regex(/^[0-9A-Za-z.-]+$/),
    approved: z.literal(true),
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
}, async ({ version }) => result(await run(powershell, [
  "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", packageScript, "-Version", version,
])));

void serveStdio(() => server);
console.error("DEV MCP: Windows Local Network Policy Manager development tools running on stdio");
