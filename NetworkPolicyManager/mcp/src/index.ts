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
const powershell =
  process.env.SystemRoot
    ? path.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    : "powershell.exe";

type JsonValue = unknown;

async function runManager(command: string, extraArgs: string[] = []): Promise<JsonValue> {
  const args = [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    managerScript,
    "-Command",
    command,
    ...extraArgs,
  ];

  try {
    const { stdout, stderr } = await execFileAsync(powershell, args, {
      windowsHide: true,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    });

    if (stderr.trim()) {
      console.error(stderr.trim());
    }

    const text = stdout.trim();
    if (!text) return {};
    return JSON.parse(text);
  } catch (error) {
    const e = error as Error & { stdout?: string; stderr?: string };
    const details = [e.message, e.stderr, e.stdout].filter(Boolean).join("\n").trim();
    throw new Error(details || "Network Policy Manager command failed.");
  }
}

function toolResult(data: unknown) {
  const structuredContent: Record<string, unknown> =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : { value: data };

  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
    structuredContent,
  };
}

function createServer(): McpServer {
  const server = new McpServer({
    name: "windows-local-network-policy-manager",
    version: "0.1.0",
  });

  server.registerTool(
    "network_policy_discover",
    {
      title: "Discover Windows network policy",
      description:
        "Read the current Windows IPv4 adapters, default routes, specific gateway routes, proxy bypass entries, and whether each discovered route is already represented by a managed rule. This tool is read-only.",
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => toolResult(await runManager("Discover")),
  );

  server.registerTool(
    "network_policy_list_rules",
    {
      title: "List managed network rules",
      description:
        "List the rules stored by Windows Local Network Policy Manager. This tool does not change Windows networking.",
      inputSchema: z.object({}),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => toolResult(await runManager("ListRules")),
  );

  server.registerTool(
    "network_policy_save_rule",
    {
      title: "Save a network rule definition",
      description:
        "Create or update a manager rule definition only. It does not apply the route. Use network_policy_discover first so adapter GUID/description and gateway are based on the live machine.",
      inputSchema: z.object({
        id: z.string().optional().describe("Existing rule ID to update; omit to create a new rule."),
        name: z.string().min(1),
        destination: z.string().min(1).describe("IPv4 address or CIDR, for example 172.16.11.0/24."),
        adapterGuid: z.string().min(1),
        adapterDescription: z.string().min(1),
        gatewayMode: z.enum(["Auto", "Manual"]),
        gateway: z.string().optional().default(""),
        bypassProxy: z.boolean().optional().default(false),
        enabled: z.boolean().optional().default(true),
        ownExistingRoute: z.boolean().optional().default(false),
        ownExistingProxy: z.boolean().optional().default(false),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async (input) => {
      const payload = {
        Id: input.id ?? "",
        Name: input.name,
        Destination: input.destination,
        AdapterGuid: input.adapterGuid,
        AdapterDescription: input.adapterDescription,
        GatewayMode: input.gatewayMode,
        Gateway: input.gateway ?? "",
        BypassProxy: input.bypassProxy ?? false,
        Enabled: input.enabled ?? true,
        OwnExistingRoute: input.ownExistingRoute ?? false,
        OwnExistingProxy: input.ownExistingProxy ?? false,
      };
      return toolResult(
        await runManager("SaveRule", ["-RuleJson", JSON.stringify(payload)]),
      );
    },
  );

  server.registerTool(
    "network_policy_test_rule",
    {
      title: "Test network route selection",
      description:
        "Test how Windows currently routes the destination for one managed rule. This tool is read-only.",
      inputSchema: z.object({
        ruleId: z.string().min(1),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ ruleId }) =>
      toolResult(await runManager("TestRule", ["-RuleId", ruleId])),
  );

  server.registerTool(
    "network_policy_apply_rule",
    {
      title: "Apply a managed network rule",
      description:
        "Apply one rule to Windows persistent routing and, when configured, the Windows proxy bypass list. The caller must explicitly pass approved=true. The MCP host must already be running with Administrator rights.",
      inputSchema: z.object({
        ruleId: z.string().min(1),
        approved: z.literal(true).describe("Must be true after the user explicitly approves changing Windows networking."),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ ruleId }) =>
      toolResult(await runManager("ApplyRule", ["-RuleId", ruleId, "-Approved"])),
  );

  server.registerTool(
    "network_policy_remove_rule",
    {
      title: "Withdraw an applied network rule",
      description:
        "Withdraw only the route/proxy entries that the manager owns for one rule. The rule definition remains stored. The caller must explicitly pass approved=true. The MCP host must already be running with Administrator rights.",
      inputSchema: z.object({
        ruleId: z.string().min(1),
        approved: z.literal(true).describe("Must be true after the user explicitly approves changing Windows networking."),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ ruleId }) =>
      toolResult(await runManager("RemoveRule", ["-RuleId", ruleId, "-Approved"])),
  );

  return server;
}

void serveStdio(createServer);
console.error("Windows Local Network Policy Manager MCP server running on stdio");
