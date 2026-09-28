import { basename } from "node:path";
import { McpGateway } from "../mcp/gateway.ts";
import { mcpInstall, mcpStatus, mcpUninstall } from "../mcp/install.ts";
import { EXIT } from "../exit-codes.ts";
import { log } from "../output.ts";

export async function mcpWrap(o: { name?: string; env?: string; ttl?: number; argv: string[] }): Promise<number> {
  const [command, ...args] = o.argv;
  if (!command) {
    log.fail("usage: agentgate mcp wrap [--name <server>] [--env E] [--ttl N] -- <upstream command…>");
    return EXIT.USAGE;
  }
  const name = (o.name ?? basename(command)).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 64) || "mcp";
  const progress = Number(process.env.AGENTGATE_MCP_PROGRESS_MS);
  return new McpGateway({
    name,
    command,
    args,
    ttl: o.ttl ?? 120,
    ...(o.env ? { env: o.env } : {}),
    ...(Number.isFinite(progress) && progress > 0 ? { progressMs: progress } : {}),
  }).run();
}

export { mcpInstall, mcpStatus, mcpUninstall };
