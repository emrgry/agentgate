import { parseArgs, type ParseArgsConfig } from "node:util";
import { loginCommand } from "./commands/login.ts";
import { pairCommand } from "./commands/pair.ts";
import { limitsCommand, sessionCommand, taskCommand, usageCommand, workspaceCommand } from "./commands/session.ts";
import { restartCommand, serveCommand, serverCommand, setupCommand, uninstallServerCommand } from "./commands/setup.ts";
import { updateCommand } from "./commands/update.ts";
import { uninstallAllCommand } from "./commands/uninstall-all.ts";
import { versionCommand } from "./commands/version.ts";
import { mcpInstall, mcpStatus, mcpUninstall, mcpWrap } from "./commands/mcp.ts";
import { execCommand } from "./commands/exec.ts";
import { hookCommand } from "./commands/hook.ts";
import { cursorHookCommand } from "./commands/hook-cursor.ts";
import { installCursorCommand, uninstallCursorCommand } from "./commands/install-cursor.ts";
import { installCodexCommand, uninstallCodexCommand } from "./commands/install-codex.ts";
import { providerHookCommand } from "./commands/hook-provider.ts";
import { installCommand, uninstallCommand } from "./commands/install.ts";
import { devicesCommand } from "./commands/devices.ts";
import { configCommand, configSetCommand, logoutCommand } from "./commands/misc.ts";
import { runAgentCommand } from "./commands/run.ts";
import { requestCommand } from "./commands/request.ts";
import { statusCommand } from "./commands/status.ts";
import { blockedLine, EXIT } from "./exit-codes.ts";
import { log, out, setVerbose } from "./output.ts";
import { CLI_VERSION } from "./version.ts";

const HELP = `agentgate ${CLI_VERSION} — human authorization layer between AI agents and the real world

Usage:
  agentgate session start [--provider claude-code] [--cwd DIR] "<prompt>" | list | tail <id> [-f] | send <id> "<text>" | stop|kill|pause|resume <id>
  agentgate task add <session> "<text>" [--title T] | task list <session>
  agentgate workspace add [dir] [--label L] | list | remove <dir|id>
  agentgate workspace allow-ungated|disallow-ungated <dir> <provider>   (providers AgentGate can't gate)
  agentgate limits set (--session ID | --global) [--max-cost-task USD] [--max-cost-session USD] [--max-session-minutes N]
                       [--max-task-minutes N] [--max-retries N] [--max-rss-mb N] [--on-exceed notify|ask|pause|stop]   ("none" clears)
  agentgate limits show [--session ID]
  agentgate usage [--range today|7d|30d]
  agentgate devices list | revoke <id> | reset        (local recovery; asks for sudo — human only)
  agentgate setup   [--port 8787] [--host 0.0.0.0] [--no-start] [--no-pair]   local server + login + pairing QR
  agentgate serve   [--port N] [--host H]         run the local server in the foreground
  agentgate server  <start|stop|status|logs [-f]>
  agentgate restart                                 restart the local server (launchd)
  agentgate uninstall-server [--purge]
  agentgate version                                 version, install type (release/dev checkout) and path
  agentgate update  [--check] [--version X]         install the latest signed release (keeps the previous one)
  agentgate update  --rollback | --restart | --prune
  agentgate uninstall [--purge] [--yes] [--dry-run] remove hooks, MCP wraps, launchd agent and installed files
  agentgate login   [--server URL] [--email EMAIL] [--accept-new-key] [--insecure-lan]
  agentgate pair    [--no-qr] [--advertise-url URL]                  one-time code to pair the AgentGate app (5 min)
  agentgate status
  agentgate config  [--policy] | config set public_url <url> | config unset public_url
  agentgate logout
  agentgate request [--agent-type cli] [--env ENV] [--repo R] [--branch B] [--ttl SECONDS] [--dry-run] -- <command...>
  agentgate run claude [--env ENV] [--ttl SECONDS] [-- <claude args...>]
  agentgate install claude-code   [--project <dir> (default: cwd) | --user --yes] [--env ENV] [--ttl SECONDS]
  agentgate uninstall claude-code [--project <dir> | --user]
  agentgate install cursor        [--project <dir> (default: cwd) | --user --yes] [--env ENV] [--ttl SECONDS]
  agentgate uninstall cursor      [--project <dir> | --user]      (Cursor agent hooks: shell, file edits, MCP)
  agentgate install codex         [--project <dir> (default: cwd) | --user --yes] [--env ENV] [--ttl SECONDS]
  agentgate uninstall codex       [--project <dir> | --user]      (interactive Codex: PreToolUse hook + trust)
  agentgate mcp wrap [--name N] [--env E] [--ttl S] -- <upstream MCP server command…>   (stdio MCP gateway)
  agentgate mcp install   --client <claude-desktop|cursor|claude-code|codex> [--project DIR] (--server NAME… | --all)
  agentgate mcp uninstall --client <…> [--project DIR] [--server NAME… | --all]
  agentgate mcp status [--project DIR]
  agentgate exec --approval <apr_id> -- <command>     (used by rewritten Claude Code Bash calls)
  agentgate hook claude-code                          (Claude Code PreToolUse hook; reads stdin)
  agentgate hook cursor                               (Cursor agent hook; reads stdin, answers permission JSON)
  agentgate hook codex|<provider>                     (Codex / providers.yaml PreToolUse hook; Control Center)

Global flags: -v/--verbose  -h/--help  --version
Environment:  AGENTGATE_HOME (default ~/.agentgate), NO_COLOR

Exit codes (request/exec): the command's own exit code if it ran; 77 blocked (denied, expired,
cancelled, verification failure, server/WS unreachable, not logged in); 130 interrupted; 2 usage.
hook: 0 = decision JSON on stdout, 2 = blocked (reason on stderr). Nothing else.`;

const GLOBAL = {
  verbose: { type: "boolean", short: "v" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean" },
} as const satisfies ParseArgsConfig["options"];

export async function main(argv: string[]): Promise<number> {
  // Everything after the first "--" is the wrapped command, never parsed as flags.
  const sep = argv.indexOf("--");
  const head = sep === -1 ? argv : argv.slice(0, sep);
  const tail = sep === -1 ? null : argv.slice(sep + 1);

  const cmd = head.find((a) => !a.startsWith("-"));
  const rest = cmd === undefined ? head : head.filter((_, i) => i !== head.indexOf(cmd));

  try {
    switch (cmd) {
      case "login": {
        const v = parse(rest, { server: { type: "string" }, email: { type: "string" }, "accept-new-key": { type: "boolean" }, "insecure-lan": { type: "boolean" } });
        if (v === null) return EXIT.OK;
        return await loginCommand({ server: str(v.server), email: str(v.email), acceptNewKey: v["accept-new-key"] === true, insecureLan: v["insecure-lan"] === true });
      }
      case "session": {
        const v = parse(rest, { provider: { type: "string" }, cwd: { type: "string" }, follow: { type: "boolean", short: "f" } }, true);
        if (v === null) return EXIT.OK;
        const [action, ...args] = v._positionals;
        return await sessionCommand(action, [...args, ...(tail ?? [])], { provider: str(v.provider) ?? "claude-code", ...(str(v.cwd) ? { cwd: str(v.cwd)! } : {}), follow: v.follow === true });
      }
      case "task": {
        const v = parse(rest, { title: { type: "string" } }, true);
        if (v === null) return EXIT.OK;
        const [action, ...args] = v._positionals;
        return await taskCommand(action, [...args, ...(tail ?? [])], { ...(str(v.title) ? { title: str(v.title)! } : {}) });
      }
      case "limits": {
        const v = parse(
          rest,
          {
            session: { type: "string" },
            global: { type: "boolean" },
            "max-cost-task": { type: "string" },
            "max-cost-session": { type: "string" },
            "max-session-minutes": { type: "string" },
            "max-task-minutes": { type: "string" },
            "max-retries": { type: "string" },
            "max-rss-mb": { type: "string" },
            "on-exceed": { type: "string" },
          },
          true,
        );
        if (v === null) return EXIT.OK;
        const flags = {
          ...(str(v.session) ? { session: str(v.session)! } : {}),
          global: v.global === true,
          ...(str(v["max-cost-task"]) ? { maxCostTask: str(v["max-cost-task"])! } : {}),
          ...(str(v["max-cost-session"]) ? { maxCostSession: str(v["max-cost-session"])! } : {}),
          ...(str(v["max-session-minutes"]) ? { maxSessionMinutes: str(v["max-session-minutes"])! } : {}),
          ...(str(v["max-task-minutes"]) ? { maxTaskMinutes: str(v["max-task-minutes"])! } : {}),
          ...(str(v["max-retries"]) ? { maxRetries: str(v["max-retries"])! } : {}),
          ...(str(v["max-rss-mb"]) ? { maxRssMb: str(v["max-rss-mb"])! } : {}),
          ...(str(v["on-exceed"]) ? { onExceed: str(v["on-exceed"])! } : {}),
        };
        return await limitsCommand(v._positionals[0], flags);
      }
      case "devices": {
        const v = parse(rest, {}, true);
        if (v === null) return EXIT.OK;
        const [action, ...args] = v._positionals;
        return await devicesCommand(action, args);
      }
      case "usage": {
        const v = parse(rest, { range: { type: "string" } });
        if (v === null) return EXIT.OK;
        return await usageCommand(str(v.range) ?? "7d");
      }
      case "workspace": {
        const v = parse(rest, { label: { type: "string" } }, true);
        if (v === null) return EXIT.OK;
        const [action, ...args] = v._positionals;
        return await workspaceCommand(action, args, { ...(str(v.label) ? { label: str(v.label)! } : {}) });
      }
      case "setup": {
        const v = parse(rest, { port: { type: "string" }, host: { type: "string" }, "no-start": { type: "boolean" }, "no-pair": { type: "boolean" } });
        if (v === null) return EXIT.OK;
        const port = v.port === undefined ? undefined : Number(v.port);
        if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new UsageError("--port must be 1-65535");
        return await setupCommand({ ...(port ? { port } : {}), ...(str(v.host) ? { host: str(v.host)! } : {}), start: v["no-start"] !== true, pair: v["no-pair"] !== true });
      }
      case "serve": {
        const v = parse(rest, { port: { type: "string" }, host: { type: "string" } });
        if (v === null) return EXIT.OK;
        return await serveCommand({ ...(v.port ? { port: Number(v.port) } : {}), ...(str(v.host) ? { host: str(v.host)! } : {}) });
      }
      case "server": {
        const v = parse(rest, { follow: { type: "boolean", short: "f" } }, true);
        if (v === null) return EXIT.OK;
        return await serverCommand(v._positionals[0], { follow: v.follow === true });
      }
      case "restart":
        if (parse(rest, {}) === null) return EXIT.OK;
        return await restartCommand();
      case "version":
        if (parse(rest, {}) === null) return EXIT.OK;
        return versionCommand();
      case "update": {
        const v = parse(rest, { check: { type: "boolean" }, version: { type: "string" }, rollback: { type: "boolean" }, restart: { type: "boolean" }, prune: { type: "boolean" } });
        if (v === null) return EXIT.OK;
        const modes = [v.check, v.rollback, v.restart, v.prune].filter((x) => x === true).length;
        if (modes > 1 || ((v.rollback || v.restart || v.prune) && v.version !== undefined)) throw new UsageError("choose one of --check, --rollback, --restart, --prune (--version only with a plain update or --check)");
        return await updateCommand({ check: v.check === true, version: str(v.version), rollback: v.rollback === true, restart: v.restart === true, prune: v.prune === true });
      }
      case "uninstall-server": {
        const v = parse(rest, { purge: { type: "boolean" } });
        if (v === null) return EXIT.OK;
        return uninstallServerCommand({ purge: v.purge === true });
      }
      case "pair": {
        const v = parse(rest, { "no-qr": { type: "boolean" }, "advertise-url": { type: "string" } });
        if (v === null) return EXIT.OK;
        return await pairCommand({ qr: v["no-qr"] !== true, advertiseUrl: str(v["advertise-url"]) });
      }
      case "status":
        if (parse(rest, {}) === null) return EXIT.OK;
        return await statusCommand();
      case "config": {
        const v = parse(rest, { policy: { type: "boolean" } }, true);
        if (v === null) return EXIT.OK;
        const [action, key, value] = v._positionals;
        if (action === "set" || action === "unset") return await configSetCommand(key, value, action === "unset");
        if (action) throw new UsageError(`unknown config action: ${action}`);
        return configCommand({ policy: v.policy === true });
      }
      case "logout":
        if (parse(rest, {}) === null) return EXIT.OK;
        return logoutCommand();
      case "request":
        return await request(rest, tail);
      case "run": {
        const v = parse(rest, { env: { type: "string" }, ttl: { type: "string" } }, true);
        if (v === null) return EXIT.OK;
        if (v._positionals.length > 1) throw new UsageError(`unexpected arguments: ${v._positionals.slice(1).join(" ")} (pass agent args after "--")`);
        const ttl = v.ttl === undefined ? undefined : Number(v.ttl);
        if (ttl !== undefined && (!Number.isInteger(ttl) || ttl <= 0)) throw new UsageError("--ttl must be a positive integer");
        return await runAgentCommand({ agent: v._positionals[0], args: tail ?? [], env: str(v.env), ttl });
      }
      case "install": {
        const v = parse(rest, { project: { type: "string" }, user: { type: "boolean" }, yes: { type: "boolean" }, env: { type: "string" }, ttl: { type: "string" } }, true);
        if (v === null) return EXIT.OK;
        const ttl = v.ttl === undefined ? undefined : Number(v.ttl);
        if (ttl !== undefined && (!Number.isInteger(ttl) || ttl <= 0)) throw new UsageError("--ttl must be a positive integer");
        if (v._positionals[0] === "codex") {
          return await installCodexCommand({ project: str(v.project), user: v.user === true, yes: v.yes === true, env: str(v.env), ttl });
        }
        if (v._positionals[0] === "cursor") {
          return await installCursorCommand({ project: str(v.project), user: v.user === true, yes: v.yes === true, env: str(v.env), ttl });
        }
        return await installCommand({
          agent: v._positionals[0],
          project: str(v.project),
          user: v.user === true,
          yes: v.yes === true,
          env: str(v.env),
          ttl,
        });
      }
      case "uninstall": {
        const v = parse(rest, { project: { type: "string" }, user: { type: "boolean" }, purge: { type: "boolean" }, yes: { type: "boolean" }, "dry-run": { type: "boolean" } }, true);
        if (v === null) return EXIT.OK;
        if (v._positionals.length === 0) {
          if (v.project !== undefined || v.user) throw new UsageError("--project/--user need an integration: agentgate uninstall claude-code …");
          return await uninstallAllCommand({ purge: v.purge === true, yes: v.yes === true, dryRun: v["dry-run"] === true });
        }
        if (v.purge || v.yes || v["dry-run"]) throw new UsageError("--purge/--yes/--dry-run apply to a full `agentgate uninstall` (no integration name)");
        if (v._positionals[0] === "cursor") return uninstallCursorCommand({ project: str(v.project), user: v.user === true });
        if (v._positionals[0] === "codex") return uninstallCodexCommand({ project: str(v.project), user: v.user === true });
        return uninstallCommand({ agent: v._positionals[0], project: str(v.project), user: v.user === true });
      }
      case "mcp": {
        const sub = rest.find((a) => !a.startsWith("-"));
        const subRest = sub === undefined ? rest : rest.filter((_, i) => i !== rest.indexOf(sub));
        if (sub === "wrap") {
          const v = parse(subRest, { name: { type: "string" }, env: { type: "string" }, ttl: { type: "string" } });
          if (v === null) return EXIT.OK;
          const ttl = v.ttl === undefined ? undefined : Number(v.ttl);
          if (ttl !== undefined && (!Number.isInteger(ttl) || ttl <= 0)) throw new UsageError("--ttl must be a positive integer");
          return await mcpWrap({ name: str(v.name), env: str(v.env), ...(ttl ? { ttl } : {}), argv: tail ?? [] });
        }
        if (sub === "install" || sub === "uninstall") {
          const v = parse(subRest, { client: { type: "string" }, project: { type: "string" }, server: { type: "string", multiple: true }, all: { type: "boolean" } });
          if (v === null) return EXIT.OK;
          const servers = Array.isArray(v.server) ? (v.server as string[]) : [];
          const opts = { client: str(v.client), project: str(v.project), servers, all: v.all === true };
          return sub === "install" ? mcpInstall(opts) : mcpUninstall(opts);
        }
        if (sub === "status") {
          const v = parse(subRest, { project: { type: "string" } });
          if (v === null) return EXIT.OK;
          return mcpStatus({ project: str(v.project) });
        }
        throw new UsageError("usage: agentgate mcp <wrap|install|uninstall|status> …");
      }
      case "exec": {
        // Every failure here must be "blocked" (77), never a usage code the caller might misread.
        try {
          const v = parse(rest, { approval: { type: "string" } });
          if (v === null) return EXIT.OK;
          return await execCommand({ approvalId: str(v.approval), argv: tail ?? [] });
        } catch (err) {
          process.stderr.write(`${blockedLine("usage", (err as Error).message)}\n`);
          return EXIT.BLOCKED;
        }
      }
      case "hook": {
        // Claude Code: exit 2 = block; anything else non-zero would FAIL OPEN.
        try {
          const v = parse(rest, {}, true);
          if (v === null) return 2;
          const agent = v._positionals[0];
          // Cursor: always answers with permission JSON (deny on any failure), exit 0.
          if (agent === "cursor") return await cursorHookCommand();
          if (agent && agent !== "claude-code") {
            if (!/^[a-z][a-z0-9_-]{0,63}$/.test(agent)) throw new Error(`unsupported hook '${agent}'`);
            return await providerHookCommand(agent);
          }
          return await hookCommand(agent);
        } catch (err) {
          process.stderr.write(`AgentGate blocked this action: ${(err as Error).message}\n`);
          return 2;
        }
      }
      case undefined: {
        const v = parse(rest, {});
        if (v?.version) {
          out(CLI_VERSION);
          return EXIT.OK;
        }
        out(HELP);
        return v === null ? EXIT.OK : EXIT.USAGE;
      }
      default:
        log.fail(`unknown command: ${cmd}`);
        out(HELP);
        return EXIT.USAGE;
    }
  } catch (err) {
    if (err instanceof UsageError) {
      log.fail(err.message);
      return EXIT.USAGE;
    }
    throw err;
  }
}

async function request(rest: string[], tail: string[] | null): Promise<number> {
  const v = parse(
    rest,
    {
      "agent-type": { type: "string" },
      env: { type: "string" },
      repo: { type: "string" },
      branch: { type: "string" },
      ttl: { type: "string" },
      "dry-run": { type: "boolean" },
    },
    true,
  );
  if (v === null) return EXIT.OK;
  // Without "--", bare positionals are accepted as the command (flags would be ambiguous).
  const commandArgv = tail ?? v._positionals;
  if (tail && v._positionals.length) throw new UsageError(`unexpected arguments before "--": ${v._positionals.join(" ")}`);

  const ttl = v.ttl === undefined ? 120 : Number(v.ttl);
  if (!Number.isInteger(ttl) || ttl <= 0) throw new UsageError("--ttl must be a positive integer (seconds; server clamps to 30–900)");
  const agentType = str(v["agent-type"]) ?? "cli";
  if (!/^[a-z][a-z0-9_.-]*$/.test(agentType)) throw new UsageError("--agent-type must be a lowercase identifier");

  return requestCommand({
    argv: commandArgv,
    agentType,
    env: str(v.env),
    repo: str(v.repo),
    branch: str(v.branch),
    ttl,
    dryRun: v["dry-run"] === true,
  });
}

class UsageError extends Error {}

interface Values {
  [key: string]: string | boolean | string[] | undefined;
  _positionals: string[];
}

/** Returns parsed values, or null if --help was printed. Throws UsageError. */
function parse(args: string[], options: ParseArgsConfig["options"], allowPositionals = false): Values | null {
  let parsed;
  try {
    parsed = parseArgs({ args, options: { ...GLOBAL, ...options }, strict: true, allowPositionals });
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
  const values = parsed.values as Record<string, string | boolean | undefined>;
  setVerbose(values.verbose === true);
  if (values.help) {
    out(HELP);
    return null;
  }
  return { ...values, _positionals: parsed.positionals };
}

function str(v: string | boolean | string[] | undefined): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
