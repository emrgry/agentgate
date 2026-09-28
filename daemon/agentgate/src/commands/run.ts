import { spawn } from "node:child_process";
import { accessSync, constants as fsc, mkdtempSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { hostname, tmpdir, constants as osc } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ourGroups } from "../claude-settings.ts";
import { shellQuote } from "../action.ts";
import { pruneApprovals } from "../approval-store.ts";
import { describeError } from "../authorize.ts";
import { AgentGateClient } from "../client/index.ts";
import { agentgateHome, keyFingerprint } from "../config.ts";
import { EXIT } from "../exit-codes.ts";
import { c, log } from "../output.ts";
import { loadEffectivePolicy } from "../policy.ts";
import { requireLogin } from "../runtime.ts";
import { findInstalled } from "./install.ts";

/** Claude hook timeout (seconds). The hook's own deadline is this minus 30 s. */
export const HOOK_TIMEOUT_S = 600;

export function hookShimPath(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "bin", "agentgate-hook.sh");
}

export interface RunOptions {
  agent: string | undefined;
  args: string[];
  env?: string;
  ttl?: number;
}

/**
 * `agentgate run claude [--env E] [--ttl N] [-- claude args…]`
 * Starts an AgentGate session and launches Claude Code with a PreToolUse hook (via
 * `claude --settings <tmpfile>`, merged with the user's own settings for this run only).
 */
export async function runAgentCommand(o: RunOptions): Promise<number> {
  if (o.agent !== "claude") {
    log.fail(`unsupported agent '${o.agent ?? ""}'. Supported: claude`);
    return EXIT.USAGE;
  }
  const claude = process.env.AGENTGATE_CLAUDE_BIN || findOnPath("claude");
  if (!claude) {
    log.fail("Claude Code (`claude`) was not found on PATH.");
    log.step("Install it with:  npm install -g @anthropic-ai/claude-code   (https://docs.claude.com/en/docs/claude-code)");
    log.step("then re-run:      agentgate run claude");
    return EXIT.USAGE;
  }

  // Preflight: refuse to start an ungated-in-practice agent (every hook call would block).
  let config;
  try {
    config = await requireLogin();
    loadEffectivePolicy();
  } catch (err) {
    log.fail(`cannot start: ${(err as Error).message}`);
    return EXIT.BLOCKED;
  }
  const client = new AgentGateClient({ server: config.server, accessToken: config.access_token, debug: log.debug });
  let sessionId: string;
  try {
    const keys = await client.keys();
    if (keys.approval_signing_key.pem.trim() !== config.signing_key.pem.trim()) {
      throw new Error(
        `server signing key ${keyFingerprint(keys.approval_signing_key.pem)} ≠ pinned ${keyFingerprint(config.signing_key.pem)} — run \`agentgate login\``,
      );
    }
    const agent = await client.registerAgent({ name: hostname(), type: "claude-code", machine_id: config.machine_id });
    sessionId = (await client.createSession(agent.id)).id;
  } catch (err) {
    log.fail(`cannot start: ${describeError(err)}`);
    return EXIT.BLOCKED;
  }

  // An installed hook (agentgate install claude-code) already gates this project/user.
  // Adding ours too would make every action ask twice; reuse it with our session instead.
  const installed = findInstalled(process.cwd());
  const useInstalled = installed.length > 0 && installed.every((i) => i.problems.length === 0);
  if (installed.some((i) => i.problems.length)) {
    log.fail(`broken AgentGate hook install: ${installed.flatMap((i) => i.problems).join("; ")} — re-run \`agentgate install claude-code\``);
    return EXIT.BLOCKED;
  }

  const home = agentgateHome();
  const dir = mkdtempSync(join(tmpdir(), "agentgate-run-"));
  const settingsPath = join(dir, "settings.json");
  const hookEnv: Record<string, string> = {
    AGENTGATE_SESSION_ID: sessionId,
    AGENTGATE_HOME: home,
    AGENTGATE_NODE: process.execPath,
    AGENTGATE_HOOK_TIMEOUT_S: String(HOOK_TIMEOUT_S),
    ...(o.env ? { AGENTGATE_ENV: o.env } : {}),
    ...(o.ttl ? { AGENTGATE_TTL: String(o.ttl) } : {}),
  };
  // Env is also put on the command line so the hook works even if Claude doesn't pass
  // its environment through. Session id / paths only — no tokens.
  const hookCommand = `${Object.entries(hookEnv)
    .map(([k, v]) => `${k}=${shellQuote(v)}`)
    .join(" ")} ${shellQuote(hookShimPath())}`;
  const groups = ourGroups(hookCommand);
  const settings = { hooks: { PreToolUse: [groups.PreToolUse], PostToolUse: [groups.PostToolUse], SessionEnd: [groups.SessionEnd] } };
  writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
  chmodSync(settingsPath, 0o600);

  log.ok(`session ${c.bold(sessionId)} — Claude Code actions are gated by AgentGate ${c.dim(`(${config.server})`)}`);
  log.debug(`settings ${settingsPath}`);

  const cleanup = async () => {
    await client.endSession(sessionId, 3_000).catch((e) => log.warn(`could not end session: ${describeError(e)}`));
    pruneApprovals(sessionId);
    rmSync(dir, { recursive: true, force: true });
  };

  const forward = (sig: NodeJS.Signals) => {
    // SIGINT reaches Claude directly via the terminal's process group.
    if (sig !== "SIGINT") child.kill(sig);
  };
  if (useInstalled) log.step(c.dim(`using installed hook (${installed.map((i) => i.file).join(", ")})`));
  const child = spawn(claude, useInstalled ? o.args : ["--settings", settingsPath, ...o.args], {
    stdio: "inherit",
    env: { ...process.env, ...hookEnv },
  });
  for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(s, forward);

  const code = await new Promise<number>((resolveP) => {
    child.once("error", (err) => {
      log.fail(`failed to start claude: ${err.message}`);
      resolveP(127);
    });
    child.once("exit", (code, signal) => resolveP(signal ? 128 + (osc.signals[signal] ?? 0) : (code ?? 1)));
  });
  for (const s of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.off(s, forward);
  await cleanup();
  log.step(`session ${sessionId} ended ${c.dim(`(claude exit ${code})`)}`);
  return code;
}

export function findOnPath(bin: string): string | null {
  for (const d of (process.env.PATH ?? "").split(delimiter)) {
    if (!d) continue;
    const p = join(d, bin);
    try {
      accessSync(p, fsc.X_OK);
      if (statSync(p).isFile()) return p;
    } catch {
      /* next */
    }
  }
  return null;
}
