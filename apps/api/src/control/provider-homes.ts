import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Per-managed-session provider homes (Codex: CODEX_HOME). A copy of the owner's credentials
 * and config plus AgentGate's PreToolUse hook — the owner's real ~/.codex is never modified.
 */

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** The PreToolUse command from the managed Claude hook settings (`agentgate serve` writes it). */
export function managedHookCommand(hookSettingsPath: string): string {
  const j = JSON.parse(readFileSync(hookSettingsPath, "utf8")) as { hooks?: { PreToolUse?: Array<{ hooks?: Array<{ command?: string }> }> } };
  const cmd = j.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command;
  if (typeof cmd !== "string" || !cmd) throw new Error("managed hook settings have no PreToolUse command");
  return cmd;
}

/** Hook command for a provider turn: pins the receipts file + control session, selects the provider hook. */
export function providerHookCommand(base: string, provider: string, o: { receipts: string; controlSession: string }): string {
  return `AGENTGATE_GATE_RECEIPTS=${shq(o.receipts)} AGENTGATE_CONTROL_SESSION=${shq(o.controlSession)} ${base} --agentgate-provider=${provider}`;
}

const safeId = (s: string) => s.replace(/[^A-Za-z0-9_-]/g, "_");

/**
 * Prepares `<base>/codex/<session>`: auth.json + config.toml copied from the owner's
 * CODEX_HOME (default ~/.codex), and hooks.json with the AgentGate PreToolUse hook.
 * Returns the directory (used as CODEX_HOME for the turn).
 */
export function prepareCodexHome(o: { baseDir: string; sessionId: string; ownerCodexHome: string; hookCommand: string; timeoutS?: number }): string {
  const dir = join(o.baseDir, "codex", safeId(o.sessionId));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const f of ["auth.json", "config.toml"]) {
    const src = join(o.ownerCodexHome, f);
    if (existsSync(src)) {
      copyFileSync(src, join(dir, f));
      chmodSync(join(dir, f), 0o600);
    }
  }
  const receipts = join(dir, "agentgate-receipts.jsonl");
  const command = providerHookCommand(o.hookCommand, "codex", { receipts, controlSession: o.sessionId });
  const hooks = {
    hooks: {
      PreToolUse: [{ matcher: ".*", hooks: [{ type: "command", command, timeout: o.timeoutS ?? 600 }] }],
    },
  };
  writeFileSync(join(dir, "hooks.json"), `${JSON.stringify(hooks, null, 2)}\n`, { mode: 0o600 });
  return dir;
}
