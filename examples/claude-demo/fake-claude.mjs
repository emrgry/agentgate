#!/usr/bin/env node
// Stand-in for the `claude` binary, for rehearsing the demo without Claude Code installed:
//   AGENTGATE_CLAUDE_BIN=examples/claude-demo/fake-claude.mjs agentgate run claude -- "git push origin main"
// It does what Claude Code does with the generated settings: pipes a PreToolUse event for a
// Bash call into the configured hook command, then runs the (possibly rewritten) command.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const settings = JSON.parse(readFileSync(args[args.indexOf("--settings") + 1], "utf8"));
const hook = settings.hooks.PreToolUse[0].hooks[0].command;
const command = args.filter((_, i) => i !== args.indexOf("--settings") && i !== args.indexOf("--settings") + 1).join(" ") || "git push origin main";

console.log(`[fake-claude] Bash: ${command}`);
const input = JSON.stringify({
  session_id: "fake-claude", transcript_path: "/dev/null", cwd: process.cwd(), permission_mode: "default",
  hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command, description: "demo" }, tool_use_id: "toolu_demo",
});
const h = spawnSync("/bin/sh", ["-c", hook], { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
if (h.status !== 0) {
  console.log(`[fake-claude] hook exit ${h.status} → BLOCKED: ${h.stderr.trim()}`);
  process.exit(1);
}
const out = h.stdout.trim() ? JSON.parse(h.stdout).hookSpecificOutput : null;
console.log(`[fake-claude] hook → ${out ? `${out.permissionDecision} (${out.permissionDecisionReason})` : "no decision (ungoverned)"}`);
const run = out?.updatedInput?.command ?? command;
if (out?.updatedInput) console.log(`[fake-claude] rewritten → ${run}`);
const e = spawnSync("/bin/sh", ["-c", run], { stdio: "inherit" });
console.log(`[fake-claude] command exit ${e.status}`);
process.exit(e.status ?? 1);
