import { describe, expect, it } from "vitest";
import { ClaudeCodeAdapter, PreToolUseInput, sensitivePathReason, SELF_MANAGEMENT_RE } from "../src/index.ts";

/**
 * Cross-agent protection for the Codex gate: a Claude Code agent (or any agent going through
 * this guard) must not edit Codex's hook config or run `agentgate install/uninstall codex`.
 */

const HOME = "/Users/dev";
const ROOT = "/Users/dev/work/demo";
const adapter = new ClaudeCodeAdapter({ homeDir: HOME, projectRoot: ROOT, agentgateHome: `${HOME}/.agentgate`, protectedDirs: [] });
const ev = (tool_name: string, tool_input: Record<string, unknown>) =>
  PreToolUseInput.parse({ hook_event_name: "PreToolUse", tool_name, tool_input, cwd: ROOT, session_id: "c" });

describe("Codex hook config is protected", () => {
  it.each([`${HOME}/.codex/hooks.json`, `${HOME}/.codex/config.toml`, `${ROOT}/.codex/hooks.json`, `${ROOT}/.codex/config.toml`, "/etc/codex/../x/.codex/requirements.toml"])(
    "Write %s → deny + high-risk path",
    (file_path) => {
      expect(adapter.guard(ev("Write", { file_path, content: "{}" }), ROOT)).toEqual({ decision: "deny", reason: "agents may not modify Codex hook settings" });
      expect(sensitivePathReason(file_path, { homeDir: HOME, projectRoot: ROOT })).toMatch(/Codex|AgentGate|outside/);
    },
  );
  it.each(["echo {} > ~/.codex/hooks.json", "cd ~/.codex && mv config.toml config.bak", "cp /tmp/h .codex/hooks.json"])("Bash %j → deny", (command) => {
    expect(adapter.guard(ev("Bash", { command }), ROOT)?.decision).toBe("deny");
  });
  it.each(["agentgate install codex --user --yes", "agentgate uninstall codex", "./daemon/agentgate/bin/agentgate.sh install codex --project ."])("Bash %j → deny (self-management)", (command) => {
    expect(SELF_MANAGEMENT_RE.test(command)).toBe(true);
    expect(adapter.guard(ev("Bash", { command }), ROOT)?.decision).toBe("deny");
  });
  it("unrelated codex usage is not affected", () => {
    expect(adapter.guard(ev("Bash", { command: "codex exec 'explain src/'" }), ROOT)).toBeNull();
    expect(adapter.guard(ev("Write", { file_path: `${ROOT}/src/codex.ts`, content: "x" }), ROOT)).toBeNull();
  });
});
