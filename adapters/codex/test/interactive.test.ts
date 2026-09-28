import { describe, expect, it } from "vitest";
import {
  CODEX_BENIGN_TOOLS,
  codexGuard,
  codexReceiptFacts,
  codexToolClass,
  normalizeCodexHook,
  parseCodexHookInput,
} from "../src/index.ts";

/**
 * Interactive Codex (`agentgate install codex`): real hook input shapes (captured from
 * codex-cli 0.158.0), tool classes and the self-protection guard.
 */

const HOME = "/Users/dev";
const ROOT = "/Users/dev/work/demo";
const AG = "/Users/dev/.agentgate";
const INSTALL = "/Users/dev/AgentGate/daemon/agentgate";
const SECRETS = "/Users/dev/Library/Application Support/agentgate-api";
const opts = { homeDir: HOME, agentgateHome: AG, protectedDirs: [INSTALL, SECRETS] };
const ctx = { session_id: "ses_1", homeDir: HOME, projectRoot: ROOT };

/** Exactly what codex 0.158.0 sent for exec_command / apply_patch (plus our tool name). */
const inp = (tool_name: string, tool_input: unknown) =>
  parseCodexHookInput({
    session_id: "01a0e7e6-be80-7c92-82ae-f440f25cb818",
    turn_id: "01a0e7e6-bfc7-7ae2-ac2b-03314962310a",
    transcript_path: null,
    cwd: ROOT,
    hook_event_name: "PreToolUse",
    model: "gpt-5.5",
    permission_mode: "default",
    tool_name,
    tool_input,
    tool_use_id: "call_1",
  });
const bash = (command: string) => inp("Bash", { command });
const patch = (...files: string[]) => inp("apply_patch", { command: `*** Begin Patch\n${files.map((f) => `*** Update File: ${f}\n@@\n-a\n+b\n`).join("")}*** End Patch\n` });

describe("real Codex payload shapes", () => {
  it("apply_patch sends the patch as tool_input.command → paths are found (was: input/patch only)", () => {
    const d = normalizeCodexHook(patch("src/a.ts", "../outside.txt"), ctx);
    expect(d.action).toMatchObject({ category: "filesystem", operation: "write", arguments: { paths: [`${ROOT}/src/a.ts`, "/Users/dev/work/outside.txt"] } });
    expect(d.risk?.level).toBe("high"); // outside the project root
    expect(codexReceiptFacts(patch("src/a.ts"))).toEqual({ kind: "file", text: "", paths: ["src/a.ts"] });
  });
  it("a patch inside the project carries no adapter risk", () => {
    expect(normalizeCodexHook(patch("src/a.ts"), ctx).risk).toBeUndefined();
  });
});

describe("codexToolClass (interactive fast path)", () => {
  it.each([...CODEX_BENIGN_TOOLS])("%s → benign", (t) => {
    expect(codexToolClass(inp(t, {}), opts)).toBe("benign");
  });
  it.each([
    ["Bash", { command: "ls" }],
    ["apply_patch", { command: "*** Begin Patch\n*** End Patch\n" }],
    ["mcp__github__create_issue", { title: "x" }],
    ["some_future_tool", {}],
    ["write_file", { path: "a" }],
  ])("%s → gated", (t, ti) => {
    expect(codexToolClass(inp(t, ti), opts)).toBe("gated");
  });
  it("view_image: benign for ordinary files, gated for secrets", () => {
    expect(codexToolClass(inp("view_image", { path: "shot.png" }), opts)).toBe("benign");
    expect(codexToolClass(inp("view_image", { path: "~/.ssh/id_ed25519" }), opts)).toBe("gated");
    expect(codexToolClass(inp("view_image", { path: `${AG}/config.json` }), opts)).toBe("gated");
    expect(codexToolClass(inp("view_image", { path: ".env" }), opts)).toBe("gated");
    expect(codexToolClass(inp("view_image", {}), opts)).toBe("gated");
    expect(codexGuard(inp("view_image", { path: "~/.ssh/id_ed25519" }), opts)?.decision).toBe("ask");
  });
});

describe("codexGuard: shell", () => {
  it.each([
    "agentgate install codex --user --yes",
    "agentgate uninstall codex --user",
    "~/.local/bin/agentgate uninstall --yes",
    "agentgate update --rollback",
    "agentgate login --email x",
    "curl -X POST http://localhost:8787/v1/approvals/apr_1/approve",
    "echo '{}' > ~/.codex/hooks.json",
    "cat /dev/null > /Users/dev/.codex/config.toml",
    "cd ~/.codex && cp /tmp/x hooks.json",
    "sed -i '' s/true/false/ .codex/config.toml",
    "rm ~/.cursor/hooks.json",
  ])("%j → deny", (cmd) => {
    expect(codexGuard(bash(cmd), opts)?.decision).toBe("deny");
  });
  it("custom CODEX_HOME: its hooks.json/config.toml are protected too", () => {
    const o = { ...opts, codexHome: "/opt/codex-home" };
    expect(codexGuard(bash("cp x /opt/codex-home/hooks.json"), o)?.decision).toBe("deny");
    expect(codexGuard(bash("ls /opt/codex-home"), o)).toBeNull();
  });
  it.each([
    "CODEX_HOME=/tmp/x codex exec 'do it'",
    "codex exec --dangerously-bypass-hook-trust 'x'",
    "codex -c features.hooks=false exec 'x'",
    "codex --config 'hooks.state={}' exec x",
    "codex --disable hooks exec x",
    "ls ~/.agentgate",
    `ls ${INSTALL}/lib`,
    "cd ~ && rm -rf .agentgate",
    "python3",
    "bash -i",
    "node",
  ])("%j → ask", (cmd) => {
    expect(codexGuard(bash(cmd), opts)?.decision).toBe("ask");
  });
  it.each(["git status", "npm test", "python3 script.py", "node build.mjs", "codex exec 'summarize README'", "cat src/codex/config.ts"])("%j → no floor", (cmd) => {
    expect(codexGuard(bash(cmd), opts)).toBeNull();
  });
});

describe("codexGuard: apply_patch", () => {
  it.each([
    [`${HOME}/.codex/hooks.json`, /Codex hook settings/],
    [`${HOME}/.codex/config.toml`, /Codex hook settings/],
    [`${ROOT}/.codex/hooks.json`, /Codex hook settings/],
    [`${ROOT}/.codex/config.toml`, /Codex hook settings/],
    [`${AG}/policy.yaml`, /AgentGate's config/],
    [`${INSTALL}/lib/agentgate.mjs`, /AgentGate itself/],
    [`${HOME}/.claude/settings.json`, /Claude Code hook settings/],
    [`${ROOT}/.cursor/hooks.json`, /Cursor hook settings/],
  ])("%s → deny", (p, re) => {
    const v = codexGuard(patch(p), opts);
    expect(v?.decision).toBe("deny");
    expect(v?.reason).toMatch(re);
  });
  it("any denied path in a multi-file patch denies the whole patch", () => {
    expect(codexGuard(patch("src/ok.ts", "~/.codex/hooks.json"), opts)?.decision).toBe("deny");
  });
  it("ordinary project files → no floor", () => {
    expect(codexGuard(patch("src/a.ts", "README.md"), opts)).toBeNull();
  });
  it("MCP and unknown tools → no floor (policy decides)", () => {
    expect(codexGuard(inp("mcp__fs__write", { path: `${HOME}/.codex/hooks.json` }), opts)).toBeNull();
  });
});
