import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ClaudeCodeAdapter, PreToolUseInput, SELF_MANAGEMENT_RE, sensitivePathReason } from "@agentgate/adapter-claude-code";
import { DEFAULT_POLICY_YAML, evaluatePolicy, loadPolicyYaml } from "@agentgate/policy-engine";
import { describe, expect, it } from "vitest";
import {
  canonicalEvent,
  conversationKey,
  CursorAdapter,
  cwdOf,
  filePaths,
  isCursorPayload,
  isFileTool,
  mcpArguments,
  parseGateInput,
  renderAllow,
  renderDeny,
} from "../src/index.ts";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const HOME = "/Users/dev";
const ROOT = "/Users/dev/work/demo";
const AG = "/Users/dev/.agentgate";
const INSTALL = "/Users/dev/.agentgate/versions/0.3.0";
const adapter = new CursorAdapter({ homeDir: HOME, projectRoot: ROOT, agentgateHome: AG, protectedDirs: [INSTALL] });
const ctx = { session_id: "ses_1", cwd: ROOT, repo: "acme/demo", branch: "main" };

const fixture = (name: string, over: Record<string, unknown> = {}) => ({
  ...JSON.parse(readFileSync(join(FIX, "common.json"), "utf8")),
  ...JSON.parse(readFileSync(join(FIX, `${name}.json`), "utf8")),
  ...over,
});
const gi = (name: string, over: Record<string, unknown> = {}) => parseGateInput(fixture(name, over));

describe("contract parsing", () => {
  it("event names: Cursor camelCase and Claude PascalCase map to the same event", () => {
    expect(canonicalEvent("beforeShellExecution")).toBe("beforeShellExecution");
    expect(canonicalEvent("PreToolUse")).toBe("preToolUse");
    expect(canonicalEvent("SessionEnd")).toBe("sessionEnd");
    expect(canonicalEvent("UserPromptSubmit")).toBe("beforeSubmitPrompt");
  });

  it("detects Cursor payloads by cursor_version and keys sessions by conversation", () => {
    expect(isCursorPayload(fixture("beforeShellExecution"))).toBe(true);
    expect(isCursorPayload({ hook_event_name: "PreToolUse", session_id: "claude" })).toBe(false);
    expect(conversationKey(fixture("beforeShellExecution"))).toBe("cursor:conv-1111");
    expect(conversationKey(fixture("sessionEnd", { conversation_id: undefined }))).toBe("cursor:conv-1111");
    expect(conversationKey({})).toBeNull();
  });

  it.each([
    ["missing command", { hook_event_name: "beforeShellExecution", cwd: ROOT }],
    ["missing file_path", { hook_event_name: "beforeReadFile" }],
    ["missing tool_name", { hook_event_name: "beforeMCPExecution", tool_input: "{}" }],
    ["unknown event", { hook_event_name: "afterFileEdit", file_path: "x" }],
    ["not an object", "nope"],
  ])("rejects %s (the hook turns this into deny)", (_n, json) => {
    expect(() => parseGateInput(json)).toThrow();
  });

  it("cwd: payload cwd, Shell working_directory, else first workspace root", () => {
    expect(cwdOf(gi("beforeShellExecution", { cwd: "/tmp/x" }))).toBe("/tmp/x");
    expect(cwdOf(gi("beforeMCPExecution.stdio"))).toBe(ROOT);
    expect(cwdOf(gi("preToolUse.shell", { cwd: undefined }))).toBe(ROOT);
  });

  it("MCP tool_input arrives as a JSON string; unparseable text is kept (and hashed)", () => {
    expect(mcpArguments('{"a":1}')).toEqual({ a: 1 });
    expect(mcpArguments("[1,2]")).toEqual({ value: [1, 2] });
    expect(mcpArguments("not json")).toEqual({ raw: "not json" });
    expect(mcpArguments({ b: 2 })).toEqual({ b: 2 });
    expect(mcpArguments(undefined)).toEqual({});
  });
});

describe("normalize (native install)", () => {
  it("beforeShellExecution → shell.execute, agent cursor + version, context", () => {
    const d = adapter.normalize(gi("beforeShellExecution"), ctx)!;
    expect(d.agent).toEqual({ type: "cursor", version: "3.1.4" });
    expect(d.action).toEqual({ category: "shell", operation: "execute", tool: "Shell", command: "git push origin main", cwd: ROOT });
    expect(d.context).toMatchObject({ repo: "acme/demo", cursor_conversation_id: "conv-1111", cursor_generation_id: "gen-2222", cursor_hook: "beforeShellExecution", cursor_sandbox: "false" });
  });

  it("beforeMCPExecution (stdio) → mcp.invoke with parsed arguments, gateway-compatible tool name", () => {
    const d = adapter.normalize(gi("beforeMCPExecution.stdio"), ctx)!;
    expect(d.action).toMatchObject({ category: "mcp", operation: "invoke", tool: "github/delete_repo", arguments: { server: "github", tool: "delete_repo", arguments: { owner: "acme", repo: "api" } } });
    expect(d.resource).toMatchObject({ type: "mcp_server", name: "github" });
    expect(d.risk).toBeUndefined();
  });

  it("beforeMCPExecution (HTTP) keeps the URL in context; a missing server name is high risk", () => {
    expect(adapter.normalize(gi("beforeMCPExecution.http"), ctx)!.context).toMatchObject({ mcp_url: "https://mcp.linear.app/sse" });
    expect(adapter.normalize(gi("beforeMCPExecution.stdio", { mcp_server_name: undefined }), ctx)!.risk?.level).toBe("high");
  });

  it("beforeReadFile: only sensitive reads are governed", () => {
    const d = adapter.normalize(gi("beforeReadFile"), ctx)!;
    expect(d.action).toMatchObject({ category: "filesystem", operation: "read", arguments: { path: `${ROOT}/.env` } });
    expect(d.risk?.level).toBe("high");
    expect(adapter.normalize(gi("beforeReadFile", { file_path: `${ROOT}/src/app.ts` }), ctx)).toBeNull();
    expect(adapter.normalize(gi("beforeReadFile", { file_path: `${HOME}/.ssh/id_ed25519` }), ctx)!.risk?.level).toBe("high");
  });

  it("preToolUse Write → filesystem.write bound to the exact input (hash, bytes)", () => {
    const d = adapter.normalize(gi("preToolUse.write"), ctx)!;
    expect(d.action).toMatchObject({ category: "filesystem", operation: "write", tool: "Write", arguments: { path: `${ROOT}/src/app.ts`, bytes: 10 } });
    expect((d.action.arguments as { input_sha256: string }).input_sha256).toMatch(/^[0-9a-f]{64}$/);
    const other = adapter.normalize(gi("preToolUse.write", { tool_input: { file_path: "src/app.ts", contents: "export {}\n// x\n" } }), ctx)!;
    expect((other.action.arguments as { input_sha256: string }).input_sha256).not.toBe((d.action.arguments as { input_sha256: string }).input_sha256);
    expect(d.context).toMatchObject({ tool_use_id: "tu-1" });
  });

  it("preToolUse Delete → filesystem.delete", () => {
    expect(adapter.normalize(gi("preToolUse.delete"), ctx)!.action).toMatchObject({ category: "filesystem", operation: "delete", arguments: { path: `${ROOT}/old.txt` } });
  });

  it("preToolUse: sensitive/outside paths are high risk; no path is high risk", () => {
    expect(adapter.normalize(gi("preToolUse.write", { tool_input: { file_path: "/etc/hosts" } }), ctx)!.risk?.level).toBe("high");
    expect(adapter.normalize(gi("preToolUse.write", { tool_input: { file_path: "~/.zshrc" } }), ctx)!.risk?.level).toBe("high");
    expect(adapter.normalize(gi("preToolUse.write", { tool_input: { contents: "x" } }), ctx)!.risk).toEqual({ level: "high", reason: "Write without a recognizable file path" });
  });

  it("preToolUse: Shell / Read / MCP / Todo are left to their dedicated hooks (native mode)", () => {
    expect(adapter.normalize(gi("preToolUse.shell"), ctx)).toBeNull();
    expect(adapter.normalize(gi("preToolUse.write", { tool_name: "Read" }), ctx)).toBeNull();
    expect(adapter.normalize(gi("preToolUse.write", { tool_name: "MCP:EditIssue" }), ctx)).toBeNull();
    expect(adapter.normalize(gi("preToolUse.write", { tool_name: "TodoWrite" }), ctx)).toBeNull();
    expect(adapter.normalize(gi("preToolUse.write", { tool_name: "Grep" }), ctx)).toBeNull();
  });

  it("file tool classification + path extraction", () => {
    for (const t of ["Write", "Edit", "StrReplace", "Delete", "ApplyPatch", "EditNotebook", "MultiEdit"]) expect(isFileTool(t)).toBe(true);
    for (const t of ["Shell", "Read", "Grep", "Task", "TodoWrite", "MCP:write_thing", "WebFetch"]) expect(isFileTool(t)).toBe(false);
    expect(filePaths({ target_file: "a", paths: ["b", "a"], old_path: "c" })).toEqual(["a", "c", "b"]);
  });
});

describe("normalize (Claude Code hook imported by Cursor)", () => {
  const imp = { mode: "claude-import" as const };
  it("preToolUse must govern Shell, Read and MCP itself", () => {
    expect(adapter.normalize(gi("preToolUse.shell"), ctx, imp)!.action).toMatchObject({ category: "shell", command: "npm install" });
    expect(adapter.normalize(gi("preToolUse.write", { tool_name: "Read", tool_input: { file_path: ".env" } }), ctx, imp)!.action.operation).toBe("read");
    const m = adapter.normalize(gi("preToolUse.write", { tool_name: "MCP:delete_repo", tool_input: { repo: "x" } }), ctx, imp)!;
    expect(m.action).toMatchObject({ category: "mcp", arguments: { server: "(unknown)", tool: "delete_repo" } });
    expect(m.risk?.level).toBe("high");
  });
});

describe("render", () => {
  it("allow is exactly {permission: allow}; deny carries messages (read: user_message only)", () => {
    expect(renderAllow()).toEqual({ permission: "allow" });
    expect(renderDeny("beforeShellExecution", "u", "a")).toEqual({ permission: "deny", user_message: "u", agent_message: "a" });
    expect(renderDeny("beforeReadFile", "u", "a")).toEqual({ permission: "deny", user_message: "u" });
    // Never Cursor's own "ask": the human decides on the phone.
    expect(JSON.stringify([renderAllow(), renderDeny("preToolUse", "u", "a")])).not.toMatch(/"ask"/);
  });
});

describe("guard: agents may not reconfigure their own gate", () => {
  it.each([
    "agentgate install cursor --user --yes",
    "agentgate uninstall cursor --user",
    "'/Users/dev/.agentgate/current/bin/agentgate' uninstall cursor --project .",
    "npx agentgate --verbose install cursor",
  ])("Shell %j → deny (self-management)", (command) => {
    expect(SELF_MANAGEMENT_RE.test(command)).toBe(true);
    expect(adapter.guard(gi("beforeShellExecution", { command }), ROOT)?.decision).toBe("deny");
  });

  it.each([
    "echo '{}' > ~/.cursor/hooks.json",
    "rm .cursor/hooks.json",
    "cd ~/.cursor && cp /tmp/x hooks.json",
    "sed -i '' 's/agentgate//' \"$HOME/.cursor/hooks.json\"",
    "python3 -c \"open('.cursor/hooks.json','w')\"",
    "cat /Library/Application\\ Support/Cursor/hooks.json",
  ])("Shell touching Cursor hooks.json %j → deny", (command) => {
    expect(adapter.guard(gi("beforeShellExecution", { command }), ROOT)?.decision).toBe("deny");
  });

  it("the same guard applies to Claude Code agents", () => {
    const claude = new ClaudeCodeAdapter({ homeDir: HOME, projectRoot: ROOT, agentgateHome: AG });
    const ev = (tool_name: string, tool_input: Record<string, unknown>) => PreToolUseInput.parse({ hook_event_name: "PreToolUse", tool_name, tool_input, cwd: ROOT });
    expect(claude.guard(ev("Write", { file_path: `${HOME}/.cursor/hooks.json` }), ROOT)?.decision).toBe("deny");
    expect(claude.guard(ev("Edit", { file_path: ".cursor/hooks.json" }), ROOT)?.decision).toBe("deny");
    expect(claude.guard(ev("Bash", { command: "echo {} > ~/.cursor/hooks.json" }), ROOT)?.decision).toBe("deny");
    expect(sensitivePathReason(`${ROOT}/.cursor/hooks.json`, { homeDir: HOME, projectRoot: ROOT })).toMatch(/Cursor hook/);
  });

  it.each([`${HOME}/.cursor/hooks.json`, ".cursor/hooks.json", `${ROOT}/sub/.cursor/hooks.json`])("file tools writing %s → deny", (p) => {
    expect(adapter.guard(gi("preToolUse.write", { tool_input: { file_path: p } }), ROOT)?.decision).toBe("deny");
    expect(adapter.guard(gi("preToolUse.delete", { tool_input: { path: p } }), ROOT)?.decision).toBe("deny");
  });

  it("file tools writing AgentGate's own files → deny; any of several paths counts", () => {
    expect(adapter.guard(gi("preToolUse.write", { tool_input: { file_path: `${AG}/policy.yaml` } }), ROOT)?.decision).toBe("deny");
    expect(adapter.guard(gi("preToolUse.write", { tool_input: { paths: ["ok.txt", `${INSTALL}/bin/agentgate-hook.sh`] } }), ROOT)?.decision).toBe("deny");
    expect(adapter.guard(gi("preToolUse.write"), ROOT)).toBeNull();
  });

  it("reads of AgentGate secrets / .env → ask; MCP calls referencing protected paths → ask", () => {
    expect(adapter.guard(gi("beforeReadFile", { file_path: `${AG}/config.json` }), ROOT)?.decision).toBe("ask");
    expect(adapter.guard(gi("beforeReadFile"), ROOT)?.decision).toBe("ask");
    expect(adapter.guard(gi("beforeMCPExecution.stdio", { tool_input: '{"path":"~/.cursor/hooks.json"}' }), ROOT)?.decision).toBe("ask");
    expect(adapter.guard(gi("beforeMCPExecution.stdio"), ROOT)).toBeNull();
  });

  it("an ordinary command has no guard verdict", () => {
    expect(adapter.guard(gi("beforeShellExecution", { command: "ls -la" }), ROOT)).toBeNull();
  });
});

describe("default policy protects Cursor hooks.json", () => {
  const policy = loadPolicyYaml(DEFAULT_POLICY_YAML);
  it.each(["echo {} > ~/.cursor/hooks.json", "cp x .cursor/hooks.json", "rm -f sub/.cursor/hooks.json"])("%j → deny", (command) => {
    const d = adapter.normalize(gi("beforeShellExecution", { command }), ctx)!;
    expect(evaluatePolicy(policy, d, { home: HOME }).decision).toBe("deny");
  });
  it("a Write tool call to .cursor/hooks.json → deny", () => {
    const d = adapter.normalize(gi("preToolUse.write", { tool_input: { file_path: ".cursor/hooks.json" } }), ctx)!;
    expect(evaluatePolicy(policy, d, { home: HOME }).decision).toBe("deny");
  });
});
