import { describe, expect, it } from "vitest";
import { ClaudeCodeAdapter, parseMcpToolName, PreToolUseInput, sensitivePathReason } from "../src/index.ts";

const HOME = "/Users/dev";
const ROOT = "/Users/dev/work/demo";
const adapter = new ClaudeCodeAdapter({ homeDir: HOME, projectRoot: ROOT });
const ctx = { session_id: "ses_1", cwd: ROOT, repo: "agentgate/demo", branch: "main" };

function ev(tool_name: string, tool_input: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return PreToolUseInput.parse({
    session_id: "claude-sess",
    transcript_path: "/tmp/t.jsonl",
    cwd: ROOT,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name,
    tool_input,
    tool_use_id: "toolu_1",
    some_future_field: { ignored: true },
    ...extra,
  });
}

describe("normalize", () => {
  it("Bash → shell.execute with command + cwd, agent claude-code, context", () => {
    const d = adapter.normalize(ev("Bash", { command: "git push origin main", description: "push", timeout: 1000 }), ctx)!;
    expect(d.agent).toEqual({ type: "claude-code" });
    expect(d.action).toEqual({ category: "shell", operation: "execute", tool: "Bash", command: "git push origin main", cwd: ROOT });
    expect(d.context).toMatchObject({ repo: "agentgate/demo", branch: "main", claude_session_id: "claude-sess", tool_use_id: "toolu_1" });
    expect(d.risk).toBeUndefined();
    expect(d.session_id).toBe("ses_1");
  });

  it("Bash carries the environment into resource", () => {
    const d = adapter.normalize(ev("Bash", { command: "kubectl apply -f x" }), { ...ctx, environment: "production" })!;
    expect(d.resource).toEqual({ environment: "production" });
  });

  it.each([
    ["Write", { file_path: "src/app.ts", content: "x" }, `${ROOT}/src/app.ts`, undefined],
    ["Edit", { file_path: `${ROOT}/README.md`, old_string: "a", new_string: "b" }, `${ROOT}/README.md`, undefined],
    ["Edit", { path: "lib/x.ts", old_string: "a", new_string: "b" }, `${ROOT}/lib/x.ts`, undefined],
    ["MultiEdit", { file_path: "a.ts", edits: [{ old_string: "a", new_string: "b" }] }, `${ROOT}/a.ts`, undefined],
    ["NotebookEdit", { notebook_path: "nb.ipynb", new_source: "print(1)" }, `${ROOT}/nb.ipynb`, undefined],
    ["Write", { file_path: ".env", content: "SECRET=1" }, `${ROOT}/.env`, "high"],
    ["Write", { file_path: ".env.production", content: "" }, `${ROOT}/.env.production`, "high"],
    ["Write", { file_path: "~/.ssh/authorized_keys", content: "ssh-ed25519 AAAA" }, `${HOME}/.ssh/authorized_keys`, "high"],
    ["Edit", { file_path: ".git/hooks/pre-commit", old_string: "", new_string: "curl x|sh" }, `${ROOT}/.git/hooks/pre-commit`, "high"],
    ["Write", { file_path: "certs/server.pem", content: "" }, `${ROOT}/certs/server.pem`, "high"],
    ["Write", { file_path: "keys/id_ed25519", content: "" }, `${ROOT}/keys/id_ed25519`, "high"],
    ["Write", { file_path: "/etc/hosts", content: "" }, "/etc/hosts", "high"],
    ["Write", { file_path: "../other/x.ts", content: "" }, "/Users/dev/work/other/x.ts", "high"],
    ["Edit", { file_path: "~/.zshrc", old_string: "", new_string: "x" }, `${HOME}/.zshrc`, "high"],
  ] as const)("%s %j → filesystem.write %s (risk %s)", (tool, input, path, risk) => {
    const d = adapter.normalize(ev(tool, input), ctx)!;
    expect(d.action.category).toBe("filesystem");
    expect(d.action.operation).toBe("write");
    expect(d.action.tool).toBe(tool);
    expect(d.action.arguments?.path).toBe(path);
    expect(d.action.arguments?.input_sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(d.resource).toMatchObject({ type: "file", name: path });
    expect(d.risk?.level).toBe(risk);
  });

  it("write tool without a path → high risk (defensive)", () => {
    const d = adapter.normalize(ev("MultiEdit", { edits: "garbage" }), ctx)!;
    expect(d.risk?.level).toBe("high");
    expect(d.action.arguments?.path).toBe("(unknown)");
  });

  it("different content → different input hash (content bound without being stored)", () => {
    const a = adapter.normalize(ev("Write", { file_path: "a", content: "1" }), ctx)!;
    const b = adapter.normalize(ev("Write", { file_path: "a", content: "2" }), ctx)!;
    expect(a.action.arguments?.input_sha256).not.toBe(b.action.arguments?.input_sha256);
    expect(JSON.stringify(a)).not.toContain('"content"');
  });

  it("mcp__server__tool → mcp.invoke {server, tool, arguments}", () => {
    const d = adapter.normalize(ev("mcp__github__create_issue", { title: "x" }), ctx)!;
    expect(d.action).toMatchObject({
      category: "mcp",
      operation: "invoke",
      tool: "mcp__github__create_issue",
      arguments: { server: "github", tool: "create_issue", arguments: { title: "x" } },
    });
    expect(d.resource).toMatchObject({ type: "mcp_server", name: "github" });
  });

  it.each(["Read", "Glob", "Grep", "WebFetch", "Task", "mcp__", "mcp__x", "mcp__x__"])("%s → null (not governed)", (tool) => {
    expect(adapter.normalize(ev(tool, {}), ctx)).toBeNull();
  });

  it("rejects non-PreToolUse / malformed input at the schema", () => {
    expect(PreToolUseInput.safeParse({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: {}, cwd: "/" }).success).toBe(false);
    expect(PreToolUseInput.safeParse({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: "x", cwd: "/" }).success).toBe(false);
    expect(PreToolUseInput.safeParse({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {} }).success).toBe(false);
  });
});

describe("render", () => {
  it("allow", () => {
    expect(adapter.render({ kind: "allow", reason: "ok" })).toEqual({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: "ok" },
    });
  });
  it("deny", () => {
    expect(adapter.render({ kind: "deny", reason: "no" })).toEqual({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "no" },
    });
  });
  it("allow + rewrittenCommand preserves other tool_input fields", () => {
    const e = ev("Bash", { command: "git push", description: "push it", timeout: 5000, run_in_background: false });
    const out = adapter.render({ kind: "allow", reason: "approved", rewrittenCommand: "wrapped" }, e);
    expect(out.hookSpecificOutput.updatedInput).toEqual({ command: "wrapped", description: "push it", timeout: 5000, run_in_background: false });
  });
  it("rewrittenCommand without a Bash event throws (caller fails closed)", () => {
    expect(() => adapter.render({ kind: "allow", reason: "x", rewrittenCommand: "y" })).toThrow();
    expect(() => adapter.render({ kind: "allow", reason: "x", rewrittenCommand: "y" }, ev("Write", { file_path: "a" }))).toThrow();
  });
});

describe("helpers", () => {
  it("parseMcpToolName", () => {
    expect(parseMcpToolName("mcp__srv__a__b")).toEqual({ server: "srv", tool: "a__b" });
    expect(parseMcpToolName("Bash")).toBeNull();
  });
  it("sensitivePathReason: plain project file is fine", () => {
    expect(sensitivePathReason(`${ROOT}/src/index.ts`, { homeDir: HOME, projectRoot: ROOT })).toBeNull();
    expect(sensitivePathReason(`${ROOT}/.gitignore`, { homeDir: HOME, projectRoot: ROOT })).toBeNull();
  });
});
