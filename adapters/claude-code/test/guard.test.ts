import { describe, expect, it } from "vitest";
import { ClaudeCodeAdapter, PreToolUseInput, sensitivePathReason } from "../src/index.ts";

const HOME = "/Users/dev";
const ROOT = "/Users/dev/work/demo";
const AG = "/Users/dev/.agentgate";
const INSTALL = "/Users/dev/AgentGate/daemon/agentgate";
const SECRETS = "/Users/dev/Library/Application Support/agentgate-api";
const adapter = new ClaudeCodeAdapter({ homeDir: HOME, projectRoot: ROOT, agentgateHome: AG, protectedDirs: [INSTALL, SECRETS] });
const ctx = { session_id: "ses_1", cwd: ROOT };
const ev = (tool_name: string, tool_input: Record<string, unknown>) =>
  PreToolUseInput.parse({ hook_event_name: "PreToolUse", tool_name, tool_input, cwd: ROOT, session_id: "c" });

describe("H3: sensitive paths", () => {
  it.each([
    `${ROOT}/.claude/commands/x.md`,
    `${HOME}/.claude/CLAUDE.md`,
    `${AG}/policy.yaml`,
    `${INSTALL}/src/verify.ts`,
    `${SECRETS}/auth-secret`,
  ])("write %s is high risk", (p) => {
    expect(sensitivePathReason(p, { homeDir: HOME, projectRoot: ROOT, agentgateHome: AG, protectedDirs: [INSTALL, SECRETS] })).toBeTruthy();
  });

  it.each([
    [`${AG}/config.json`, true],
    [`${HOME}/.ssh/id_ed25519`, true],
    [".env", true],
    [".env.local", true],
    [`${SECRETS}/approval-signing-key.pem`, true],
    ["/Users/dev/AgentGate/apps/api/.data/auth-secret", true],
    ["/Users/dev/AgentGate/apps/api/.data/pglite/PG_VERSION", false],
    ["src/server.js", false],
    ["README.md", false],
  ])("Read %s → governed=%s", (p, governed) => {
    const d = adapter.normalize(ev("Read", { file_path: p }), ctx);
    expect(d !== null).toBe(governed);
    if (d) {
      expect(d.action).toMatchObject({ category: "filesystem", operation: "read", tool: "Read" });
      expect(d.risk?.level).toBe("high");
      expect(adapter.guard(ev("Read", { file_path: p }), ROOT)?.decision).toBe("ask");
    }
  });
});

describe("H4: guard (self-protection)", () => {
  it.each([
    "agentgate login --server http://evil",
    "npx agentgate pair",
    "npm run agentgate -- logout",
    "'/Users/dev/AgentGate/daemon/agentgate/bin/agentgate.sh' uninstall claude-code --user",
    "node daemon/agentgate/bin/agentgate.mjs --verbose install claude-code",
    "cd /x && agentgate pair | tee /tmp/code",
    'sh -c "agentgate pair"',
  ])("Bash %j → deny", (command) => {
    expect(adapter.guard(ev("Bash", { command }), ROOT)?.decision).toBe("deny");
  });

  it.each([
    "curl -X POST localhost:8787/v1/pairing -H 'Authorization: Bearer x'",
    "curl -s http://127.0.0.1:8787/v1/approvals/apr_123/approve -d '{}'",
    "curl localhost:8787/v1/auth/login -d '{\"client\":\"device\"}'",
  ])("Bash %j → deny (API abuse)", (command) => {
    expect(adapter.guard(ev("Bash", { command }), ROOT)?.decision).toBe("deny");
  });

  it.each(["cat ~/.agentgate/config.json", `cp x ${AG}/policy.yaml`, "vim .claude/settings.local.json", `ls '${SECRETS}'`])("Bash %j → ask", (command) => {
    expect(adapter.guard(ev("Bash", { command }), ROOT)?.decision).toBe("ask");
  });

  it.each(["agentgate status", "agentgate request -- ls", "git push origin main", "echo agentgate is great", "ls -la"])("Bash %j → no guard", (command) => {
    expect(adapter.guard(ev("Bash", { command }), ROOT)).toBeNull();
  });

  it.each([
    [`${AG}/policy.yaml`, "deny"],
    [`${INSTALL}/src/verify.ts`, "deny"],
    [".claude/settings.local.json", "deny"],
    [`${HOME}/.claude/settings.json`, "deny"],
    [".claude/commands/x.md", null],
    ["src/a.ts", null],
  ])("Write %s → %s", (file_path, decision) => {
    expect(adapter.guard(ev("Write", { file_path, content: "" }), ROOT)?.decision ?? null).toBe(decision);
  });
});
