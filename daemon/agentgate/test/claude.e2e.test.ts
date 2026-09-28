import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateSigningKeyPair } from "@agentgate/core";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli, runProcess, type RunResult } from "./helpers.ts";

/**
 * Milestone 4: Claude Code PreToolUse hook, `agentgate exec`, `agentgate run claude`.
 * No real `claude` binary: the hook is fed sample PreToolUse JSON exactly like Claude
 * Code does, and `run` is exercised with a fake `claude` that invokes the configured hook.
 */

const BIN_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "bin");
const HOOK_SHIM = join(BIN_DIR, "agentgate-hook.sh");
const SESSION = "ses_hook_test_0001";
const T = 30_000;

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, policy?: string | null) {
  server = await new FakeServer(opts).start();
  const env = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy });
  return { s: server, ...env, probe: join(env.work, "executed.txt") };
}

function hookInput(tool_name: string, tool_input: Record<string, unknown>, cwd: string) {
  return JSON.stringify({
    session_id: "claude-session-1",
    transcript_path: "/tmp/transcript.jsonl",
    cwd,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name,
    tool_input,
    tool_use_id: "toolu_01",
  });
}

/** Invoke the hook the way Claude Code does: through the shim, JSON on stdin. */
function runHook(input: string, o: { home: string; cwd: string; env?: Record<string, string> }) {
  return runProcess(HOOK_SHIM, [], {
    home: o.home,
    cwd: o.cwd,
    input,
    env: { AGENTGATE_SESSION_ID: SESSION, AGENTGATE_NODE: process.execPath, ...o.env },
  });
}

function decision(r: RunResult) {
  return JSON.parse(r.stdout).hookSpecificOutput as {
    permissionDecision: string;
    permissionDecisionReason: string;
    updatedInput?: Record<string, unknown>;
  };
}

/** Run a (rewritten) Bash command like Claude's Bash tool would. */
function bash(command: string, o: { home: string; cwd: string; env?: Record<string, string> }) {
  return runProcess("/bin/sh", ["-c", command], { home: o.home, cwd: o.cwd, env: { AGENTGATE_SESSION_ID: SESSION, ...o.env } });
}

async function closedPort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

describe("hook claude-code", () => {
  it("Bash git push → ask → approve → allow with wrapped updatedInput (token not exposed, nonce not consumed)", async () => {
    const { s, home, work } = await setup({}, null); // built-in policy: ask-git-push
    const r = await runHook(hookInput("Bash", { command: "git push origin main", description: "Push", timeout: 60000 }, work), { home, cwd: work });
    expect(r.code).toBe(0);
    const d = decision(r);
    expect(d.permissionDecision).toBe("allow");
    expect(d.permissionDecisionReason).toMatch(/approved by device dev_test_phone \(apr_/);
    const cmd = d.updatedInput!.command as string;
    expect(cmd).toMatch(/agentgate\.sh'? exec --approval apr_[A-Za-z0-9_-]+ -- 'git push origin main'$/);
    expect(d.updatedInput).toMatchObject({ description: "Push", timeout: 60000 });

    // the signed token never appears in the command / hook output
    const [rec] = [...s.approvals.values()];
    const stored = readdirSync(join(home, "approvals"));
    expect(stored).toHaveLength(1);
    const storedPath = join(home, "approvals", stored[0]!);
    expect(statSync(storedPath).mode & 0o777).toBe(0o600);
    const token = JSON.parse(readFileSync(storedPath, "utf8")).token as string;
    expect(token).toBe(rec!.token);
    expect(r.stdout).not.toContain(token);
    expect(r.stderr).not.toContain(token);
    // nonce left for exec
    expect(existsSync(join(home, "nonces")) ? readdirSync(join(home, "nonces")) : []).toHaveLength(0);
    // action was reported as claude-code / shell.execute
    const sub = s.requests.find((q) => q.path === "/v1/actions")!.body as { action: { agent: { type: string }; action: { category: string } } };
    expect(sub.action.agent.type).toBe("claude-code");
    expect(sub.action.action.category).toBe("shell");
  }, T);

  it("policy allow → exit 0, permissionDecision allow, no rewrite", async () => {
    const { home, work } = await setup();
    const r = await runHook(hookInput("Bash", { command: "ls -la" }, work), { home, cwd: work });
    expect(r.code).toBe(0);
    const d = decision(r);
    expect(d.permissionDecision).toBe("allow");
    expect(d.updatedInput).toBeUndefined();
  }, T);

  it("denied on device → exit 2 with the reason on stderr", async () => {
    const { s, home, work } = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const r = await runHook(hookInput("Bash", { command: "touch x" }, work), { home, cwd: work });
    expect(r.code).toBe(2);
    expect(r.stdout).toBe("");
    expect(r.stderr).toMatch(/AgentGate blocked this action: denied on device/);
    expect(s.executions.at(-1)?.status).toBe("blocked");
  }, T);

  it("policy deny → exit 2", async () => {
    const { home, work } = await setup();
    const r = await runHook(hookInput("Bash", { command: "rm -rf /tmp/whatever" }, work), { home, cwd: work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/denied by policy/);
  }, T);

  it("server unreachable → exit 2", async () => {
    const port = await closedPort();
    const env = makeEnv({ server: `http://127.0.0.1:${port}`, token: "x".repeat(24), publicKeyPem: generateSigningKeyPair().publicKeyPem });
    const r = await runHook(hookInput("Bash", { command: "touch x" }, env.work), { home: env.home, cwd: env.work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/ECONNREFUSED|server unreachable/);
  }, T);

  it("internal deadline (server hangs) → exit 2 before the hook timeout", async () => {
    const { home, work } = await setup({ hangActions: true });
    const t0 = Date.now();
    const r = await runHook(hookInput("Bash", { command: "touch x" }, work), { home, cwd: work, env: { AGENTGATE_HOOK_TIMEOUT_S: "32" } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/hook deadline/);
    expect(Date.now() - t0).toBeLessThan(8_000);
  }, T);

  it("approval wait is capped by the deadline → exit 2", async () => {
    const { home, work } = await setup({ onAsk: () => {} });
    const r = await runHook(hookInput("Bash", { command: "touch x" }, work), { home, cwd: work, env: { AGENTGATE_HOOK_TIMEOUT_S: "34" } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/timed out|hook deadline/);
  }, T);

  it.each([
    ["garbage", "not json at all {"],
    ["empty", ""],
    ["wrong event", JSON.stringify({ hook_event_name: "SomethingElse", tool_name: "Bash", tool_input: {}, cwd: "/" })],
    ["tool_input not an object", JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: "rm -rf /", cwd: "/" })],
  ])("%s stdin → exit 2", async (_n, input) => {
    const { home, work } = await setup();
    const r = await runHook(input, { home, cwd: work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/AgentGate blocked this action/);
  }, T);

  it("no AGENTGATE_SESSION_ID and no Claude session_id → exit 2", async () => {
    const { home, work } = await setup();
    const input = JSON.parse(hookInput("Bash", { command: "ls" }, work));
    delete input.session_id;
    const r = await runProcess(HOOK_SHIM, [], {
      home,
      cwd: work,
      input: JSON.stringify(input),
      env: { AGENTGATE_NODE: process.execPath },
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/no AgentGate session/);
  }, T);

  it("ungoverned tool (Read) → exit 0, no output (Claude's normal flow)", async () => {
    const { s, home, work } = await setup();
    const r = await runHook(hookInput("Read", { file_path: "x" }, work), { home, cwd: work });
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");
    expect(s.count("POST", "/v1/actions")).toBe(0);
  }, T);

  it("Write .env → adapter-asserted high risk → ask → approved → allow (token consumed in hook)", async () => {
    const { s, home, work } = await setup({}, null);
    const r = await runHook(hookInput("Write", { file_path: ".env", content: "API_KEY=abc" }, work), { home, cwd: work });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    const d = decision(r);
    expect(d.permissionDecision).toBe("allow");
    expect(d.updatedInput).toBeUndefined();
    expect(s.approvals.size).toBe(1);
    expect(readdirSync(join(home, "nonces"))).toHaveLength(1);
    const body = JSON.stringify(s.requests.find((q) => q.path === "/v1/actions")!.body);
    expect(body).not.toContain("API_KEY=abc"); // content bound by hash, not uploaded
  }, T);

  it("Write to an ordinary project file → allowed by default policy", async () => {
    const { s, home, work } = await setup({}, null);
    const r = await runHook(hookInput("Write", { file_path: "src/a.ts", content: "x" }, work), { home, cwd: work });
    expect(r.code).toBe(0);
    expect(decision(r).permissionDecision).toBe("allow");
    expect(s.approvals.size).toBe(0);
  }, T);

  it("forged approval token → exit 2 (verified in the hook already)", async () => {
    const rogue = generateSigningKeyPair();
    const { home, work } = await setup({ onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, {}, rogue.privateKeyPem)) });
    const r = await runHook(hookInput("Bash", { command: "touch x" }, work), { home, cwd: work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/bad_signature/);
    expect(existsSync(join(home, "approvals")) ? readdirSync(join(home, "approvals")) : []).toHaveLength(0);
  }, T);
});

describe("agentgate-hook.sh (fail-closed shim)", () => {
  function fakeNode(dir: string, body: string) {
    const p = join(dir, "fake-node");
    writeFileSync(p, `#!/bin/sh\n${body}\n`);
    chmodSync(p, 0o755);
    return p;
  }

  it("node missing from PATH → exit 2", async () => {
    const { home, work } = await setup();
    const r = await runProcess(HOOK_SHIM, [], {
      home,
      cwd: work,
      input: "{}",
      bareEnv: true,
      env: { PATH: "/usr/bin:/bin", AGENTGATE_SESSION_ID: SESSION },
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/node runtime not found/);
  }, T);

  it.each([
    ["exit 1", "exit 1"],
    ["exit 77 (agentgate crash code)", "exit 77"],
    ["exit 127 (tsx failed to load)", "exit 127"],
    ["killed by SIGKILL", "kill -9 $$"],
    ["killed by SIGSEGV", "kill -11 $$"],
  ])("runtime %s → exit 2", async (_n, body) => {
    const { home, work } = await setup();
    const r = await runProcess(HOOK_SHIM, [], {
      home,
      cwd: work,
      input: "{}",
      env: { AGENTGATE_NODE: fakeNode(work, body), AGENTGATE_SESSION_ID: SESSION },
    });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/AgentGate blocked this action/);
  }, T);

  it("passes exit 0 + stdout through unchanged", async () => {
    const { home, work } = await setup();
    const r = await runProcess(HOOK_SHIM, [], {
      home,
      cwd: work,
      input: "{}",
      env: { AGENTGATE_NODE: fakeNode(work, `echo '{"ok":true}'; exit 0`), AGENTGATE_SESSION_ID: SESSION },
    });
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe('{"ok":true}');
  }, T);
});

describe("exec --approval", () => {
  /** Hook-approve `touch <probe>` and return the rewritten command. */
  async function approved() {
    const ctx = await setup();
    const r = await runHook(hookInput("Bash", { command: `touch ${ctx.probe}` }, ctx.work), { home: ctx.home, cwd: ctx.work });
    expect(r.code).toBe(0);
    return { ...ctx, wrapped: decision(r).updatedInput!.command as string };
  }

  it("happy path: runs exactly the approved command, reports lifecycle, consumes the nonce", async () => {
    const { s, home, work, probe, wrapped } = await approved();
    const r = await bash(wrapped, { home, cwd: work });
    expect(r.code).toBe(0);
    expect(existsSync(probe)).toBe(true);
    expect(s.executions.map((e) => e.status)).toEqual(["started", "completed"]);
    expect(readdirSync(join(home, "nonces"))).toHaveLength(1);
    expect(readdirSync(join(home, "approvals"))).toHaveLength(0);
  }, T);

  it("modified command (different string for the same approval) → 77, nothing runs", async () => {
    const { home, work, probe, wrapped } = await approved();
    const evil = join(work, "evil.txt");
    const id = wrapped.match(/--approval (apr_[A-Za-z0-9_-]+)/)![1]!;
    const r = await runCli(["exec", "--approval", id, "--", `touch ${probe}; touch ${evil}`], { home, cwd: work, env: { AGENTGATE_SESSION_ID: SESSION } });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/hash_mismatch/);
    expect(existsSync(probe)).toBe(false);
    expect(existsSync(evil)).toBe(false);
  }, T);

  it("AGENTGATE_DEV tamper hook at the exec boundary → 77 hash_mismatch", async () => {
    const { s, home, work, probe, wrapped } = await approved();
    const evil = join(work, "evil.txt");
    const r = await bash(wrapped, { home, cwd: work, env: { AGENTGATE_DEV: "1", AGENTGATE_TAMPER_COMMAND: `touch ${evil}` } });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/hash_mismatch/);
    expect(existsSync(probe)).toBe(false);
    expect(existsSync(evil)).toBe(false);
    expect(s.executions.at(-1)).toMatchObject({ status: "blocked" });
  }, T);

  it("different working directory → 77 (cwd is part of the hash)", async () => {
    const { home, work, probe, wrapped } = await approved();
    const other = join(work, "sub");
    mkdirSync(other);
    const r = await bash(wrapped, { home, cwd: other });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
  }, T);

  it("replay: second run → 77; restoring the token file → 77 replayed", async () => {
    const { home, work, probe, wrapped } = await approved();
    const [file] = readdirSync(join(home, "approvals"));
    const backup = join(work, "token-backup.json");
    copyFileSync(join(home, "approvals", file!), backup);

    expect((await bash(wrapped, { home, cwd: work })).code).toBe(0);
    expect(existsSync(probe)).toBe(true);

    const again = await bash(wrapped, { home, cwd: work });
    expect(again.code).toBe(77);
    expect(again.stderr).toMatch(/no stored approval/);

    copyFileSync(backup, join(home, "approvals", file!));
    const replay = await bash(wrapped, { home, cwd: work });
    expect(replay.code).toBe(77);
    expect(replay.stderr).toMatch(/replayed/);
  }, T);

  it("different AgentGate session in env → 77", async () => {
    const { home, work, probe, wrapped } = await approved();
    const r = await bash(wrapped, { home, cwd: work, env: { AGENTGATE_SESSION_ID: "ses_someone_else" } });
    expect(r.code).toBe(77);
    expect(existsSync(probe)).toBe(false);
  }, T);

  it("unknown approval / missing --approval → 77", async () => {
    const { home, work } = await setup();
    expect((await runCli(["exec", "--approval", "apr_doesnotexist", "--", "true"], { home, cwd: work })).code).toBe(77);
    expect((await runCli(["exec", "--", "true"], { home, cwd: work })).code).toBe(77);
    expect((await runCli(["exec", "--bogus-flag", "--", "true"], { home, cwd: work })).code).toBe(77);
  }, T);
});

describe("run claude", () => {
  /** Fake `claude`: reads --settings, pipes a PreToolUse JSON into the configured hook
   *  command (with a minimal env), then runs the rewritten Bash command like Claude would. */
  const FAKE_CLAUDE = `#!/usr/bin/env node
const fs = require("fs"), cp = require("child_process");
const args = process.argv.slice(2);
const settingsPath = args[args.indexOf("--settings") + 1];
const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
const entry = settings.hooks.PreToolUse[0];
const hookCmd = entry.hooks[0].command;
const input = JSON.stringify({
  session_id: "claude-s", transcript_path: "/tmp/t.jsonl", cwd: process.cwd(), permission_mode: "default",
  hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: process.env.FAKE_CMD, description: "d" }, tool_use_id: "toolu_1",
});
const h = cp.spawnSync("/bin/sh", ["-c", hookCmd], { input, encoding: "utf8", env: { PATH: "/usr/bin:/bin", HOME: process.env.HOME } });
const report = { args, matcher: entry.matcher, timeout: entry.hooks[0].timeout, hookCmd, settingsMode: fs.statSync(settingsPath).mode & 0o777,
  settingsPath, sessionEnv: process.env.AGENTGATE_SESSION_ID, hookStatus: h.status, hookStdout: h.stdout, hookStderr: h.stderr };
if (h.status === 0 && h.stdout.trim()) {
  const out = JSON.parse(h.stdout).hookSpecificOutput;
  report.decision = out.permissionDecision;
  if (out.updatedInput) {
    const e = cp.spawnSync("/bin/sh", ["-c", out.updatedInput.command], { encoding: "utf8", env: process.env });
    report.execStatus = e.status; report.execStderr = e.stderr; report.rewritten = out.updatedInput.command;
  }
}
fs.writeFileSync(process.env.FAKE_CLAUDE_REPORT, JSON.stringify(report));
process.exit(Number(process.env.FAKE_CLAUDE_EXIT || 0));
`;

  function fakeClaudeDir(work: string) {
    const dir = join(work, "fakebin");
    mkdirSync(dir);
    writeFileSync(join(dir, "claude"), FAKE_CLAUDE);
    chmodSync(join(dir, "claude"), 0o755);
    return dir;
  }

  it("wires settings → hook → approval → exec end to end, then ends the session and cleans up", async () => {
    const { s, home, work, probe } = await setup();
    const fakebin = fakeClaudeDir(work);
    const reportPath = join(work, "report.json");
    const r = await runCli(["run", "claude", "--", "--model", "x"], {
      home,
      cwd: work,
      env: {
        PATH: `${fakebin}:${dirname(process.execPath)}:/usr/bin:/bin`,
        FAKE_CMD: `touch ${probe}`,
        FAKE_CLAUDE_REPORT: reportPath,
        FAKE_CLAUDE_EXIT: "5",
      },
    });
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    expect(report.args).toEqual(["--settings", report.settingsPath, "--model", "x"]);
    expect(report.matcher).toBe("Bash|Read|Write|Edit|MultiEdit|NotebookEdit|mcp__.*");
    expect(report.timeout).toBe(600);
    expect(report.settingsMode).toBe(0o600);
    expect(report.hookCmd).toContain("agentgate-hook.sh");
    expect(report.hookCmd).not.toContain(s.token);
    expect(report.hookStatus).toBe(0);
    expect(report.decision).toBe("allow");
    expect(report.rewritten).toMatch(/exec --approval apr_/);
    expect(report.execStatus).toBe(0);
    expect(existsSync(probe)).toBe(true);
    expect(report.sessionEnv).toMatch(/^ses_/);

    expect(r.code).toBe(5); // claude's exit code propagates
    expect(s.endedSessions).toEqual([report.sessionEnv]);
    expect(existsSync(report.settingsPath)).toBe(false);
    expect(s.requests.find((q) => q.path === "/v1/agents")!.body).toMatchObject({ type: "claude-code" });
  }, T);

  it("claude not installed → install hint, exit 2", async () => {
    const { home, work } = await setup();
    const r = await runCli(["run", "claude"], { home, cwd: work, env: { PATH: `${dirname(process.execPath)}:/usr/bin:/bin` } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/npm install -g @anthropic-ai\/claude-code/);
  }, T);

  it("server unreachable → refuses to start claude (77)", async () => {
    const port = await closedPort();
    const env = makeEnv({ server: `http://127.0.0.1:${port}`, token: "x".repeat(24), publicKeyPem: generateSigningKeyPair().publicKeyPem });
    const fakebin = fakeClaudeDir(env.work);
    const reportPath = join(env.work, "report.json");
    const r = await runCli(["run", "claude"], {
      home: env.home,
      cwd: env.work,
      env: { PATH: `${fakebin}:${dirname(process.execPath)}:/usr/bin:/bin`, FAKE_CLAUDE_REPORT: reportPath, FAKE_CMD: "true" },
    });
    expect(r.code).toBe(77);
    expect(existsSync(reportPath)).toBe(false);
  }, T);
});
