import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli, runProcess, type RunResult } from "./helpers.ts";

/**
 * M5: true exit codes through the exec wrapper, unambiguous blocks, per-approval cancel,
 * PostToolUse reporting, PID-aware stale lock reclaim.
 */

const HOOK_SHIM = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
const T = 30_000;
const MINIMAL = { PATH: "/usr/bin:/bin" };

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, env: { tokenExpiresAt?: string; refreshToken?: "issue" } = {}) {
  server = await new FakeServer(opts).start();
  const e = makeEnv({
    server: server.url,
    token: server.token,
    publicKeyPem: server.keys.publicKeyPem,
    ...(env.tokenExpiresAt ? { tokenExpiresAt: env.tokenExpiresAt } : {}),
    ...(env.refreshToken ? { refreshToken: server.issueRefreshToken() } : {}),
  });
  return { s: server, ...e };
}

function input(event: string, tool_name: string, tool_input: Record<string, unknown>, cwd: string, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    session_id: "claude-m5",
    transcript_path: "/tmp/t.jsonl",
    cwd,
    permission_mode: "default",
    hook_event_name: event,
    tool_name,
    tool_input,
    tool_use_id: "toolu_m5",
    ...extra,
  });
}

const hook = (stdin: string, o: { home: string; cwd: string; env?: Record<string, string> }) =>
  runProcess(HOOK_SHIM, [], { home: o.home, cwd: o.cwd, input: stdin, env: { AGENTGATE_NODE: process.execPath, ...o.env } });

const decision = (r: RunResult) => JSON.parse(r.stdout).hookSpecificOutput;

/** Approve `command` through the hook, then run the rewritten command the way Claude's
 *  Bash tool does (user shell = zsh, minimal PATH). Also runs the raw command for comparison. */
async function viaWrapper(t: Awaited<ReturnType<typeof setup>>, command: string) {
  const h = await hook(input("PreToolUse", "Bash", { command, run_in_background: false }, t.work), { home: t.home, cwd: t.work });
  expect(h.code).toBe(0);
  const wrapped: string = decision(h).updatedInput.command;
  expect(decision(h).updatedInput.run_in_background).toBe(false);
  const tool = await runProcess("/bin/zsh", ["-c", wrapped], { home: t.home, cwd: t.work, bareEnv: true, env: MINIMAL });
  const raw = spawnSync("/bin/sh", ["-c", command], { cwd: t.work, env: MINIMAL, encoding: "utf8" });
  return { tool, raw, wrapped };
}

/** Drop agentgate's own status lines (stderr, prefixed "agentgate "). */
const userStderr = (s: string) =>
  s
    .split("\n")
    .filter((l) => !l.startsWith("agentgate "))
    .join("\n");
const normSh = (s: string) => s.replace(/\/bin\/sh: (line \d+: )?/g, "").trim();

// makeEnv's test policy: `touch` → ask. Every case starts with touch to force the wrapper path.
describe("P0: true exit code through the exec wrapper", () => {
  const cases: Array<[string, (w: string) => string]> = [
    ["failing chain, binary missing from PATH (the desktop bug shape)", (w) => `touch ${w}/a && node-does-not-exist --check x && echo never`],
    [
      "multi-line heredoc commit message with apostrophes and Co-Authored-By",
      (w) =>
        `touch ${w}/b && git commit -q -m "$(cat <<'EOF'\nAdd version endpoint — don't break it\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nEOF\n)" && echo committed`,
    ],
    ["quoted arguments and explicit exit", (w) => `touch "${w}/c d" && printf '%s|%s\\n' "it's" 'a "b"' && exit 3`],
    ["stdout + stderr and exit 1", (w) => `touch ${w}/e && echo out && echo err >&2 && false`],
  ];

  for (const [name, make] of cases) {
    it(`${name}: tool exit == raw exit, reported truthfully, output passes through`, async () => {
      const t = await setup();
      const cmd = make(t.work);
      const { tool, raw } = await viaWrapper(t, cmd);
      expect(raw.status).not.toBeNull();
      expect(tool.code).toBe(raw.status);
      expect(tool.stdout).toBe(raw.stdout);
      expect(normSh(userStderr(tool.stderr))).toContain(normSh(raw.stderr));
      const last = t.s.executions.at(-1)!;
      expect(last.exit_code).toBe(raw.status);
      expect(last.status).toBe(raw.status === 0 ? "completed" : "failed");
      expect(tool.stderr).not.toContain("agentgate: BLOCKED");
    }, T);
  }

  it("`…; git log -1` shape (the desktop case): exit 0 is the shell's truth, and the audit is annotated", async () => {
    const t = await setup();
    const { tool } = await viaWrapper(t, `touch ${t.work}/x && no-such-bin --check && echo never; echo tail`);
    expect(tool.code).toBe(0);
    expect(tool.stdout).toBe("tail\n");
    const last = t.s.executions.at(-1)!;
    expect(last).toMatchObject({ status: "completed", exit_code: 0 });
    expect(last.detail).toMatch(/earlier commands may have failed/);
  }, T);
});

describe("exit 77 disambiguation", () => {
  it("a command that itself exits 77: no BLOCKED line, reported failed(77) with a note", async () => {
    const t = await setup();
    const r = await runCli(["request", "--", "echo hi; exit 77"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stdout).toBe("hi\n");
    expect(r.stderr).not.toMatch(/^agentgate: BLOCKED/m);
    expect(t.s.executions.at(-1)).toMatchObject({ status: "failed", exit_code: 77 });
    expect(t.s.executions.at(-1)!.detail).toMatch(/came from the command itself/);
  }, T);

  it("a block: exit 77 + exactly one `agentgate: BLOCKED [reason]` line; API gets `blocked` with the reason", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const r = await runCli(["request", "--", `touch ${t.work}/z`], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    const lines = r.stderr.split("\n").filter((l) => /^agentgate: BLOCKED/.test(l));
    expect(lines).toEqual(["agentgate: BLOCKED [device_denied] denied on device"]);
    expect(t.s.executions.at(-1)).toMatchObject({ status: "blocked" });
    expect(t.s.executions.at(-1)!.detail).toMatch(/^device_denied: /);
  }, T);

  it.each([
    ["unknown approval", ["exec", "--approval", "apr_nope_nope", "--", "true"], "approval_not_found"],
    ["exec usage", ["exec", "--", "true"], "usage"],
  ])("%s → BLOCKED [%s]", async (_n, args, reason) => {
    const t = await setup();
    const r = await runCli(args as string[], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(new RegExp(`^agentgate: BLOCKED \\[${reason}\\] `, "m"));
  }, T);
});

describe("per-approval cancel", () => {
  it("hook gives up at its deadline → approval cancelled on the server", async () => {
    const t = await setup({ onAsk: () => {} });
    const r = await hook(input("PreToolUse", "Bash", { command: "touch q" }, t.work), { home: t.home, cwd: t.work, env: { AGENTGATE_HOOK_TIMEOUT_S: "34" } });
    expect(r.code).toBe(2);
    expect(t.s.cancels).toHaveLength(1);
    expect(t.s.cancels[0]!.reason).toMatch(/agent_timeout|hook_deadline/);
    expect([...t.s.approvals.values()][0]!.approval.status).toBe("cancelled");
  }, T);

  it("hook interrupted (SIGTERM) while waiting → cancelled, exit 2", async () => {
    const t = await setup({ onAsk: () => {} });
    const child = spawn(HOOK_SHIM, [], {
      cwd: t.work,
      env: { ...process.env, AGENTGATE_HOME: t.home, AGENTGATE_NODE: process.execPath, NO_COLOR: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stdin.end(input("PreToolUse", "Bash", { command: "touch q" }, t.work));
    for (let i = 0; i < 100 && t.s.approvals.size === 0; i++) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 300));
    spawnSync("pkill", ["-TERM", "-P", String(child.pid)]); // the node process under the shim
    const code = await new Promise<number | null>((r) => child.on("close", r));
    expect(code).toBe(2);
    expect(t.s.cancels.map((c) => c.reason)).toContain("agent_aborted");
  }, T);

  it("SessionEnd with an approval still pending → cancelled; the waiting hook exits 2", async () => {
    const t = await setup({ onAsk: () => {} });
    const waiting = hook(input("PreToolUse", "Bash", { command: "touch q" }, t.work), { home: t.home, cwd: t.work });
    for (let i = 0; i < 100 && t.s.approvals.size === 0; i++) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 300));
    const end = await hook(JSON.stringify({ session_id: "claude-m5", cwd: t.work, hook_event_name: "SessionEnd", reason: "other" }), {
      home: t.home,
      cwd: t.work,
    });
    expect(end.code).toBe(0);
    const w = await waiting;
    expect(w.code).toBe(2);
    expect(w.stderr).toMatch(/cancelled/);
    expect(t.s.cancels.map((c) => c.reason)).toContain("claude_session_ended");
    expect(existsSync(join(t.home, "pending")) ? readdirSync(join(t.home, "pending")) : []).toHaveLength(0);
  }, T);
});

describe("PostToolUse reporting", () => {
  const writeEnv = (w: string) => input("PreToolUse", "Write", { file_path: ".env", content: "A=1" }, w);

  it("approved Write → PostToolUse reports started + completed for the matching action, once", async () => {
    const t = await setup();
    const pre = await hook(writeEnv(t.work), { home: t.home, cwd: t.work });
    expect(decision(pre).permissionDecision).toBe("allow");
    const actionId = [...t.s.approvals.values()][0]!.action.action_id;
    const post = await hook(input("PostToolUse", "Write", { file_path: ".env", content: "A=1" }, t.work, { tool_response: { filePath: ".env", success: true } }), {
      home: t.home,
      cwd: t.work,
    });
    expect(post.code).toBe(0);
    expect(post.stdout).toBe("");
    expect(t.s.executions.filter((e) => e.action_id === actionId).map((e) => e.status)).toEqual(["started", "completed"]);
    await hook(input("PostToolUse", "Write", {}, t.work), { home: t.home, cwd: t.work });
    expect(t.s.executions.filter((e) => e.action_id === actionId)).toHaveLength(2);
  }, T);

  it("policy-allowed Edit + error response → failed", async () => {
    const t = await setup();
    const pre = await hook(input("PreToolUse", "Edit", { file_path: "src/a.ts", old_string: "a", new_string: "b" }, t.work), { home: t.home, cwd: t.work });
    expect(decision(pre).permissionDecision).toBe("allow");
    const post = await hook(input("PostToolUse", "Edit", {}, t.work, { tool_response: { success: false, error: "old_string not found" } }), { home: t.home, cwd: t.work });
    expect(post.code).toBe(0);
    expect(t.s.executions.map((e) => e.status)).toEqual(["started", "failed"]);
    expect(t.s.executions[1]!.detail).toMatch(/old_string not found/);
  }, T);

  it("denied action / unknown tool_use_id → exit 0, no output, nothing reported", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const pre = await hook(writeEnv(t.work), { home: t.home, cwd: t.work });
    expect(pre.code).toBe(2);
    const post = await hook(input("PostToolUse", "Write", {}, t.work), { home: t.home, cwd: t.work });
    expect(post).toMatchObject({ code: 0, stdout: "" });
    const unknown = await hook(input("PostToolUse", "Write", {}, t.work, { tool_use_id: "toolu_other" }), { home: t.home, cwd: t.work });
    expect(unknown).toMatchObject({ code: 0, stdout: "" });
    expect(t.s.executions.filter((e) => e.status !== "blocked")).toHaveLength(0);
  }, T);

  it("run claude writes PreToolUse + PostToolUse + SessionEnd into its settings", async () => {
    const t = await setup();
    const fakebin = join(t.work, "fakebin");
    mkdirSync(fakebin);
    writeFileSync(join(fakebin, "claude"), `#!/bin/sh\nwhile [ "$1" != "--settings" ]; do shift; done\ncat "$2" > "$OUT"\n`, { mode: 0o755 });
    const out = join(t.work, "settings.json");
    const r = await runCli(["run", "claude"], { home: t.home, cwd: t.work, env: { PATH: `${fakebin}:/usr/bin:/bin`, OUT: out } });
    expect(r.code).toBe(0);
    const s = JSON.parse(readFileSync(out, "utf8"));
    expect(Object.keys(s.hooks)).toEqual(["PreToolUse", "PostToolUse", "SessionEnd"]);
  }, T);
});

describe("stale config.lock", () => {
  const expired = () => new Date(Date.now() - 60_000).toISOString();

  it("a fresh lock whose owner PID is dead is reclaimed immediately", async () => {
    const t = await setup({}, { tokenExpiresAt: expired(), refreshToken: "issue" });
    const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" }).stdout;
    writeFileSync(join(t.home, "config.lock"), `${dead}:${Date.now()}:0.5`);
    const t0 = Date.now();
    const r = await runCli(["request", "--", "true"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(t.s.refreshCalls).toBe(1);
  }, T);

  it("a lock held by a live process is respected", async () => {
    const t = await setup({}, { tokenExpiresAt: expired(), refreshToken: "issue" });
    writeFileSync(join(t.home, "config.lock"), `${process.pid}:${Date.now()}:0.5`); // the test runner: alive
    const child = runCli(["request", "--", "true"], { home: t.home, cwd: t.work });
    await new Promise((r) => setTimeout(r, 1_500));
    expect(t.s.refreshCalls).toBe(0);
    unlinkSync(join(t.home, "config.lock"));
    expect((await child).code).toBe(0);
    expect(t.s.refreshCalls).toBe(1);
  }, T);
});
