import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli, runProcess, type RunResult } from "./helpers.ts";

/**
 * `agentgate install claude-code` / `uninstall`, hook-managed sessions (no
 * AGENTGATE_SESSION_ID), SessionEnd, token refresh. Temp HOME + temp projects only —
 * never the real ~/.claude.
 */

const HOOK_SHIM = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
const T = 30_000;
const MARKER = "--agentgate-install=claude-code/v1";

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, env: { policy?: string | null; tokenExpiresAt?: string; refreshToken?: string | "issue" } = {}) {
  server = await new FakeServer(opts).start();
  const refreshToken = env.refreshToken === "issue" ? server.issueRefreshToken() : env.refreshToken;
  const e = makeEnv({
    server: server.url,
    token: server.token,
    publicKeyPem: server.keys.publicKeyPem,
    policy: env.policy,
    ...(env.tokenExpiresAt ? { tokenExpiresAt: env.tokenExpiresAt } : {}),
    ...(refreshToken ? { refreshToken } : {}),
  });
  const root = dirname(e.home);
  const fakeHome = join(root, "userhome");
  const project = join(root, "project");
  mkdirSync(fakeHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  return { s: server, ...e, fakeHome, project, probe: join(e.work, "executed.txt") };
}

const cli = (args: string[], o: { home: string; fakeHome: string; cwd: string; env?: Record<string, string> }) =>
  runCli(args, { home: o.home, cwd: o.cwd, env: { HOME: o.fakeHome, ...o.env } });

const readJson = (p: string) => JSON.parse(readFileSync(p, "utf8"));
const settingsPath = (project: string) => join(project, ".claude", "settings.local.json");
const cfg = (home: string) => readJson(join(home, "config.json"));

function gitInit(dir: string) {
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
}

function ourCommands(settings: any): string[] {
  return Object.values(settings.hooks ?? {}).flatMap((groups: any) =>
    groups.flatMap((g: any) => (g.hooks ?? []).map((h: any) => h.command)).filter((c: string) => c.includes(MARKER)),
  );
}

function hookInput(tool_name: string, tool_input: Record<string, unknown>, cwd: string, session_id = "claude-sess-A") {
  return JSON.stringify({
    session_id,
    transcript_path: "/tmp/t.jsonl",
    cwd,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name,
    tool_input,
    tool_use_id: "toolu_1",
  });
}

/** Installed-hook invocation: no AGENTGATE_SESSION_ID (like the desktop app). */
function runHook(input: string, o: { home: string; cwd: string; env?: Record<string, string> }) {
  return runProcess(HOOK_SHIM, [], { home: o.home, cwd: o.cwd, input, env: { AGENTGATE_NODE: process.execPath, ...o.env } });
}

const decision = (r: RunResult) => JSON.parse(r.stdout).hookSpecificOutput;
/** `K=v` or `K='v'` (shellQuote only quotes when needed). */
const hasVar = (cmd: string, k: string, v: string) => cmd.includes(`${k}=${v} `) || cmd.includes(`${k}='${v}' `);

async function closedPort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

// ─────────────────────────────────────────────────────────────────────────────

describe("install / uninstall claude-code", () => {
  const userGroup = { matcher: "Bash", hooks: [{ type: "command", command: "echo my-own-hook", timeout: 5 }] };

  it("project: merges with existing settings + hooks, backs up, git-ignores, is idempotent, uninstall restores exactly", async () => {
    const t = await setup();
    gitInit(t.project);
    const original = {
      permissions: { allow: ["Bash(ls:*)"] },
      hooks: { PreToolUse: [userGroup], PostToolUse: [{ matcher: "Write", hooks: [{ type: "command", command: "echo post" }] }] },
      model: "opus",
    };
    mkdirSync(join(t.project, ".claude"));
    writeFileSync(settingsPath(t.project), JSON.stringify(original, null, 2));

    const r = await cli(["install", "claude-code", "--project", t.project], { ...t, cwd: t.work });
    expect(r.code).toBe(0);
    const s = readJson(settingsPath(t.project));
    expect(s.permissions).toEqual(original.permissions);
    expect(s.model).toBe("opus");
    expect(s.hooks.PostToolUse[0]).toEqual(original.hooks.PostToolUse[0]); // user's first, ours appended
    expect(s.hooks.PostToolUse).toHaveLength(2);
    expect(s.hooks.PostToolUse[1].matcher).toBe("Write|Edit|MultiEdit|NotebookEdit|mcp__.*");
    expect(s.hooks.PostToolUse[1].hooks[0].timeout).toBe(10);
    expect(s.hooks.PreToolUse[0]).toEqual(userGroup); // user's own hook untouched, first
    expect(s.hooks.PreToolUse).toHaveLength(2);
    expect(s.hooks.PreToolUse[1].matcher).toBe("Bash|Read|Write|Edit|MultiEdit|NotebookEdit|mcp__.*");
    expect(s.hooks.PreToolUse[1].hooks[0].timeout).toBe(600);
    expect(s.hooks.SessionEnd).toHaveLength(1);
    expect(s.hooks.SessionEnd[0].hooks[0].timeout).toBe(10);

    const cmd: string = s.hooks.PreToolUse[1].hooks[0].command;
    expect(hasVar(cmd, "AGENTGATE_NODE", process.execPath)).toBe(true);
    expect(hasVar(cmd, "AGENTGATE_HOME", t.home)).toBe(true);
    expect(cmd).toMatch(/\/daemon\/agentgate\/bin\/agentgate-hook\.sh'? --agentgate-install=claude-code\/v1$/);
    expect(cmd).not.toContain(t.s.token); // no secrets
    expect(cmd).not.toMatch(/agr_/);

    // backup + gitignore
    const backups = readdirSync(join(t.project, ".claude")).filter((n) => n.includes(".agentgate-backup-"));
    expect(backups).toHaveLength(1);
    expect(readJson(join(t.project, ".claude", backups[0]!))).toEqual(original);
    execFileSync("git", ["check-ignore", "-q", ".claude/settings.local.json"], { cwd: t.project }); // throws if not ignored

    // idempotent
    expect((await cli(["install", "claude-code", "--project", t.project], { ...t, cwd: t.work })).code).toBe(0);
    expect(ourCommands(readJson(settingsPath(t.project)))).toHaveLength(7); // PreToolUse + PostToolUse + SessionEnd + 4 observe events

    // status reports it
    const st = await cli(["status"], { ...t, cwd: t.project });
    expect(st.stdout).toMatch(/hook installed \(project\)/);

    // uninstall → exactly the original content, exclude line removed
    const u = await cli(["uninstall", "claude-code", "--project", t.project], { ...t, cwd: t.work });
    expect(u.code).toBe(0);
    expect(readJson(settingsPath(t.project))).toEqual(original);
    expect(readFileSync(join(t.project, ".git", "info", "exclude"), "utf8")).not.toContain("settings.local.json");
  }, T);

  it("project without prior settings: creates file + .claude; uninstall removes both", async () => {
    const t = await setup();
    const r = await cli(["install", "claude-code"], { ...t, cwd: t.project }); // --project defaults to cwd
    expect(r.code).toBe(0);
    expect(statSync(settingsPath(t.project)).mode & 0o777).toBe(0o600);
    expect(Object.keys(readJson(settingsPath(t.project)))).toEqual(["hooks"]);
    expect((await cli(["uninstall", "claude-code"], { ...t, cwd: t.project })).code).toBe(0);
    expect(existsSync(settingsPath(t.project))).toBe(false);
    expect(existsSync(join(t.project, ".claude"))).toBe(false);
  }, T);

  it("uninstall removes only our entries, even if the user added hooks after install", async () => {
    const t = await setup();
    expect((await cli(["install", "claude-code"], { ...t, cwd: t.project })).code).toBe(0);
    const s = readJson(settingsPath(t.project));
    s.hooks.PreToolUse.push(userGroup);
    s.theme = "dark";
    writeFileSync(settingsPath(t.project), JSON.stringify(s));
    expect((await cli(["uninstall", "claude-code"], { ...t, cwd: t.project })).code).toBe(0);
    const after = readJson(settingsPath(t.project));
    expect(after).toEqual({ hooks: { PreToolUse: [userGroup] }, theme: "dark" });
  }, T);

  it("--user without --yes refuses and writes nothing; with --yes merges into ~/.claude/settings.json", async () => {
    const t = await setup();
    const userSettings = join(t.fakeHome, ".claude", "settings.json");
    mkdirSync(dirname(userSettings));
    writeFileSync(userSettings, JSON.stringify({ model: "sonnet" }));

    const no = await cli(["install", "claude-code", "--user"], { ...t, cwd: t.work });
    expect(no.code).toBe(2);
    expect(no.stderr).toMatch(/EVERY Claude Code session/);
    expect(no.stderr).toMatch(/desktop app/);
    expect(readJson(userSettings)).toEqual({ model: "sonnet" });

    const yes = await cli(["install", "claude-code", "--user", "--yes"], { ...t, cwd: t.work });
    expect(yes.code).toBe(0);
    const s = readJson(userSettings);
    expect(s.model).toBe("sonnet");
    expect(ourCommands(s)).toHaveLength(7);

    // a project install on top would double-ask → refused
    expect((await cli(["install", "claude-code"], { ...t, cwd: t.project })).code).toBe(1);

    expect((await cli(["uninstall", "claude-code", "--user"], { ...t, cwd: t.work })).code).toBe(0);
    expect(readJson(userSettings)).toEqual({ model: "sonnet" });
  }, T);

  it("refuses to touch invalid JSON", async () => {
    const t = await setup();
    mkdirSync(join(t.project, ".claude"));
    writeFileSync(settingsPath(t.project), "{ not json");
    const r = await cli(["install", "claude-code"], { ...t, cwd: t.project });
    expect(r.code).toBe(1);
    expect(readFileSync(settingsPath(t.project), "utf8")).toBe("{ not json");
  }, T);

  it("refuses when not logged in", async () => {
    const t = await setup();
    await cli(["logout"], { ...t, cwd: t.work });
    const r = await cli(["install", "claude-code"], { ...t, cwd: t.project });
    expect(r.code).toBe(1);
    expect(existsSync(settingsPath(t.project))).toBe(false);
  }, T);

  it("the installed command works with a minimal env (PATH=/usr/bin:/bin, no HOME): allow + approved exec", async () => {
    const t = await setup();
    expect((await cli(["install", "claude-code"], { ...t, cwd: t.project })).code).toBe(0);
    const cmd: string = readJson(settingsPath(t.project)).hooks.PreToolUse.at(-1).hooks[0].command;
    const minimal = { PATH: "/usr/bin:/bin" };

    const allow = await runProcess("/bin/sh", ["-c", cmd], {
      home: t.home,
      cwd: t.project,
      bareEnv: true,
      env: minimal,
      input: hookInput("Bash", { command: "ls" }, t.project),
    });
    expect(allow.stderr).toBe("");
    expect(allow.code).toBe(0);
    expect(decision(allow).permissionDecision).toBe("allow");

    const probe = join(t.project, "made.txt");
    const ask = await runProcess("/bin/sh", ["-c", cmd], {
      home: t.home,
      cwd: t.project,
      bareEnv: true,
      env: minimal,
      input: hookInput("Bash", { command: `touch ${probe}` }, t.project),
    });
    expect(ask.code).toBe(0);
    const wrapped: string = decision(ask).updatedInput.command;
    expect(hasVar(wrapped, "AGENTGATE_NODE", process.execPath)).toBe(true);

    // Claude's Bash tool, minimal env, NO AGENTGATE_SESSION_ID: binding comes from the record.
    const ex = await runProcess("/bin/sh", ["-c", wrapped], { home: t.home, cwd: t.project, bareEnv: true, env: minimal });
    expect(ex.code).toBe(0);
    expect(existsSync(probe)).toBe(true);
    expect(t.s.executions.map((e) => e.status)).toEqual(["started", "completed"]);
  }, T);

  it("run claude defers to an installed hook (no second --settings hook → no double approval)", async () => {
    const t = await setup();
    expect((await cli(["install", "claude-code"], { ...t, cwd: t.project })).code).toBe(0);
    const fakebin = join(t.work, "fakebin");
    mkdirSync(fakebin);
    writeFileSync(join(fakebin, "claude"), `#!/bin/sh\necho "$@" > "$FAKE_ARGS"\n`, { mode: 0o755 });
    const argsFile = join(t.work, "args.txt");
    const r = await cli(["run", "claude", "--", "--x"], {
      ...t,
      cwd: t.project,
      env: { PATH: `${fakebin}:${dirname(process.execPath)}:/usr/bin:/bin`, FAKE_ARGS: argsFile },
    });
    expect(r.code).toBe(0);
    expect(readFileSync(argsFile, "utf8").trim()).toBe("--x");
  }, T);
});

// ─────────────────────────────────────────────────────────────────────────────

describe("hook-managed sessions (no AGENTGATE_SESSION_ID)", () => {
  it("creates one AgentGate session per Claude session and reuses it; mapping file is 0600", async () => {
    const t = await setup();
    const a1 = await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-1"), { home: t.home, cwd: t.work });
    const a2 = await runHook(hookInput("Bash", { command: "pwd" }, t.work, "claude-1"), { home: t.home, cwd: t.work });
    const b1 = await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-2"), { home: t.home, cwd: t.work });
    expect([a1.code, a2.code, b1.code]).toEqual([0, 0, 0]);
    expect(t.s.createdSessions).toHaveLength(2);
    const m = readJson(join(t.home, "sessions", "claude-1.json"));
    expect(m.session_id).toBe(t.s.createdSessions[0]);
    expect(statSync(join(t.home, "sessions", "claude-1.json")).mode & 0o777).toBe(0o600);
    const sub = t.s.requests.filter((q) => q.path === "/v1/actions").map((q) => (q.body as any).action.session_id);
    expect(sub).toEqual([t.s.createdSessions[0], t.s.createdSessions[0], t.s.createdSessions[1]]);
    // registered as a claude-code agent, cached in config
    expect(t.s.requests.find((q) => q.path === "/v1/agents")!.body).toMatchObject({ type: "claude-code" });
    expect(cfg(t.home).claude_agent_id).toBe("agt_test");
  }, T);

  it("race: 6 parallel hooks for a new Claude session create exactly one AgentGate session", async () => {
    const t = await setup({ sessionDelayMs: 150 });
    const runs = await Promise.all(
      Array.from({ length: 6 }, (_, i) => runHook(hookInput("Bash", { command: `echo ${i}` }, t.work, "claude-race"), { home: t.home, cwd: t.work })),
    );
    expect(runs.map((r) => r.code)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(t.s.createdSessions).toHaveLength(1);
    const used = new Set(t.s.requests.filter((q) => q.path === "/v1/actions").map((q) => (q.body as any).action.session_id));
    expect([...used]).toEqual(t.s.createdSessions);
  }, T);

  it("mapped session ended server-side → a new session is created and the call still succeeds", async () => {
    const t = await setup();
    expect((await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-x"), { home: t.home, cwd: t.work })).code).toBe(0);
    t.s.endedSessions.push(t.s.createdSessions[0]!);
    const r = await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-x"), { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
    expect(t.s.createdSessions).toHaveLength(2);
    expect(readJson(join(t.home, "sessions", "claude-x.json")).session_id).toBe(t.s.createdSessions[1]);
  }, T);

  it("approved Bash: exec takes the session binding from the approval record (no env var)", async () => {
    const t = await setup();
    const r = await runHook(hookInput("Bash", { command: `touch ${t.probe}` }, t.work, "claude-exec"), { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
    const rec = readJson(join(t.home, "approvals", readdirSync(join(t.home, "approvals"))[0]!));
    expect(rec.session_id).toBe(t.s.createdSessions[0]);
    const ex = await runProcess("/bin/sh", ["-c", decision(r).updatedInput.command], { home: t.home, cwd: t.work });
    expect(ex.code).toBe(0);
    expect(existsSync(t.probe)).toBe(true);
  }, T);

  it("SessionEnd ends the mapped session, removes the mapping, exits 0", async () => {
    const t = await setup();
    await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-end"), { home: t.home, cwd: t.work });
    const sid = t.s.createdSessions[0]!;
    const end = await runHook(JSON.stringify({ session_id: "claude-end", cwd: t.work, hook_event_name: "SessionEnd", reason: "prompt_input_exit" }), {
      home: t.home,
      cwd: t.work,
    });
    expect(end.code).toBe(0);
    expect(end.stdout).toBe("");
    expect(t.s.endedSessions).toEqual([sid]);
    expect(existsSync(join(t.home, "sessions", "claude-end.json"))).toBe(false);
  }, T);

  it("SessionEnd never blocks: server down → still exit 0 quickly", async () => {
    const t = await setup();
    await runHook(hookInput("Bash", { command: "ls" }, t.work, "claude-down"), { home: t.home, cwd: t.work });
    const c = cfg(t.home);
    c.server = `http://127.0.0.1:${await closedPort()}`;
    writeFileSync(join(t.home, "config.json"), JSON.stringify(c));
    const t0 = Date.now();
    const end = await runHook(JSON.stringify({ session_id: "claude-down", cwd: t.work, hook_event_name: "SessionEnd" }), { home: t.home, cwd: t.work });
    expect(end.code).toBe(0);
    expect(Date.now() - t0).toBeLessThan(8_000);
  }, T);

  it("SessionEnd under `agentgate run` (AGENTGATE_SESSION_ID set) does nothing", async () => {
    const t = await setup();
    const end = await runHook(JSON.stringify({ session_id: "x", cwd: t.work, hook_event_name: "SessionEnd" }), {
      home: t.home,
      cwd: t.work,
      env: { AGENTGATE_SESSION_ID: "ses_run" },
    });
    expect(end.code).toBe(0);
    expect(t.s.endedSessions).toEqual([]);
  }, T);
});

// ─────────────────────────────────────────────────────────────────────────────

describe("token refresh", () => {
  const expired = () => new Date(Date.now() - 60_000).toISOString();

  it("happy path: expired access token is refreshed transparently; config rotated (0600)", async () => {
    const t = await setup({}, { tokenExpiresAt: expired(), refreshToken: "issue" });
    const before = cfg(t.home);
    const r = await runCli(["request", "--", "echo", "hi"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("hi");
    expect(t.s.refreshCalls).toBe(1);
    const after = cfg(t.home);
    expect(after.access_token).not.toBe(before.access_token);
    expect(after.refresh_token).not.toBe(before.refresh_token);
    expect(Date.parse(after.token_expires_at)).toBeGreaterThan(Date.now());
    expect(statSync(join(t.home, "config.json")).mode & 0o777).toBe(0o600);
  }, T);

  it("rotation: each refresh presents the latest token (a chain, no reuse)", async () => {
    const t = await setup({}, { tokenExpiresAt: expired(), refreshToken: "issue" });
    for (let i = 0; i < 3; i++) {
      const c = cfg(t.home);
      c.token_expires_at = expired();
      writeFileSync(join(t.home, "config.json"), JSON.stringify(c), { mode: 0o600 });
      expect((await runCli(["request", "--", "true"], { home: t.home, cwd: t.work })).code).toBe(0);
    }
    expect(t.s.refreshCalls).toBe(3);
    const revoked = [...t.s.refreshTokens.values()].filter((r) => r.revoked);
    expect(revoked).toHaveLength(0);
  }, T);

  it("parallel hooks with an expired token refresh exactly once (lock + re-read)", async () => {
    const t = await setup({ refreshDelayMs: 200 }, { tokenExpiresAt: expired(), refreshToken: "issue" });
    const runs = await Promise.all(
      Array.from({ length: 5 }, (_, i) => runHook(hookInput("Bash", { command: `echo ${i}` }, t.work, "claude-p"), { home: t.home, cwd: t.work })),
    );
    expect(runs.map((r) => r.code)).toEqual([0, 0, 0, 0, 0]);
    expect(t.s.refreshCalls).toBe(1);
    expect([...t.s.refreshTokens.values()].some((r) => r.revoked)).toBe(false);
  }, T);

  it("reuse detected (server revoked the family) → request 77, hook 2, clear login message", async () => {
    const t = await setup({}, { tokenExpiresAt: expired(), refreshToken: "issue" });
    const old = cfg(t.home).refresh_token;
    expect((await runCli(["request", "--", "true"], { home: t.home, cwd: t.work })).code).toBe(0); // rotates
    // simulate a stale copy (e.g. restored backup) presenting the rotated token
    const c = cfg(t.home);
    c.refresh_token = old;
    c.token_expires_at = expired();
    writeFileSync(join(t.home, "config.json"), JSON.stringify(c), { mode: 0o600 });

    const r = await runCli(["request", "--", "true"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/refresh_token_reused.*agentgate login/);
    expect([...t.s.refreshTokens.values()].every((x) => x.revoked)).toBe(true);

    const h = await runHook(hookInput("Bash", { command: "ls" }, t.work), { home: t.home, cwd: t.work });
    expect(h.code).toBe(2);
    expect(h.stderr).toMatch(/agentgate login/);
  }, T);

  it("expired refresh token → request 77 / hook 2 / exec 77", async () => {
    const t = await setup({}, { tokenExpiresAt: expired() });
    const c = cfg(t.home);
    c.refresh_token = t.s.issueRefreshToken({ expired: true });
    writeFileSync(join(t.home, "config.json"), JSON.stringify(c), { mode: 0o600 });
    const r = await runCli(["request", "--", "true"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/refresh_token_expired/);
    expect((await runHook(hookInput("Bash", { command: "ls" }, t.work), { home: t.home, cwd: t.work })).code).toBe(2);
    expect((await runCli(["exec", "--approval", "apr_whatever", "--", "true"], { home: t.home, cwd: t.work })).code).toBe(77);
  }, T);

  it("no refresh token + expired access token → blocked (unchanged behavior)", async () => {
    const t = await setup({}, { tokenExpiresAt: expired() });
    const r = await runCli(["request", "--", "true"], { home: t.home, cwd: t.work });
    expect(r.code).toBe(77);
    expect(r.stderr).toMatch(/agentgate login/);
  }, T);

  it("login stores the refresh token; logout deletes it", async () => {
    const t = await setup();
    expect((await runCli(["login", "--server", t.s.url], { home: t.home, cwd: t.work })).code).toBe(0);
    expect(cfg(t.home).refresh_token).toMatch(/^agr_/);
    const shown = await runCli(["config"], { home: t.home, cwd: t.work });
    expect(shown.stdout).not.toMatch(/agr_[A-Za-z0-9]/);
    await runCli(["logout"], { home: t.home, cwd: t.work });
    expect(cfg(t.home).refresh_token).toBeUndefined();
  }, T);
});
