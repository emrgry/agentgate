import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeEnv, runCli, runProcess } from "./helpers.ts";

/**
 * Control Center through the real stack: `agentgate setup` (fake launchd) → `agentgate serve`
 * with the supervisor, the fake agent as the provider binary, CLI session/workspace commands,
 * and observed-session hooks through the real shim.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE_LAUNCHCTL = join(HERE, "fake-launchctl.mjs");
const FAKE_AGENT = join(HERE, "..", "..", "..", "apps", "api", "test", "fake-agent.mjs");
const HOOK_SHIM = join(HERE, "..", "bin", "agentgate-hook.sh");
const T = 90_000;

async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const p = (s.address() as { port: number }).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}

let env: { home: string; work: string; userHome: string; launchd: string; port: number };
const run = (args: string[], extra: Record<string, string> = {}) =>
  runCli(args, {
    home: env.home,
    cwd: env.work,
    env: {
      HOME: env.userHome,
      AGENTGATE_LAUNCHCTL: FAKE_LAUNCHCTL,
      AGENTGATE_SETUP_PLATFORM: "darwin",
      FAKE_LAUNCHD_DIR: env.launchd,
      FAKE_LAUNCHD_EXTRA_ENV: JSON.stringify({ AGENTGATE_CLAUDE_BIN: FAKE_AGENT }),
      ...extra,
    },
  });

beforeAll(async () => {
  const e = makeEnv({ server: "http://127.0.0.1:1", token: "x".repeat(24), publicKeyPem: "x", policy: null });
  const root = dirname(e.home);
  const userHome = join(root, "userhome");
  mkdirSync(userHome, { recursive: true });
  env = { home: join(root, "cchome"), work: e.work, userHome, launchd: join(root, "launchd"), port: await freePort() };
  chmodSync(FAKE_LAUNCHCTL, 0o755);
  const r = await run(["setup", "--port", String(env.port), "--no-pair"]);
  if (r.code !== 0) throw new Error(`setup failed: ${r.stderr}`);
}, T);

afterAll(async () => {
  if (env) await run(["uninstall-server", "--purge"]);
}, T);

describe("control center CLI (real server + supervisor)", () => {
  it("serve wrote managed-turn hook settings (PreToolUse gating + PostToolUse), 0600", () => {
    const f = join(env.home, "server", "managed-hooks.json");
    const s = JSON.parse(readFileSync(f, "utf8"));
    expect(Object.keys(s.hooks)).toEqual(["PreToolUse", "PostToolUse"]);
    expect(s.hooks.PreToolUse[0].hooks[0].command).toContain("agentgate-hook.sh");
  });

  it("session start → tail → list; question → send answers → resumed; stop ends it", async () => {
    const st = await run(["session", "start", "ask:Which file should I delete?"]);
    expect(st.code).toBe(0);
    const id = st.stdout.trim();
    expect(id).toMatch(/^ags_/);
    const tail = await run(["session", "tail", id]);
    expect(tail.stdout).toMatch(/message\.user.*ask:Which file/);
    expect(tail.stdout).toMatch(/input\.required.*Which file should I delete\?/);
    expect(tail.stdout).toMatch(/question pending/);
    const list = await run(["session", "list"]);
    expect(list.stdout).toMatch(new RegExp(`${id}\\s+waiting_input\\s+managed`));
    expect((await run(["session", "send", id, "say:deleted one.txt"])).stderr).toMatch(/answered applied/);
    const tail2 = await run(["session", "tail", id]);
    expect(tail2.stdout).toMatch(/message\.assistant deleted one\.txt/);
    expect((await run(["session", "stop", id])).stderr).toMatch(/stop: completed/);
  }, T);

  it("task add / list: queued tasks run in order after the current one", async () => {
    const id = (await run(["session", "start", "ticks:3;say:one"])).stdout.trim();
    expect((await run(["task", "add", id, "say:two", "--title", "Second"])).stderr).toMatch(/task (queued|started)/);
    for (let i = 0; i < 100; i++) {
      const l = (await run(["task", "list", id])).stdout;
      if ((l.match(/completed/g) ?? []).length === 2) {
        expect(l).toMatch(/0\s+tsk_\S+\s+completed.*ticks:3;say:one/);
        expect(l).toMatch(/1\s+tsk_\S+\s+completed.*Second/);
        return;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error("tasks did not complete");
  }, T);

  it("kill a running session", async () => {
    const id = (await run(["session", "start", "hang"])).stdout.trim();
    await new Promise((r) => setTimeout(r, 800));
    expect((await run(["session", "kill", id])).code).toBe(0);
    for (let i = 0; i < 40; i++) {
      if ((await run(["session", "list"])).stdout.match(new RegExp(`${id}\\s+killed`))) return;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error("session was not killed");
  }, T);

  it("workspace allow-ungated / disallow-ungated (local opt-in for providers AgentGate can't gate)", async () => {
    expect((await run(["workspace", "add", env.work, "--label", "ug"])).code).toBe(0);
    const allow = await run(["workspace", "allow-ungated", env.work, "aider"]);
    expect(allow.code).toBe(0);
    expect(allow.stderr + allow.stdout).toMatch(/UNGATED/);
    expect((await run(["workspace", "list"])).stdout).toMatch(/UNGATED: aider/);
    expect((await run(["workspace", "disallow-ungated", env.work, "aider"])).code).toBe(0);
    expect((await run(["workspace", "list"])).stdout).not.toMatch(/UNGATED/);
    expect((await run(["workspace", "allow-ungated", env.work])).code).toBe(2);
    await run(["workspace", "remove", env.work]);
  }, T);

  it("limits set --global / --session, limits show, usage", async () => {
    const g = await run(["limits", "set", "--global", "--max-cost-task", "2", "--max-retries", "3", "--on-exceed", "notify"]);
    expect(g.stderr).toMatch(/limits set for all sessions/);
    expect(g.code).toBe(0);
    expect(JSON.parse((await run(["limits", "show"])).stdout).global_limits).toEqual({ max_cost_usd_per_task: 2, max_retries: 3, on_exceed: "notify" });
    const id = (await run(["session", "start", "say:hi"])).stdout.trim();
    expect((await run(["limits", "set", "--session", id, "--max-cost-task", "none", "--max-rss-mb", "512"])).code).toBe(0);
    const shown = JSON.parse((await run(["limits", "show", "--session", id])).stdout);
    expect(shown.limits).toEqual({ max_cost_usd_per_task: null, max_retries: 3, max_rss_mb: 512, on_exceed: "ask" });
    expect((await run(["limits", "set", "--max-cost-task", "1"])).code).toBe(2); // needs --session or --global
    expect((await run(["limits", "set", "--global", "--on-exceed", "explode"])).code).toBe(2);
    const u = await run(["usage", "--range", "today"]);
    expect(u.code).toBe(0);
    expect(u.stdout).toMatch(/usage \(today\)/);
    expect(u.stdout).toMatch(/claude-code\s+\d+ sessions/);
    expect((await run(["usage", "--range", "1y"])).code).toBe(2);
  }, T);

  it("workspace add / list / remove", async () => {
    const add = await run(["workspace", "add", env.work, "--label", "demo"]);
    expect(add.code).toBe(0);
    expect((await run(["workspace", "list"])).stdout).toMatch(/demo\s+\//);
    expect((await run(["workspace", "remove", env.work])).code).toBe(0);
    expect((await run(["workspace", "list"])).stdout).toMatch(/no workspaces/);
  }, T);

  it("observed session via the installed hook shim (--agentgate-observe): exit 0, no stdout, reported", async () => {
    const hook = (payload: Record<string, unknown>) =>
      runProcess(HOOK_SHIM, ["--agentgate-install=claude-code/v1", "--agentgate-observe"], {
        home: env.home,
        cwd: env.work,
        input: JSON.stringify({ session_id: "claude-interactive-1", cwd: env.work, ...payload }),
        env: { AGENTGATE_NODE: process.execPath, HOME: env.userHome },
      });
    for (const p of [
      { hook_event_name: "SessionStart", source: "startup" },
      { hook_event_name: "UserPromptSubmit", prompt: "Refactor the parser" },
      { hook_event_name: "Notification", notification_type: "idle_prompt", message: "Claude is waiting for your input" },
    ]) {
      const r = await hook(p);
      expect([r.code, r.stdout]).toEqual([0, ""]);
    }
    const list = await run(["session", "list"]);
    expect(list.stdout).toMatch(/waiting_input\s+observed\s+.*Refactor the parser/);
  }, T);

  it("observe hooks fired inside a managed turn (AGENTGATE_MANAGED_SESSION) don't create an observed duplicate", async () => {
    const id = (await run(["session", "start", "say:hi"])).stdout.trim();
    const before = (await run(["session", "list"])).stdout.split("\n").filter(Boolean).length;
    for (const p of [{ hook_event_name: "SessionStart", source: "startup" }, { hook_event_name: "Stop" }]) {
      const r = await runProcess(HOOK_SHIM, ["--agentgate-install=claude-code/v1", "--agentgate-observe"], {
        home: env.home,
        cwd: env.work,
        input: JSON.stringify({ session_id: "claude-managed-dup-1", cwd: "/somewhere/else", ...p }),
        env: { AGENTGATE_NODE: process.execPath, HOME: env.userHome, AGENTGATE_MANAGED_SESSION: id },
      });
      expect([r.code, r.stdout]).toEqual([0, ""]);
    }
    const list = (await run(["session", "list"])).stdout;
    expect(list.split("\n").filter(Boolean).length).toBe(before);
    expect(list).not.toMatch(/claude-managed-dup-1/);
  }, T);

  it("observe shim never fails, even without node (Stop must not be blocked)", async () => {
    const r = await runProcess(HOOK_SHIM, ["--agentgate-observe"], {
      home: env.home,
      cwd: env.work,
      input: "{}",
      bareEnv: true,
      env: { PATH: "/usr/bin:/bin" },
    });
    expect([r.code, r.stdout]).toEqual([0, ""]);
    // the same shim WITHOUT observe mode stays fail-closed
    const gate = await runProcess(HOOK_SHIM, [], { home: env.home, cwd: env.work, input: "{}", bareEnv: true, env: { PATH: "/usr/bin:/bin" } });
    expect(gate.code).toBe(2);
  }, T);
});
