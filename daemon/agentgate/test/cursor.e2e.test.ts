import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DecisionPayloadV2 } from "@agentgate/protocol";
import { generateDeviceKeyPair, publicKeyFingerprint, signDecision } from "@agentgate/signing";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type AskContext, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runCli, runProcess, type RunResult } from "./helpers.ts";

/**
 * Cursor integration: `agentgate install|uninstall cursor` (hooks.json merge / restore) and
 * `agentgate hook cursor` through the real fail-closed shim. Temp HOME + temp AGENTGATE_HOME
 * only — never the real ~/.cursor or ~/.agentgate.
 */

const BIN_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "bin");
const HOOK_SHIM = join(BIN_DIR, "agentgate-hook.sh");
const CLI_SHIM = join(BIN_DIR, "agentgate.sh");
const MARKER = "--agentgate-install=cursor/v1";
const T = 30_000;

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

const rnd = (n: number) => new Uint8Array(randomBytes(n));
const phone = generateDeviceKeyPair(rnd);

async function setup(opts: FakeServerOptions = {}, env: { policy?: string | null; requireSig?: boolean; serverUrl?: string } = {}) {
  server = await new FakeServer(opts).start();
  server.deviceKeys = [{ device_id: "dev_A", public_key: phone.publicKey, fingerprint: publicKeyFingerprint(phone.publicKey), revoked_at: null }];
  const e = makeEnv({ server: env.serverUrl ?? server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy: env.policy });
  if (env.requireSig !== false) {
    const p = join(e.home, "config.json");
    writeFileSync(p, JSON.stringify({ ...JSON.parse(readFileSync(p, "utf8")), require_device_signatures: true }), { mode: 0o600 });
  }
  const root = dirname(e.home);
  const fakeHome = join(root, "userhome");
  const project = join(root, "project");
  mkdirSync(fakeHome, { recursive: true });
  mkdirSync(project, { recursive: true });
  currentWork = e.work;
  return { s: server, ...e, fakeHome, project };
}

/** A phone-signed (v2) decision for the pending approval, relayed by the (fake) server. */
function signed(c: AskContext, over: Partial<DecisionPayloadV2> = {}, key = phone.privateKey): string {
  const now = Date.now();
  return signDecision(
    {
      v: 2,
      approval_id: c.approval.approval_id,
      action_id: c.action.action_id,
      session_id: c.sessionId,
      action_hash: c.actionHash,
      decision: "approve",
      device_id: "dev_A",
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + 60_000).toISOString(),
      nonce: Buffer.from(rnd(18)).toString("base64url"),
      ...over,
    },
    key,
  );
}
const approveOnPhone = (c: AskContext) => c.server.resolve(c, "approved", signed(c));

/** Work dir of the most recent setup() (the workspace root Cursor would report). */
let currentWork = "";
function payload(event: string, fields: Record<string, unknown>, work = currentWork) {
  return JSON.stringify({
    conversation_id: "conv-1",
    generation_id: "gen-1",
    model: "m",
    hook_event_name: event,
    cursor_version: "3.1.4",
    workspace_roots: [work],
    user_email: null,
    transcript_path: null,
    ...fields,
  });
}

function hook(input: string, o: { home: string; fakeHome: string; cwd: string; env?: Record<string, string>; claude?: boolean }) {
  return runProcess(HOOK_SHIM, o.claude ? ["--agentgate-install=claude-code/v1"] : ["--agentgate-provider=cursor", MARKER], {
    home: o.home,
    cwd: o.cwd,
    input,
    env: { AGENTGATE_NODE: process.execPath, HOME: o.fakeHome, AGENTGATE_HOOK_TIMEOUT_S: "300", ...o.env },
  });
}

function decision(r: RunResult): { permission: string; user_message?: string; agent_message?: string } {
  expect(r.code).toBe(0);
  const lines = r.stdout.trim().split("\n");
  expect(lines).toHaveLength(1); // exactly one JSON answer, nothing else on stdout
  return JSON.parse(lines[0]!);
}

const cli = (args: string[], o: { home: string; fakeHome: string; cwd: string }) => runCli(args, { home: o.home, cwd: o.cwd, env: { HOME: o.fakeHome } });
const userHooks = (fakeHome: string) => join(fakeHome, ".cursor", "hooks.json");
const readJson = (p: string) => JSON.parse(readFileSync(p, "utf8"));

// ── install / uninstall ─────────────────────────────────────────────────────

describe("agentgate install cursor", () => {
  it("--user needs --yes; then writes a fail-closed hooks.json with stable paths; idempotent; uninstall removes what it created", async () => {
    const t = await setup();
    const refused = await cli(["install", "cursor", "--user"], { ...t, cwd: t.work });
    expect(refused.code).toBe(2);
    expect(refused.stderr).toMatch(/refusing without --yes/);
    expect(existsSync(userHooks(t.fakeHome))).toBe(false);

    const r = await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work });
    expect(r.stderr).toMatch(/installed AgentGate Cursor hooks/);
    expect(r.code).toBe(0);
    const doc = readJson(userHooks(t.fakeHome));
    expect(doc.version).toBe(1);
    expect(Object.keys(doc.hooks).sort()).toEqual(["beforeMCPExecution", "beforeReadFile", "beforeShellExecution", "preToolUse", "sessionEnd"]);
    for (const ev of ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse"]) {
      expect(doc.hooks[ev]).toHaveLength(1);
      expect(doc.hooks[ev][0]).toMatchObject({ timeout: 300, failClosed: true });
      expect(doc.hooks[ev][0].command).toContain(`${HOOK_SHIM} --agentgate-provider=cursor ${MARKER}`);
      expect(doc.hooks[ev][0].command).toContain(`AGENTGATE_HOME=${t.home}`);
      expect(doc.hooks[ev][0].command).toContain("AGENTGATE_HOOK_TIMEOUT_S=300");
    }
    expect(doc.hooks.preToolUse[0].matcher).toBe("Write|Edit|Delete|Patch|Replace|Notebook|Create|Move|Rename");
    expect(doc.hooks.sessionEnd[0].failClosed).toBeUndefined();
    expect(readJson(join(t.home, "cursor-installs.json"))[userHooks(t.fakeHome)]).toMatchObject({ scope: "user", restore: { kind: "absent" } });

    const bytes = readFileSync(userHooks(t.fakeHome), "utf8");
    const again = await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work });
    expect(again.code).toBe(0);
    expect(again.stderr).toMatch(/unchanged/);
    expect(readFileSync(userHooks(t.fakeHome), "utf8")).toBe(bytes);

    const u = await cli(["uninstall", "cursor", "--user"], { ...t, cwd: t.work });
    expect(u.code).toBe(0);
    expect(existsSync(userHooks(t.fakeHome))).toBe(false);
    expect(existsSync(join(t.fakeHome, ".cursor"))).toBe(false); // we created the dir, it is empty again
    expect(readJson(join(t.home, "cursor-installs.json"))).toEqual({});
  }, T);

  it("merges into an existing hooks.json without touching the user's hooks, backs up, and restores it byte-for-byte", async () => {
    const t = await setup();
    mkdirSync(join(t.fakeHome, ".cursor"), { recursive: true });
    const original = `{
    "version": 1,
    "hooks": {
        "afterFileEdit": [ { "command": "./hooks/format.sh" } ],
        "beforeShellExecution": [ { "command": "./hooks/audit.sh", "matcher": "curl" } ]
    },
    "x-note": "kept"
}
`;
    writeFileSync(userHooks(t.fakeHome), original);
    expect((await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work })).code).toBe(0);
    const doc = readJson(userHooks(t.fakeHome));
    expect(doc["x-note"]).toBe("kept");
    expect(doc.hooks.afterFileEdit).toEqual([{ command: "./hooks/format.sh" }]);
    expect(doc.hooks.beforeShellExecution[0]).toEqual({ command: "./hooks/audit.sh", matcher: "curl" }); // user's first, ours appended
    expect(doc.hooks.beforeShellExecution[1].command).toContain(MARKER);
    expect(readFileSync(userHooks(t.fakeHome), "utf8")).toMatch(/\n {4}"hooks"/); // indentation preserved
    expect(readdirSync(join(t.fakeHome, ".cursor")).some((n) => n.startsWith("hooks.json.agentgate-backup-"))).toBe(true);

    expect((await cli(["uninstall", "cursor", "--user"], { ...t, cwd: t.work })).code).toBe(0);
    expect(readFileSync(userHooks(t.fakeHome), "utf8")).toBe(original);
  }, T);

  it("file edited after install → uninstall removes only AgentGate's entries and keeps the edit", async () => {
    const t = await setup();
    expect((await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work })).code).toBe(0);
    const doc = readJson(userHooks(t.fakeHome));
    doc.hooks.stop = [{ command: "./hooks/stop.sh" }];
    doc.hooks.beforeShellExecution.unshift({ command: "./mine.sh" });
    writeFileSync(userHooks(t.fakeHome), JSON.stringify(doc, null, 2));
    expect((await cli(["uninstall", "cursor", "--user"], { ...t, cwd: t.work })).code).toBe(0);
    expect(readJson(userHooks(t.fakeHome))).toEqual({ version: 1, hooks: { beforeShellExecution: [{ command: "./mine.sh" }], stop: [{ command: "./hooks/stop.sh" }] } });
  }, T);

  it.each([
    ["invalid JSON", "{ nope"],
    ["unknown version", JSON.stringify({ version: 2, hooks: {} })],
    ["hooks not an object", JSON.stringify({ version: 1, hooks: [] })],
    ["event not an array", JSON.stringify({ version: 1, hooks: { stop: { command: "x" } } })],
  ])("refuses to edit %s (file unchanged)", async (_n, content) => {
    const t = await setup();
    mkdirSync(join(t.fakeHome, ".cursor"), { recursive: true });
    writeFileSync(userHooks(t.fakeHome), content);
    const r = await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not modifying it/);
    expect(readFileSync(userHooks(t.fakeHome), "utf8")).toBe(content);
  }, T);

  it("--project: writes <dir>/.cursor/hooks.json, git-excludes it, refuses a second scope, uninstall cleans up", async () => {
    const t = await setup();
    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: t.project });
    const r = await cli(["install", "cursor", "--project", t.project], { ...t, cwd: t.work });
    expect(r.code).toBe(0);
    expect(r.stderr).toMatch(/TRUSTED workspaces/);
    const file = join(t.project, ".cursor", "hooks.json");
    expect(readJson(file).hooks.beforeShellExecution[0].command).toContain(MARKER);
    expect(readFileSync(join(t.project, ".git", "info", "exclude"), "utf8")).toContain("/.cursor/hooks.json");

    const user = await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work });
    expect(user.code).toBe(1);
    expect(user.stderr).toMatch(/ask twice/);

    expect((await cli(["uninstall", "cursor", "--project", t.project], { ...t, cwd: t.work })).code).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(readFileSync(join(t.project, ".git", "info", "exclude"), "utf8")).not.toContain("/.cursor/hooks.json");
  }, T);

  it("not logged in → refuses (the hook would block everything)", async () => {
    const t = await setup();
    writeFileSync(join(t.home, "config.json"), JSON.stringify({ version: 1, server: t.s.url, machine_id: "m" }));
    const r = await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work });
    expect(r.code).toBe(1);
    expect(existsSync(userHooks(t.fakeHome))).toBe(false);
  }, T);

  it("full `agentgate uninstall --yes` removes the recorded Cursor install (original bytes back)", async () => {
    const t = await setup();
    mkdirSync(join(t.fakeHome, ".cursor"), { recursive: true });
    const original = JSON.stringify({ version: 1, hooks: { stop: [{ command: "./s.sh" }] } });
    writeFileSync(userHooks(t.fakeHome), original);
    expect((await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work })).code).toBe(0);
    const dry = await cli(["uninstall", "--dry-run"], { ...t, cwd: t.work });
    expect(dry.stdout).toContain(`remove Cursor hooks from ${userHooks(t.fakeHome)}`);
    const r = await cli(["uninstall", "--yes"], { ...t, cwd: t.work });
    expect(r.code).toBe(0);
    expect(readFileSync(userHooks(t.fakeHome), "utf8")).toBe(original);
  }, T);
});

// ── hook ────────────────────────────────────────────────────────────────────

describe("agentgate hook cursor", () => {
  it("policy allow → {permission: allow}; action reported as agent cursor in a conversation-mapped session", async () => {
    const t = await setup();
    const d = decision(await hook(payload("beforeShellExecution", { command: "ls -la", cwd: t.work, sandbox: false }), { ...t, cwd: t.work }));
    expect(d).toEqual({ permission: "allow" });
    const sub = t.s.requests.find((q) => q.path === "/v1/actions")!.body as { action: { agent: { type: string }; action: { tool: string }; context: Record<string, string> } };
    expect(sub.action.agent).toEqual({ type: "cursor", version: "3.1.4" });
    expect(sub.action.action.tool).toBe("Shell");
    expect(sub.action.context).toMatchObject({ cursor_conversation_id: "conv-1", cursor_hook: "beforeShellExecution" });
    // Same conversation → same AgentGate session.
    decision(await hook(payload("beforeShellExecution", { command: "pwd", cwd: t.work }), { ...t, cwd: t.work }));
    expect(t.s.createdSessions).toHaveLength(1);
  }, T);

  it("policy deny → deny JSON with user + agent messages, never Cursor's own ask", async () => {
    const t = await setup();
    const r = await hook(payload("beforeShellExecution", { command: "rm -rf build", cwd: t.work }), { ...t, cwd: t.work });
    const d = decision(r);
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/AgentGate blocked this: denied by policy/);
    expect(d.agent_message).toMatch(/Do not retry it/);
    expect(r.stdout).not.toMatch(/"ask"/);
  }, T);

  it("ask → phone-signed approval → allow; decision verified against the pinned device key and its nonce consumed", async () => {
    const t = await setup({ onAsk: approveOnPhone }, { policy: null });
    const d = decision(await hook(payload("beforeShellExecution", { command: "git push origin main", cwd: t.work }), { ...t, cwd: t.work }));
    expect(d).toEqual({ permission: "allow" });
    expect(t.s.approvals.size).toBe(1);
    expect(readdirSync(join(t.home, "nonces"))).toHaveLength(1);
  }, T);

  it("ask → denied on the phone → deny", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const d = decision(await hook(payload("beforeShellExecution", { command: "touch x", cwd: t.work }), { ...t, cwd: t.work }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toBe("AgentGate: denied on your phone.");
    expect(existsSync(join(t.work, "x"))).toBe(false);
  }, T);

  it.each([
    ["forged signature (unknown key)", (c: AskContext) => signed(c, {}, generateDeviceKeyPair(rnd).privateKey), /bad_signature/],
    ["decision for another action hash", (c: AskContext) => signed(c, { action_hash: "0".repeat(64) }), /hash_mismatch|differs/],
    ["server-signed v1 token when phone signatures are required", (c: AskContext) => c.server.sign(c), /v1_not_accepted|phone-signed/],
  ])("approval that fails verification → deny (%s)", async (_n, make, why) => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "approved", make(c)) });
    const d = decision(await hook(payload("beforeShellExecution", { command: "touch x", cwd: t.work }), { ...t, cwd: t.work }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/could not be verified/);
    expect(d.user_message).toMatch(why);
  }, T);

  it("no decision before the approval wait runs out → deny 'approve on your phone, then retry'; approval cancelled", async () => {
    const t = await setup({ onAsk: () => {} });
    const r = await hook(payload("beforeShellExecution", { command: "touch x", cwd: t.work }), { ...t, cwd: t.work, env: { AGENTGATE_HOOK_TIMEOUT_S: "20" } });
    const d = decision(r);
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/Approve on your phone, then retry/);
    expect(d.agent_message).toMatch(/retry the exact same action once/);
    expect(t.s.cancels.length).toBeGreaterThanOrEqual(1);
  }, T);

  it("internal hook deadline (server hangs) → deny JSON before Cursor's timeout", async () => {
    const t = await setup({ hangActions: true });
    const started = Date.now();
    const d = decision(await hook(payload("beforeShellExecution", { command: "touch x", cwd: t.work }), { ...t, cwd: t.work, env: { AGENTGATE_HOOK_TIMEOUT_S: "18" } }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/hook deadline/);
    expect(Date.now() - started).toBeLessThan(15_000);
  }, T);

  it("server unreachable → deny (fail-closed), even for a command policy allows", async () => {
    const t = await setup({}, { serverUrl: "http://127.0.0.1:9" });
    const d = decision(await hook(payload("beforeShellExecution", { command: "ls", cwd: t.work }), { ...t, cwd: t.work }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/unavailable/);
  }, T);

  it.each([
    ["garbage stdin", "not json {"],
    ["missing command", JSON.stringify({ hook_event_name: "beforeShellExecution", cursor_version: "1", conversation_id: "c" })],
    ["no conversation id", JSON.stringify({ hook_event_name: "beforeShellExecution", cursor_version: "1", command: "touch x", cwd: "/" })],
  ])("malformed input (%s) → deny JSON", async (_n, input) => {
    const t = await setup();
    expect(decision(await hook(input, { ...t, cwd: t.work })).permission).toBe("deny");
  }, T);

  it("crash / broken runtime → the shim exits 2 (Cursor: deny), even if something printed allow", async () => {
    const t = await setup();
    const liar = join(t.work, "fake-node");
    writeFileSync(liar, '#!/bin/sh\necho \'{"permission":"allow"}\'\nexit 3\n');
    chmodSync(liar, 0o755);
    const r1 = await hook(payload("beforeShellExecution", { command: "ls", cwd: t.work }), { ...t, cwd: t.work, env: { AGENTGATE_NODE: liar } });
    expect(r1.code).toBe(2);
    expect(r1.stderr).toMatch(/hook exited abnormally \(code 3\)/);
    const r2 = await hook(payload("beforeShellExecution", { command: "ls", cwd: t.work }), { ...t, cwd: t.work, env: { AGENTGATE_NODE: "/nonexistent/node", PATH: "/usr/bin:/bin" } });
    expect(r2.code).toBe(2);
  }, T);

  it("approved shell command whose script changed while waiting → deny (exec context re-check)", async () => {
    const t = await setup({
      onAsk: (c) => {
        writeFileSync(join(t0.work, "build.sh"), "echo evil\n");
        approveOnPhone(c);
      },
    });
    const t0 = t;
    writeFileSync(join(t.work, "build.sh"), "echo build\n");
    const d = decision(await hook(payload("beforeShellExecution", { command: "sh build.sh", cwd: t.work }), { ...t, cwd: t.work }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/changed while waiting for approval/);
  }, T);

  it("self-management and hooks.json edits are denied without asking the phone", async () => {
    const t = await setup({ onAsk: approveOnPhone });
    for (const command of ["agentgate uninstall cursor --user", "echo {} > ~/.cursor/hooks.json"]) {
      const d = decision(await hook(payload("beforeShellExecution", { command, cwd: t.work }), { ...t, cwd: t.work }));
      expect(d.permission).toBe("deny");
    }
    const w = decision(await hook(payload("preToolUse", { tool_name: "Write", tool_input: { file_path: ".cursor/hooks.json", contents: "{}" }, cwd: t.work }), { ...t, cwd: t.work }));
    expect(w.permission).toBe("deny");
    expect(w.user_message).toMatch(/Cursor hook settings/);
    expect(t.s.approvals.size).toBe(0);
  }, T);

  it("preToolUse file edits: inside the project → allow; outside → ask → approved; Grep → allow without network", async () => {
    const t = await setup({ onAsk: approveOnPhone });
    expect(decision(await hook(payload("preToolUse", { tool_name: "Write", tool_input: { file_path: "src/a.ts", contents: "x" }, cwd: t.work }), { ...t, cwd: t.work }))).toEqual({ permission: "allow" });
    expect(t.s.approvals.size).toBe(0);
    expect(decision(await hook(payload("preToolUse", { tool_name: "Write", tool_input: { file_path: "/tmp/elsewhere.txt", contents: "x" }, cwd: t.work }), { ...t, cwd: t.work }))).toEqual({ permission: "allow" });
    expect(t.s.approvals.size).toBe(1);
    const before = t.s.requests.length;
    expect(decision(await hook(payload("preToolUse", { tool_name: "Grep", tool_input: { pattern: "x" }, cwd: t.work }), { ...t, cwd: t.work }))).toEqual({ permission: "allow" });
    expect(t.s.requests.length).toBe(before);
  }, T);

  it("beforeReadFile: .env → ask → approved; ordinary file → allow without network; deny has no agent_message", async () => {
    const t = await setup({ onAsk: approveOnPhone });
    expect(decision(await hook(payload("beforeReadFile", { file_path: join(t.work, ".env"), content: "S=1" }), { ...t, cwd: t.work }))).toEqual({ permission: "allow" });
    expect(t.s.approvals.size).toBe(1);
    const n = t.s.requests.length;
    expect(decision(await hook(payload("beforeReadFile", { file_path: join(t.work, "README.md"), content: "hi" }), { ...t, cwd: t.work }))).toEqual({ permission: "allow" });
    expect(t.s.requests.length).toBe(n);

    const t2 = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const d = decision(await hook(payload("beforeReadFile", { file_path: join(t2.work, ".env"), content: "S=1" }), { ...t2, cwd: t2.work }));
    expect(d).toEqual({ permission: "deny", user_message: "AgentGate: denied on your phone." });
  }, T);

  it("beforeMCPExecution: unwrapped server is gated here; a server behind `agentgate mcp wrap` is left to the gateway", async () => {
    const t = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const call = (fields: Record<string, unknown>) =>
      hook(payload("beforeMCPExecution", { tool_name: "delete_repo", tool_input: '{"repo":"api"}', mcp_server_name: "gh", ...fields }), { ...t, cwd: t.work });
    const d = decision(await call({ command: "npx -y server-github" }));
    expect(d.permission).toBe("deny");
    expect(t.s.approvals.size).toBe(1);

    mkdirSync(join(t.fakeHome, ".cursor"), { recursive: true });
    writeFileSync(
      join(t.fakeHome, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { gh: { command: CLI_SHIM, args: ["mcp", "wrap", "--name", "gh", "--", "npx", "-y", "server-github"], env: { AGENTGATE_MCP_WRAPPED: "1" } } } }),
    );
    const n = t.s.requests.length;
    expect(decision(await call({ command: `${CLI_SHIM} mcp wrap --name gh -- npx -y server-github` }))).toEqual({ permission: "allow" });
    expect(t.s.requests.length).toBe(n);
    // A launch command that is not our gateway (spoofed marker, HTTP transport) is still gated.
    expect(decision(await call({ command: "npx -y server-github" })).permission).toBe("deny");
    expect(decision(await call({ command: undefined, url: "https://x", mcp_server_url: "https://x" })).permission).toBe("deny");
  }, T);

  it("sessionEnd → {} and the mapped AgentGate session is ended", async () => {
    const t = await setup();
    decision(await hook(payload("beforeShellExecution", { command: "ls", cwd: t.work }), { ...t, cwd: t.work }));
    const sid = t.s.createdSessions[0]!;
    const r = await hook(payload("sessionEnd", { session_id: "conv-1", reason: "user_close" }), { ...t, cwd: t.work });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({});
    expect(t.s.endedSessions).toContain(sid);
  }, T);
});

describe("Cursor running AgentGate's Claude Code hook (Third-Party Imports)", () => {
  it("without a native Cursor hook: the Claude hook gates Cursor's preToolUse itself (flat permission JSON)", async () => {
    const t = await setup();
    const shell = payload("preToolUse", { tool_name: "Shell", tool_input: { command: "rm -rf build" }, cwd: t.work });
    const d = decision(await hook(shell, { ...t, cwd: t.work, claude: true }));
    expect(d.permission).toBe("deny");
    expect(d.user_message).toMatch(/denied by policy/);
  }, T);

  it("with the native Cursor hook installed: the Claude hook defers (allow, no network) — no double approvals", async () => {
    const t = await setup();
    expect((await cli(["install", "cursor", "--user", "--yes"], { ...t, cwd: t.work })).code).toBe(0);
    const n = t.s.requests.length;
    const shell = payload("PreToolUse", { tool_name: "Shell", tool_input: { command: "rm -rf build" }, cwd: t.work });
    expect(decision(await hook(shell, { ...t, cwd: t.work, claude: true }))).toEqual({ permission: "allow" });
    expect(t.s.requests.length).toBe(n);
  }, T);

  it("a spoofed marker (not a real AgentGate hook) does not make the Claude hook defer", async () => {
    const t = await setup();
    mkdirSync(join(t.work, ".cursor"), { recursive: true });
    const fake = { command: `true # agentgate-hook.sh ${MARKER}`, failClosed: true };
    writeFileSync(join(t.work, ".cursor", "hooks.json"), JSON.stringify({ version: 1, hooks: { beforeShellExecution: [fake], beforeMCPExecution: [fake], beforeReadFile: [fake], preToolUse: [fake] } }));
    const shell = payload("preToolUse", { tool_name: "Shell", tool_input: { command: "rm -rf build" }, cwd: t.work });
    expect(decision(await hook(shell, { ...t, cwd: t.work, claude: true })).permission).toBe("deny");
  }, T);

  it("Claude Code's own payloads are unaffected (no cursor_version)", async () => {
    const t = await setup();
    const r = await hook(JSON.stringify({ session_id: "s", cwd: t.work, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "t" }), { ...t, cwd: t.work, claude: true });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("allow");
  }, T);
});
