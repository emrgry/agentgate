import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FakeServer, type FakeServerOptions } from "./fake-server.ts";
import { makeEnv, runProcess } from "./helpers.ts";

/**
 * Control Center Phase 2: `agentgate hook codex|<generic>` via the shim's
 * `--agentgate-provider=<id>` flag. Same fail-closed contract (0 = allow silently,
 * 2 = block), no rewrite path (token consumed in the hook), gating receipts.
 */

const HOOK_SHIM = join(dirname(fileURLToPath(import.meta.url)), "..", "bin", "agentgate-hook.sh");
const T = 30_000;

let server: FakeServer | null = null;
afterEach(async () => {
  await server?.stop();
  server = null;
});

async function setup(opts: FakeServerOptions = {}, policy?: string | null) {
  server = await new FakeServer(opts).start();
  const env = makeEnv({ server: server.url, token: server.token, publicKeyPem: server.keys.publicKeyPem, policy });
  return { s: server, ...env, receipts: join(env.work, "receipts.jsonl") };
}

const codexInput = (tool_name: string, tool_input: Record<string, unknown>, cwd: string) =>
  JSON.stringify({ session_id: "codex-thread-1", cwd, hook_event_name: "PreToolUse", model: "gpt-x", turn_id: "t1", tool_name, tool_input, tool_use_id: "call_1", permission_mode: "never" });

function hook(provider: string, input: string, o: { home: string; cwd: string; env?: Record<string, string> }) {
  return runProcess(HOOK_SHIM, ["--agentgate-installed", `--agentgate-provider=${provider}`], {
    home: o.home,
    cwd: o.cwd,
    input,
    env: { AGENTGATE_NODE: process.execPath, ...o.env },
  });
}
const receiptsOf = (f: string) => (existsSync(f) ? readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

describe("hook codex", () => {
  it("policy allow → exit 0, no stdout; invoked + allow receipts; action reported as codex with the control session", async () => {
    const { s, home, work, receipts } = await setup();
    const r = await hook("codex", codexInput("Bash", { command: "ls -la" }, work), { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: receipts, AGENTGATE_CONTROL_SESSION: "ags_x" } });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(r.stdout).toBe("");
    expect(receiptsOf(receipts).map((x) => [x.phase, x.kind, x.text, x.decision])).toEqual([
      ["invoked", "shell", "ls -la", undefined],
      ["decision", "shell", "ls -la", "allow"],
    ]);
    const sub = s.requests.find((q) => q.path === "/v1/actions")!.body as { action: { agent: { type: string }; context: Record<string, string> } };
    expect(sub.action.agent.type).toBe("codex");
    expect(sub.action.context).toMatchObject({ codex_session_id: "codex-thread-1", agentgate_control_session: "ags_x" });
  }, T);

  it("ask → approved on the phone → exit 0; the one-time token is verified AND consumed in the hook", async () => {
    const { s, home, work, receipts } = await setup({}, null);
    const r = await hook("codex", codexInput("Bash", { command: "git push origin main" }, work), { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: receipts } });
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(s.approvals.size).toBe(1);
    expect(readdirSync(join(home, "nonces"))).toHaveLength(1);
    expect(receiptsOf(receipts).at(-1).decision).toBe("allow");
  }, T);

  it("denied → exit 2 + reason on stderr + deny receipt", async () => {
    const { home, work, receipts } = await setup({ onAsk: (c) => c.server.resolve(c, "denied", null) });
    const r = await hook("codex", codexInput("Bash", { command: "touch x" }, work), { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: receipts } });
    expect(r.code).toBe(2);
    expect(r.stdout).toBe("");
    expect(r.stderr).toMatch(/AgentGate blocked this action: denied on device/);
    expect(receiptsOf(receipts).map((x) => [x.phase, x.kind, x.text, x.decision])).toEqual([
      ["invoked", "shell", "touch x", undefined],
      ["decision", "shell", "touch x", "deny"],
    ]);
  }, T);

  it("apply_patch receipts carry the patch paths", async () => {
    const { home, work, receipts } = await setup();
    await hook("codex", codexInput("apply_patch", { input: "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch" }, work), { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: receipts } });
    expect(receiptsOf(receipts)[0]).toMatchObject({ phase: "invoked", kind: "file", paths: ["a.txt"] });
  }, T);

  it("unwritable receipts file → blocked before anything is asked", async () => {
    const { s, home, work } = await setup();
    const r = await hook("codex", codexInput("Bash", { command: "ls" }, work), { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: "/nonexistent-dir/x/receipts.jsonl" } });
    expect(r.code).toBe(2);
    expect(s.count("POST", "/v1/actions")).toBe(0);
  }, T);

  it.each([
    ["garbage", "not json {"],
    ["missing tool_name", JSON.stringify({ hook_event_name: "PreToolUse", cwd: "/", tool_input: {} })],
    ["missing cwd", JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {} })],
  ])("%s → exit 2", async (_n, input) => {
    const { home, work } = await setup();
    const r = await hook("codex", input, { home, cwd: work });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/AgentGate blocked this action/);
  }, T);

  it("non-PreToolUse events are ignored (exit 0, no network)", async () => {
    const { s, home, work } = await setup();
    const r = await hook("codex", JSON.stringify({ hook_event_name: "PostToolUse", cwd: work, tool_name: "Bash", tool_input: {} }), { home, cwd: work });
    expect(r.code).toBe(0);
    expect(s.requests.length).toBe(0);
  }, T);

  it("invalid provider id in the shim flag → exit 2", async () => {
    const { home, work } = await setup();
    const r = await runProcess(HOOK_SHIM, ["--agentgate-provider=../evil"], { home, cwd: work, input: "{}", env: { AGENTGATE_NODE: process.execPath } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/invalid provider id/);
  }, T);
});

describe("hook <generic provider> (hermes)", () => {
  it("Claude-style input → shell action for agent type hermes; policy deny → exit 2", async () => {
    const { s, home, work, receipts } = await setup();
    const input = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "20260926_x", cwd: work, tool_name: "terminal", tool_input: { command: "rm -rf /tmp/whatever" } });
    const r = await hook("hermes", input, { home, cwd: work, env: { AGENTGATE_GATE_RECEIPTS: receipts } });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/denied by policy/);
    const sub = s.requests.find((q) => q.path === "/v1/actions")?.body as { action: { agent: { type: string }; action: { category: string } } } | undefined;
    if (sub) expect(sub.action.agent.type).toBe("hermes");
    expect(receiptsOf(receipts).map((x) => x.phase)).toEqual(["invoked", "decision"]);
  }, T);
});
