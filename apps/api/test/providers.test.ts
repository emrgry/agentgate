import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { codexProvider } from "@agentgate/adapter-codex";
import { BUILTIN_PROFILES_DIR, genericProvider, loadProfiles, parseProfile, prepareGenericHome } from "@agentgate/adapter-generic";
import { ListProvidersResponse } from "@agentgate/protocol";
import { auditLogs } from "../src/db/schema.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { managedHookCommand, prepareCodexHome } from "../src/control/provider-homes.ts";
import { controlHarness, FAKE_CLAUDE, FAKE_CODEX, FAKE_HERMES } from "./control-harness.ts";

/** Control Center Phase 2: Codex + generic (providers.yaml / Hermes) providers, tripwire, ungated opt-in. */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());

const homes = () => realpathSync(mkdtempSync(join(tmpdir(), "ag-homes-")));

function hermesProfile() {
  const p = loadProfiles([BUILTIN_PROFILES_DIR]).profiles.find((x) => x.id === "hermes")!;
  // Never copy the real ~/.hermes in tests.
  return { ...p, approval: { ...p.approval, hook: { ...p.approval.hook!, copy_from: join(homes(), "none") } } };
}

function control(extra: Partial<SupervisorOptions> = {}, env: Record<string, string> = {}): SupervisorOptions {
  const base = homes();
  const log = join(base, "agent.log");
  const hermes = hermesProfile();
  const aider = parseProfile(
    `id: aider\ndisplay_name: Aider\nbinary: ${FAKE_HERMES}\ncommand: {args: [chat, -z, --query-file, "-"], prompt: {via: stdin}}\noutput: {format: text}\napproval: {mode: none}\n`,
  );
  return {
    providers: {
      "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }),
      codex: codexProvider({ binary: FAKE_CODEX, minVersion: "0.40.0", extraArgs: ["--yolo", "-m", "gpt-x"], codexHome: (sid) => join(base, "codex", sid) }),
      hermes: genericProvider(hermes, { binary: FAKE_HERMES, prepareHome: (p, sid) => prepareGenericHome(p, { baseDir: base, sessionId: sid, hookCommand: "/bin/false" }) }),
      aider: genericProvider(aider),
    },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, FAKE_AGENT_LOG: log, ...env }),
    stopGraceMs: 300,
    tripwireGraceMs: 300,
    ...extra,
  };
}
const logOf = (ctl: SupervisorOptions) => String(ctl.turnEnv().FAKE_AGENT_LOG);
const logLines = (ctl: SupervisorOptions) => readFileSync(logOf(ctl), "utf8").trim().split("\n").map((l) => JSON.parse(l));

describe("codex provider", () => {
  it("runs gated turns (hook receipts present), resumes with `exec resume <thread>` and drops forbidden flags", async () => {
    const ctl = control();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "tool:ls;patch:a.txt;say:first done", "codex");
    let s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s).toMatchObject({ provider: "codex", gated: true, usage: { turns: 1, input_tokens: 10, output_tokens: 5, cost_usd: null } });
    expect(s.summary?.last_message).toBe("first done");
    expect((await c.cmd(phone, id, { command: "instruct", text: "say:second" })).json.status).toBe("applied");
    s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 2);
    const [first, second] = logLines(ctl);
    expect(first.args.slice(0, 2)).toEqual(["exec", "--json"]);
    expect(first.args).toContain("--sandbox");
    expect(first.args[first.args.indexOf("--sandbox") + 1]).toBe("workspace-write");
    expect(first.args).toContain("--dangerously-bypass-hook-trust");
    expect(first.args).not.toContain("--yolo");
    expect(first.args).toEqual(expect.arrayContaining(["-m", "gpt-x"]));
    expect(first.args.at(-1)).toBe("-");
    expect(first.env.AGENTGATE_CONTROL_SESSION).toBe(id);
    expect(first.env.CODEX_HOME).toContain(id);
    expect(second.args.slice(0, 3)).toEqual(["exec", "resume", "--json"]);
    expect(second.args.slice(-2)).toEqual([s.provider_session_id, "-"]);
    expect(second.args).not.toContain("--ephemeral");
    const evs = await c.events(agent, id);
    expect(evs.filter((e) => e.type === "tool.call").map((e) => e.payload.tool)).toEqual(["Bash", "apply_patch"]);
    expect(evs.some((e) => e.type.startsWith("provider."))).toBe(false);
  }, T);

  it("tripwire: a tool that runs without an AgentGate receipt kills the turn and fails the task", async () => {
    const { agent, dir } = await c.server(control());
    const id = await c.start(agent, dir, "nohook:rm -rf build;sleep:3000;say:never", "codex");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "failed");
    expect(s.summary?.error).toBe("gating inactive: tool ran without AgentGate check");
    expect(s.summary?.last_message).toBeNull();
    const t = (await c.tasks(agent, id))[0]!;
    expect(t.status).toBe("failed");
    const evs = await c.events(agent, id);
    expect(evs.find((e) => e.type === "session.failed")!.payload).toMatchObject({ gating: "inactive" });
    const audit = await c.h.database.db.select().from(auditLogs).where(eq(auditLogs.event, "execution.blocked"));
    expect(audit.map((a) => (a.payload_json as { reason: string }).reason)).toContain("gating inactive: tool ran without AgentGate check");
    expect(c.h.push.sent.some((m) => m.data.session_id === id && /failed a task/.test(m.body ?? ""))).toBe(true);
  }, T);

  it("tripwire: a tool that completed although the hook denied it = bypass → killed; a declined command is fine", async () => {
    const { agent, dir } = await c.server(control());
    const ok = await c.start(agent, dir, "declined:curl evil;say:fine", "codex");
    expect((await c.until(() => c.session(agent, ok), (x) => ["waiting_input", "failed"].includes(x.status))).status).toBe("waiting_input");
    const bad = await c.start(agent, dir, "denied:curl evil;sleep:3000", "codex");
    const s = await c.until(() => c.session(agent, bad), (x) => x.status === "failed");
    expect(s.summary?.error).toBe("gating bypassed: a tool ran although AgentGate blocked it");
  }, T);

  it("tripwire on tool start: no receipt within the grace period → killed while the tool still runs", async () => {
    const { agent, dir } = await c.server(control());
    // item.started without a receipt, and the command "runs" for 3 s.
    const id = await c.start(agent, dir, "nohook:sleep 3;say:x", "codex");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "failed", 10_000);
    expect(s.summary?.error).toMatch(/gating inactive/);
  }, T);

  it("fails closed on an old or unknown codex version", async () => {
    for (const [v, re] of [
      ["0.39.9", /older than the required 0\.40\.0/],
      ["none", /version unknown/],
    ] as const) {
      const { agent, dir } = await c.server(control({}, { FAKE_CODEX_VERSION: v }));
      const id = await c.start(agent, dir, "say:hi", "codex");
      const s = await c.until(() => c.session(agent, id), (x) => x.status === "failed");
      expect(s.summary?.error).toMatch(re);
      await c.close();
    }
  }, T);

  it("prepareCodexHome copies auth/config and writes hooks.json with the provider hook (receipts + control session pinned)", () => {
    const owner = homes();
    writeFileSync(join(owner, "auth.json"), '{"k":1}');
    writeFileSync(join(owner, "config.toml"), 'model = "x"\n');
    const settings = join(owner, "managed-hooks.json");
    writeFileSync(settings, JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "AGENTGATE_HOME='/h' '/x/agentgate-hook.sh' --agentgate-installed" }] }] } }));
    const dir = prepareCodexHome({ baseDir: homes(), sessionId: "ags_1", ownerCodexHome: owner, hookCommand: managedHookCommand(settings) });
    expect(readFileSync(join(dir, "auth.json"), "utf8")).toBe('{"k":1}');
    const hooks = JSON.parse(readFileSync(join(dir, "hooks.json"), "utf8"));
    const cmd = hooks.hooks.PreToolUse[0].hooks[0].command as string;
    expect(cmd).toContain(`AGENTGATE_GATE_RECEIPTS='${dir}/agentgate-receipts.jsonl'`);
    expect(cmd).toContain("AGENTGATE_CONTROL_SESSION='ags_1'");
    expect(cmd.endsWith("--agentgate-installed --agentgate-provider=codex")).toBe(true);
  });
});

describe("generic providers (providers.yaml)", () => {
  it("hermes stream-json: deltas merged, tools gated by receipts, resume with -r <id>", async () => {
    const ctl = control();
    const { agent, phone, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "tool:ls;say:hello there", "hermes");
    let s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s).toMatchObject({ provider: "hermes", gated: true, provider_session_id: "20260926_120000_abc" });
    expect(s.summary?.last_message).toBe("hello there");
    await c.cmd(phone, id, { command: "instruct", text: "say:again" });
    s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 2);
    const lines = logLines(ctl);
    expect(lines[1].args).toEqual(expect.arrayContaining(["-r", "20260926_120000_abc"]));
    expect(lines[0].home).toContain(id);
  }, T);

  it("hermes tripwire: a tool without a hook receipt kills the turn", async () => {
    const { agent, dir } = await c.server(control());
    const id = await c.start(agent, dir, "nohook:rm x;say:done", "hermes");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "failed");
    expect(s.summary?.error).toMatch(/gating inactive/);
  }, T);

  it("hermes without --format stream-json falls back to text mode (final text, no resume)", async () => {
    const ctl = control({}, { FAKE_HERMES_TEXT: "1" });
    const { agent, dir } = await c.server(ctl);
    const id = await c.start(agent, dir, "say:plain answer", "hermes");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s.summary?.last_message).toBe("plain answer");
    expect(s.provider_session_id).toBeNull();
    expect(logLines(ctl)[0].args).toEqual(["chat", "--oneshot", "-z", "--query-file", "-"]);
  }, T);

  it("ungated providers: listed as gated:false; start refused until `allow-ungated` for that workspace", async () => {
    const { agent, phone, dir } = await c.server(control());
    const list = ListProvidersResponse.parse((await c.inject("GET", "/v1/providers", undefined, { token: phone.token })).json).items;
    expect(Object.fromEntries(list.map((p) => [p.id, p.gated]))).toEqual({ "claude-code": true, codex: true, hermes: true, aider: false });
    const refused = await c.inject("POST", "/v1/agent-sessions", { cwd: dir, prompt: "say:x", provider: "aider" }, { token: agent });
    expect(refused.status).toBe(403);
    expect(refused.json.error.code ?? refused.json.code).toBe("ungated_provider_not_allowed");
    const w = (await c.inject("POST", "/v1/workspaces", { path: dir }, { token: agent })).json;
    // The phone can't opt in (agent audience + loopback only).
    expect((await c.inject("POST", `/v1/workspaces/${w.id}/allow-ungated`, { provider: "aider" }, { token: phone.token })).status).toBe(403);
    const r = await c.inject("POST", `/v1/workspaces/${w.id}/allow-ungated`, { provider: "aider" }, { token: agent });
    expect(r.json.ungated_providers).toEqual(["aider"]);
    const id = await c.start(agent, dir, "say:ungated hello", "aider");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s.gated).toBe(false);
    expect(s.summary?.last_message).toBe("ungated hello");
    // The opt-in is per workspace: another dir is still refused.
    const other = realpathSync(mkdtempSync(join(tmpdir(), "ag-other-")));
    expect((await c.inject("POST", "/v1/agent-sessions", { cwd: other, prompt: "x", provider: "aider" }, { token: agent })).status).toBe(403);
    // Revoke.
    await c.inject("POST", `/v1/workspaces/${w.id}/allow-ungated`, { provider: "aider", allow: false }, { token: agent });
    expect((await c.inject("POST", "/v1/agent-sessions", { cwd: dir, prompt: "x", provider: "aider" }, { token: agent })).status).toBe(403);
  }, T);
});
