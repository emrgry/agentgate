import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { computeActionHash, generateSigningKeyPair } from "@agentgate/core";
import { AgentSession, ServerEvent, type CommandBody } from "@agentgate/protocol";
import { commandBodyHash, generateDeviceKeyPair, signCommand, signDecision, type DeviceKeyPair } from "@agentgate/signing";
import { buildApp } from "../src/app.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { openDatabase } from "../src/db/client.ts";
import { createSigner } from "../src/keys.ts";
import { createHarness, draft, RecordingPush, TestClock, type Harness } from "./helpers.ts";

/** Control Center Phase 1: supervisor (real processes, fake agent binary), signed commands, observed hooks. */

const FAKE = join(dirname(fileURLToPath(import.meta.url)), "fake-agent.mjs");
const T = 30_000;
const rnd = (n: number) => new Uint8Array(randomBytes(n));

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

type R = { status: number; json: any };
async function inject(method: "GET" | "POST" | "DELETE", url: string, body?: unknown, o: { token?: string; ip?: string } = {}): Promise<R> {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: o.ip ?? "127.0.0.1",
    headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

function control(log: string, extra: Partial<SupervisorOptions> = {}): SupervisorOptions {
  return {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE }) },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, FAKE_AGENT_LOG: log }),
    stopGraceMs: 400,
    ...extra,
  };
}

async function server(o: { pushInterval?: number } = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-cc-")));
  const log = join(dir, "agent.log");
  h = await createHarness({ mode: "local", openDeviceLogin: false, control: control(log), sessionPushIntervalMs: o.pushInterval ?? 30_000 });
  await h.app.ready();
  const agent = (await inject("POST", "/v1/auth/login", { client: "agent" })).json.access_token as string;
  const phone = await pair(agent);
  currentPhoneToken = phone.token;
  return { agent, phone, dir, log };
}

async function pair(agent: string, name = "iPhone") {
  const kp = generateDeviceKeyPair(rnd);
  const code = (await inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
  const r = await inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_name: name, device_public_key: kp.publicKey }, { ip: "192.168.1.50" });
  if (r.status === 202) throw new Error("expected bootstrap");
  await inject("POST", "/v1/devices", { name, platform: "ios", push_token: `ExponentPushToken[${name}]` }, { token: r.json.access_token });
  return { kp, token: r.json.access_token as string, id: r.json.device_id as string };
}

function sign(kp: DeviceKeyPair, deviceId: string, sessionId: string, body: CommandBody, over: Record<string, unknown> = {}) {
  const now = h!.clock.now().getTime();
  return signCommand(
    {
      v: 2,
      kind: "command",
      command: body.command,
      session_id: sessionId,
      payload_hash: commandBodyHash(body),
      device_id: deviceId,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + 60_000).toISOString(),
      nonce: Buffer.from(rnd(18)).toString("base64url"),
      ...over,
    } as never,
    kp.privateKey,
  );
}

const phoneCmd = (p: { kp: DeviceKeyPair; token: string; id: string }, sessionId: string, body: CommandBody, over: Record<string, unknown> = {}) =>
  inject("POST", `/v1/agent-sessions/${sessionId}/commands`, { device_id: p.id, body, signed_command: sign(p.kp, p.id, sessionId, body, over) }, { token: p.token });

async function startLocal(agent: string, cwd: string, prompt: string) {
  const r = await inject("POST", "/v1/agent-sessions", { cwd, prompt }, { token: agent });
  expect(r.status).toBe(201);
  return r.json.session.id as string;
}

async function session(agent: string, id: string) {
  return AgentSession.parse((await inject("GET", `/v1/agent-sessions/${id}`, undefined, { token: agent })).json);
}

async function until(agent: string, id: string, pred: (s: AgentSession) => boolean, ms = 30_000) {
  const end = Date.now() + ms;
  for (;;) {
    await h!.supervisor!.settle(id);
    const s = await session(agent, id);
    if (pred(s)) return s;
    if (Date.now() > end) throw new Error(`timeout; status=${s.status}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function events(agent: string, id: string) {
  return (await inject("GET", `/v1/agent-sessions/${id}/events?limit=500`, undefined, { token: agent })).json.items as Array<{ seq: number; type: string; payload: any }>;
}

/** The already-paired phone of the current harness (device token). */
async function server2Phone() {
  const code = (await inject("POST", "/v1/pairing", {}, { token: (await inject("POST", "/v1/auth/login", { client: "agent" })).json.access_token })).json.code;
  void code;
  return { token: currentPhoneToken! };
}
let currentPhoneToken: string | null = null;

async function untilCond(pred: () => Promise<boolean>, ms: number) {
  const end = Date.now() + ms;
  for (;;) {
    await h!.supervisor!.settle();
    if (await pred()) return;
    if (Date.now() > end) throw new Error("condition not reached");
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Polls `count` until it hasn't changed for `quietMs`; returns the stable value. */
async function stableCount(count: () => Promise<number>, quietMs: number, ms: number): Promise<number> {
  const end = Date.now() + ms;
  let last = -1;
  let since = Date.now();
  for (;;) {
    await h!.supervisor!.settle();
    const n = await count();
    if (n !== last) {
      last = n;
      since = Date.now();
    } else if (Date.now() - since >= quietMs) return n;
    if (Date.now() > end) throw new Error("count never stabilised");
    await new Promise((r) => setTimeout(r, 50));
  }
}

const agentRuns = (log: string) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);

describe("supervisor: turns and status machine", () => {
  it("turn without a question → waiting_input (idle), usage, summary, 'finished a task' push", async () => {
    const { agent, dir } = await server();
    const id = await startLocal(agent, dir, "tool:ls;say:All done.");
    const s = await until(agent, id, (x) => x.status === "waiting_input");
    expect(s).toMatchObject({ mode: "managed", pending_interaction_id: null, usage: { turns: 1, cost_usd: 0.01, input_tokens: 10, output_tokens: 5 } });
    expect(s.provider_session_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(s.summary).toMatchObject({ last_message: "All done.", error: null });
    expect(s.can).toMatchObject({ instruct: true, pause: false, stop: true, kill: false });
    const ev = await events(agent, id);
    expect(ev.map((e) => e.type)).toEqual([
      "session.started",
      "message.user",
      "status.changed",
      "tool.call",
      "tool.result",
      "message.assistant",
      "turn.completed",
      "status.changed",
    ]);
    expect(ev.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    // latest-first paging backwards: items stay ascending
    const back = (await inject("GET", `/v1/agent-sessions/${id}/events?before_seq=7&limit=3`, undefined, { token: agent })).json;
    expect(back.items.map((e: any) => e.seq)).toEqual([4, 5, 6]);
    expect(back.next_after_seq).toBe(6);
    const older = (await inject("GET", `/v1/agent-sessions/${id}/events?before_seq=4&limit=3`, undefined, { token: agent })).json;
    expect(older.items.map((e: any) => e.seq)).toEqual([1, 2, 3]);
    // "latest" sentinel from the phone (Number.MAX_SAFE_INTEGER) must not overflow the int4 column
    const latest = await inject("GET", `/v1/agent-sessions/${id}/events?before_seq=${Number.MAX_SAFE_INTEGER}&limit=3`, undefined, { token: agent });
    expect([latest.status, latest.json.items.map((e: any) => e.seq)]).toEqual([200, [6, 7, 8]]);
    const fwd = (await inject("GET", `/v1/agent-sessions/${id}/events?after_seq=6&limit=5`, undefined, { token: agent })).json;
    expect([fwd.items.map((e: any) => e.seq), fwd.next_after_seq]).toEqual([[7, 8], null]);
    // own sessions only; deep-link GET works with a device token
    expect((await inject("GET", `/v1/agent-sessions/${id}`, undefined, { token: (await server2Phone()).token })).status).toBe(200);
    expect(h!.push.sent.at(-1)).toMatchObject({ body: "Claude Code finished a task", data: { url: `agentgate://sessions/${id}`, session_id: id, server_fingerprint: expect.any(String) } });
  }, T);

  it("question → input_required interaction + push; signed answer resumes with --resume <same session>", async () => {
    const { agent, phone, dir, log } = await server();
    const id = await startLocal(agent, dir, "ask:Which file should I delete?");
    const s = await until(agent, id, (x) => x.status === "waiting_input" && x.pending_interaction_id !== null);
    expect((await events(agent, id)).find((e) => e.type === "input.required")!.payload).toMatchObject({ interaction_id: s.pending_interaction_id, prompt: "Which file should I delete?" });
    expect(h!.push.sent.at(-1)!.body).toBe("Claude Code is waiting for you");
    const r = await phoneCmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "say:Deleted one.txt" });
    expect(r.status).toBe(200);
    expect(r.json.status).toBe("applied");
    const done = await until(agent, id, (x) => x.status === "waiting_input" && x.usage.turns === 2);
    expect(done.pending_interaction_id).toBeNull();
    const runs = agentRuns(log);
    expect(runs[1].args).toEqual(expect.arrayContaining(["--resume", s.provider_session_id]));
    expect(runs[0].args).not.toContain("--resume");
    expect(runs.every((x: any) => !x.args.join(" ").includes("bypassPermissions"))).toBe(true);
  }, T);

  it("instruct while running is queued, then runs as the next --resume turn", async () => {
    const { agent, phone, dir, log } = await server();
    const id = await startLocal(agent, dir, "ticks:5;say:first done");
    await until(agent, id, (x) => x.status === "running");
    const q = await phoneCmd(phone, id, { command: "instruct", text: "say:second done" });
    expect(q.json.status).toBe("queued");
    const s = await until(agent, id, (x) => x.status === "waiting_input" && x.usage.turns === 2);
    expect(s.summary?.last_message).toBe("second done");
    expect(agentRuns(log)).toHaveLength(2);
    const ev = await events(agent, id);
    expect(ev.filter((e) => e.type === "message.user").map((e) => e.payload.text)).toEqual(["ticks:5;say:first done", "say:second done"]);
  }, T);

  it("pause (SIGSTOP) freezes output; resume (SIGCONT) continues; kill → killed", async () => {
    const { agent, phone, dir } = await server();
    const id = await startLocal(agent, dir, "ticks:900"); // ~90 s of output unless paused/killed
    const ticks = async () => (await events(agent, id)).filter((e) => e.type === "message.assistant").length;
    await untilCond(async () => (await ticks()) >= 2, 60_000);
    expect((await phoneCmd(phone, id, { command: "pause" })).json.session.status).toBe("paused");
    // Deterministic: wait until output that was already in the pipe has been applied,
    // i.e. the count is stable across a quiet window — then it must stay frozen.
    const n1 = await stableCount(ticks, 500, 30_000);
    await new Promise((r) => setTimeout(r, 1_000));
    await h!.supervisor!.settle(id);
    expect(await ticks()).toBe(n1);
    expect((await phoneCmd(phone, id, { command: "resume" })).json.session.status).toBe("running");
    await untilCond(async () => (await ticks()) > n1, 60_000);
    expect((await phoneCmd(phone, id, { command: "kill" })).status).toBe(200);
    const s = await until(agent, id, (x) => x.status === "killed", 60_000);
    expect(s.ended_at).not.toBeNull();
  }, 180_000);

  it("stop → stopping → stopped (SIGINT); stop while idle → completed + session.completed", async () => {
    const { agent, phone, dir } = await server();
    const id = await startLocal(agent, dir, "hang");
    await until(agent, id, (x) => x.status === "running");
    expect((await phoneCmd(phone, id, { command: "stop" })).json.session.status).toBe("stopping");
    await until(agent, id, (x) => x.status === "stopped");
    const id2 = await startLocal(agent, dir, "say:ok");
    await until(agent, id2, (x) => x.status === "waiting_input");
    expect((await phoneCmd(phone, id2, { command: "stop" })).json.session.status).toBe("completed");
    expect((await events(agent, id2)).at(-1)!.type).toBe("session.completed");
  }, T);

  it("kill reaches the whole process group (grandchild dies too)", async () => {
    const { agent, phone, dir } = await server();
    const pidFile = join(dir, "child.pid");
    h!.supervisor!["o"].turnEnv = () => ({ ...process.env, FAKE_CHILD_PID: pidFile });
    const id = await startLocal(agent, dir, "child");
    const end = Date.now() + 5000;
    while (!existsSync(pidFile) && Date.now() < end) await new Promise((r) => setTimeout(r, 50));
    const child = Number(readFileSync(pidFile, "utf8"));
    expect(() => process.kill(child, 0)).not.toThrow();
    await phoneCmd(phone, id, { command: "kill" });
    await until(agent, id, (x) => x.status === "killed");
    await new Promise((r) => setTimeout(r, 200));
    expect(() => process.kill(child, 0)).toThrow();
  }, T);

  it("error result → failed + session.failed; crash without result → failed + session.terminated; pushes", async () => {
    const { agent, dir } = await server({ pushInterval: 0 });
    const a = await startLocal(agent, dir, "fail");
    const sa = await until(agent, a, (x) => x.status === "failed");
    expect(sa.summary?.error).toMatch(/simulated failure/);
    expect((await events(agent, a)).some((e) => e.type === "session.failed")).toBe(true);
    const b = await startLocal(agent, dir, "say:working;crash");
    await until(agent, b, (x) => x.status === "failed");
    const term = (await events(agent, b)).find((e) => e.type === "session.terminated")!;
    expect(term.payload.reason).toMatch(/exited with code 3/);
    expect(h!.push.sent.map((m) => m.body)).toEqual(expect.arrayContaining(["Claude Code failed a task", "Claude Code stopped unexpectedly"]));
    // a failed session can be continued with a new instruction (--resume)
    expect((await session(agent, b)).can.instruct).toBe(true);
  }, T);

  it("server restart: running sessions become lost; instruct resumes with --resume", async () => {
    const database = await openDatabase({ kind: "memory" });
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-cc-")));
    const log = join(dir, "agent.log");
    const signer = createSigner(generateSigningKeyPair().privateKeyPem);
    const mk = () =>
      buildApp({ db: database.db, signer, authSecret: "test-secret-test-secret-test-secret", push: () => new RecordingPush(), clock: new TestClock(), logLevel: false, mode: "local", control: control(log), rateLimit: false });
    const a = await mk();
    const tok = JSON.parse((await a.app.inject({ method: "POST", url: "/v1/auth/login", remoteAddress: "127.0.0.1", headers: { "content-type": "application/json" }, payload: '{"client":"agent"}' })).body).access_token;
    const call = async (app: typeof a, method: "GET" | "POST", url: string, body?: unknown) =>
      JSON.parse((await app.app.inject({ method, url, remoteAddress: "127.0.0.1", headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" }, ...(body ? { payload: JSON.stringify(body) } : {}) })).body);
    const id = (await call(a, "POST", "/v1/agent-sessions", { cwd: dir, prompt: "say:hi;hang" })).session.id;
    for (let i = 0; i < 100 && !(await call(a, "GET", `/v1/agent-sessions/${id}`)).provider_session_id; i++) await new Promise((r) => setTimeout(r, 50));
    await a.supervisor!.settle(id);
    const psid = (await call(a, "GET", `/v1/agent-sessions/${id}`)).provider_session_id;
    await a.app.close(); // server goes away while the turn runs
    const b = await mk();
    const lost = await call(b, "GET", `/v1/agent-sessions/${id}`);
    expect(lost.status).toBe("lost");
    expect(lost.can.instruct).toBe(true);
    const r = await call(b, "POST", `/v1/agent-sessions/${id}/commands`, { body: { command: "instruct", text: "say:back" } });
    expect(r.status).toBe("applied");
    for (let i = 0; i < 100 && (await call(b, "GET", `/v1/agent-sessions/${id}`)).status !== "waiting_input"; i++) await new Promise((r) => setTimeout(r, 50));
    expect(agentRuns(log).at(-1).args).toEqual(expect.arrayContaining(["--resume", psid]));
    await b.app.close();
    await database.close();
  }, T);

  it("a managed turn's tool approval → awaiting_approval, resolved → running", async () => {
    const { agent, phone, dir } = await server();
    const id = await startLocal(agent, dir, "say:working;hang");
    const s = await until(agent, id, (x) => x.status === "running" && x.provider_session_id !== null);
    const ag = await inject("POST", "/v1/agents", { name: "m", type: "claude-code", machine_id: "m" }, { token: agent });
    const ses = await inject("POST", "/v1/sessions", { agent_id: ag.json.id }, { token: agent });
    const d = { ...draft(ses.json.id), context: { claude_session_id: s.provider_session_id! } };
    const act = await inject("POST", "/v1/actions", { action: d, policy: { decision: "ask", rule_id: null, risk: "high", reason: "r" }, action_hash: computeActionHash(d) }, { token: agent });
    await until(agent, id, (x) => x.status === "awaiting_approval");
    expect((await events(agent, id)).some((e) => e.type === "approval.requested" && e.payload.approval_id === act.json.approval.approval_id)).toBe(true);
    const now = h!.clock.now().getTime();
    const dec = signDecision(
      { v: 2, approval_id: act.json.approval.approval_id, action_id: act.json.action.action_id, session_id: ses.json.id, action_hash: act.json.action_hash, decision: "approve", device_id: phone.id, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 60_000).toISOString(), nonce: Buffer.from(rnd(18)).toString("base64url") },
      phone.kp.privateKey,
    );
    expect((await inject("POST", `/v1/approvals/${act.json.approval.approval_id}/approve`, { device_id: phone.id, signed_decision: dec }, { token: phone.token })).status).toBe(200);
    await until(agent, id, (x) => x.status === "running");
    await phoneCmd(phone, id, { command: "kill" });
  }, T);
});

describe("signed commands", () => {
  async function idle() {
    const ctx = await server();
    const id = await startLocal(ctx.agent, ctx.dir, "say:ready");
    await until(ctx.agent, id, (x) => x.status === "waiting_input");
    return { ...ctx, id };
  }

  it.each([
    ["forged (random key)", (c: any) => ({ device_id: c.phone.id, body: { command: "instruct", text: "say:x" }, signed_command: sign(generateDeviceKeyPair(rnd), c.phone.id, c.id, { command: "instruct", text: "say:x" }) })],
    ["another device's key", (c: any) => ({ device_id: c.phone.id, body: { command: "instruct", text: "say:x" }, signed_command: sign(c.other.kp, c.phone.id, c.id, { command: "instruct", text: "say:x" }) })],
    ["body swap", (c: any) => ({ device_id: c.phone.id, body: { command: "instruct", text: "say:EVIL" }, signed_command: sign(c.phone.kp, c.phone.id, c.id, { command: "instruct", text: "say:x" }) })],
    ["command swap (signed pause, sent kill)", (c: any) => ({ device_id: c.phone.id, body: { command: "kill" }, signed_command: sign(c.phone.kp, c.phone.id, c.id, { command: "pause" }) })],
    ["other session", (c: any) => ({ device_id: c.phone.id, body: { command: "instruct", text: "say:x" }, signed_command: sign(c.phone.kp, c.phone.id, "ags_other", { command: "instruct", text: "say:x" }) })],
    [
      "an approval decision token used as a command",
      (c: any) => {
        const now = h!.clock.now().getTime();
        return {
          device_id: c.phone.id,
          body: { command: "instruct", text: "say:x" },
          signed_command: signDecision({ v: 2, approval_id: c.id, action_id: "a", session_id: c.id, action_hash: "0".repeat(64), decision: "approve", device_id: c.phone.id, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 60_000).toISOString(), nonce: Buffer.from(rnd(18)).toString("base64url") }, c.phone.kp.privateKey),
        };
      },
    ],
  ])("rejects %s (403, audited, nothing runs)", async (_n, make) => {
    const c = await idle();
    const other = await pair(c.agent, "iPad-2").catch(() => null); // second device needs approval → use a detached key instead
    const ctx = { ...c, other: other ?? { kp: generateDeviceKeyPair(rnd) } };
    const r = await inject("POST", `/v1/agent-sessions/${c.id}/commands`, make(ctx), { token: c.phone.token });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("invalid_signed_command");
    await h!.supervisor!.settle(c.id);
    expect((await session(c.agent, c.id)).usage.turns).toBe(1);
    const audit = await h!.database.db.execute(`SELECT count(*)::int AS n FROM audit_logs WHERE event = 'session.command_rejected'` as never);
    expect(((audit as any).rows ?? audit)[0].n).toBeGreaterThan(0);
  }, T);

  it("replay of a valid signed command → 403 replayed", async () => {
    const c = await idle();
    const body: CommandBody = { command: "instruct", text: "say:once" };
    const req = { device_id: c.phone.id, body, signed_command: sign(c.phone.kp, c.phone.id, c.id, body) };
    expect((await inject("POST", `/v1/agent-sessions/${c.id}/commands`, req, { token: c.phone.token })).json.status).toBe("applied");
    const again = await inject("POST", `/v1/agent-sessions/${c.id}/commands`, req, { token: c.phone.token });
    expect([again.status, again.json.error?.message]).toEqual([403, expect.stringMatching(/replayed/)]);
  }, T);

  it("kill must be freshly signed (≤ 60 s)", async () => {
    const c = await idle();
    const old = h!.clock.now().getTime() - 90_000;
    const r = await phoneCmd(c.phone, c.id, { command: "kill" }, { issued_at: new Date(old).toISOString(), expires_at: new Date(old + 200_000).toISOString() });
    expect(r.json.error.code).toBe("stale_command");
  }, T);

  it("a command that isn't possible now → 200 status rejected with a reason", async () => {
    const c = await idle();
    const r = await phoneCmd(c.phone, c.id, { command: "pause" });
    expect(r.json).toMatchObject({ status: "rejected", reason: expect.stringMatching(/pause is not possible/) });
  }, T);
});

describe("workspaces + phone start", () => {
  it("start only in allowlisted workspaces; the phone cannot widen the allowlist", async () => {
    const { agent, phone, dir } = await server();
    const body: CommandBody = { command: "start", provider: "claude-code", workspace_id: "wsp_nope", prompt: "say:hi" };
    const bad = await inject("POST", "/v1/agent-sessions", { device_id: phone.id, body, signed_command: sign(phone.kp, phone.id, "new", body) }, { token: phone.token });
    expect([bad.status, bad.json.error.code]).toEqual([403, "workspace_not_allowed"]);
    expect((await inject("POST", "/v1/workspaces", { path: dir }, { token: phone.token })).status).toBe(403);
    expect((await inject("POST", "/v1/workspaces", { path: dir }, { token: agent, ip: "192.168.1.9" })).status).toBe(403);
    const w = await inject("POST", "/v1/workspaces", { path: dir, label: "demo" }, { token: agent });
    expect(w.status).toBe(201);
    expect((await inject("GET", "/v1/workspaces", undefined, { token: phone.token })).json.items).toEqual([{ id: w.json.id, path: dir, label: "demo", ungated_providers: [] }]);
    const ok: CommandBody = { command: "start", provider: "claude-code", workspace_id: w.json.id, prompt: "say:started from phone", title: "Phone task" };
    const r = await inject("POST", "/v1/agent-sessions", { device_id: phone.id, body: ok, signed_command: sign(phone.kp, phone.id, "new", ok) }, { token: phone.token });
    expect(r.status).toBe(201);
    const s = await until(agent, r.json.session.id, (x) => x.status === "waiting_input");
    expect(s).toMatchObject({ title: "Phone task", cwd: dir });
    // signed for a session id instead of "new" → rejected
    const wrong = await inject("POST", "/v1/agent-sessions", { device_id: phone.id, body: ok, signed_command: sign(phone.kp, phone.id, s.id, ok) }, { token: phone.token });
    expect(wrong.status).toBe(403);
  }, T);
});

describe("realtime + notifications", () => {
  it("device WS receives session.updated and session.event", async () => {
    const { agent, phone, dir } = await server();
    await h!.app.listen({ port: 0, host: "127.0.0.1" });
    const port = (h!.app.server.address() as { port: number }).port;
    const got: ServerEvent[] = [];
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/device/connect`, { headers: { authorization: `Bearer ${phone.token}` } });
    ws.on("message", (d) => got.push(ServerEvent.parse(JSON.parse(d.toString()))));
    await new Promise((r) => ws.once("open", r));
    const id = await startLocal(agent, dir, "say:secret AKIAABCDEFGHIJKLMNOP here");
    await until(agent, id, (x) => x.status === "waiting_input");
    await new Promise((r) => setTimeout(r, 100));
    ws.close();
    expect(got.some((e) => e.type === "session.updated" && e.session.id === id && e.session.status === "waiting_input")).toBe(true);
    const msg = got.find((e) => e.type === "session.event" && e.event.type === "message.assistant") as any;
    expect(msg.event.payload.text).toBe("secret AKIA*** here"); // redacted
  }, T);

  it("coalesces session pushes (≤ 1 / 30 s per session) except input_required", async () => {
    const { agent, phone, dir } = await server();
    const id = await startLocal(agent, dir, "say:one");
    await until(agent, id, (x) => x.status === "waiting_input");
    await phoneCmd(phone, id, { command: "instruct", text: "say:two" });
    await until(agent, id, (x) => x.usage.turns === 2 && x.status === "waiting_input");
    await phoneCmd(phone, id, { command: "instruct", text: "ask:Continue?" });
    await until(agent, id, (x) => x.usage.turns === 3 && x.status === "waiting_input");
    const bodies = h!.push.sent.filter((m) => m.data.session_id === id).map((m) => m.body);
    expect(bodies).toEqual(["Claude Code finished a task", "Claude Code is waiting for you"]);
  }, T);
});

describe("observed sessions (installed hooks)", () => {
  it("maps hook events; Notification idle → waiting_input; continue remotely → managed --resume turn", async () => {
    const { agent, phone, dir, log } = await server();
    const hook = (hook_event_name: string, extra: Record<string, unknown> = {}) =>
      inject("POST", "/v1/agent-sessions/observe", { provider: "claude-code", hook: { session_id: "claude-obs-1", cwd: dir, hook_event_name, ...extra } }, { token: agent });
    expect((await hook("SessionStart", { source: "startup" })).status).toBe(200);
    await hook("UserPromptSubmit", { prompt: "Refactor the parser" });
    await hook("PostToolUse", { tool_name: "Edit", tool_input: { file_path: "a.ts" }, tool_response: { success: true } });
    const w = (await hook("Notification", { notification_type: "idle_prompt", message: "Claude is waiting for your input" })).json.session;
    expect(w).toMatchObject({ mode: "observed", status: "waiting_input", title: "Refactor the parser", can: { continue_remotely: true, pause: false, kill: false } });
    expect(h!.push.sent.at(-1)!.body).toBe("Claude Code is waiting for you");
    await hook("Stop");
    const ended = (await hook("SessionEnd", { reason: "prompt_input_exit" })).json.session;
    expect(ended.status).toBe("completed");
    const types = (await events(agent, ended.id)).map((e) => e.type);
    expect(types).toEqual(expect.arrayContaining(["session.started", "message.user", "tool.result", "input.required", "turn.completed", "session.completed"]));
    // hooks can't be posted by the phone or remotely
    expect((await inject("POST", "/v1/agent-sessions/observe", { hook: {} }, { token: phone.token })).status).toBe(403);
    // Continue remotely
    const r = await phoneCmd(phone, ended.id, { command: "instruct", text: "say:continued remotely" });
    expect(r.json.status).toBe("applied");
    const s = await until(agent, ended.id, (x) => x.status === "waiting_input" && x.usage.turns === 1);
    expect(s.mode).toBe("managed");
    expect(agentRuns(log).at(-1).args).toEqual(expect.arrayContaining(["--resume", "claude-obs-1"]));
    // hooks from the now-managed session's own turns are ignored
    const after = (await hook("Stop")).json.session;
    expect(after.mode).toBe("managed");
  }, T);
});
