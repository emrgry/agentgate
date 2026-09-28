import { randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { generateSigningKeyPair } from "@agentgate/core";
import { AgentSession, AgentTask, ListProvidersResponse, type CommandBody } from "@agentgate/protocol";
import { commandBodyHash, generateDeviceKeyPair, signCommand, type DeviceKeyPair } from "@agentgate/signing";
import { buildApp } from "../src/app.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { openDatabase } from "../src/db/client.ts";
import { createSigner } from "../src/keys.ts";
import { createHarness, RecordingPush, TestClock, type Harness } from "./helpers.ts";

/** Control Center Phase 2: task queue, providers, many concurrent sessions, turn cap. */

const FAKE = join(dirname(fileURLToPath(import.meta.url)), "fake-agent.mjs");
const T = 90_000;
const rnd = (n: number) => new Uint8Array(randomBytes(n));

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

type R = { status: number; json: any };
async function inject(method: "GET" | "POST", url: string, body?: unknown, o: { token?: string } = {}): Promise<R> {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: "127.0.0.1",
    headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

const other = { ...claudeCodeProvider({ binary: FAKE }), id: "other-agent", displayName: "Other Agent" };
function control(extra: Partial<SupervisorOptions> = {}): SupervisorOptions {
  return {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE }), "other-agent": other, "ghost-cli": { ...other, id: "ghost-cli", displayName: "Ghost", binary: "ghost-cli-not-installed" } },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env }),
    stopGraceMs: 400,
    ...extra,
  };
}

async function server(extra: Partial<SupervisorOptions> = {}) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-tasks-")));
  h = await createHarness({ mode: "local", openDeviceLogin: false, control: control(extra) });
  await h.app.ready();
  const agent = (await inject("POST", "/v1/auth/login", { client: "agent" })).json.access_token as string;
  const kp = generateDeviceKeyPair(rnd);
  const code = (await inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
  const r = await inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_name: "iPhone", device_public_key: kp.publicKey });
  await inject("POST", "/v1/devices", { name: "iPhone", platform: "ios", push_token: "ExponentPushToken[p]" }, { token: r.json.access_token });
  return { agent, dir, phone: { kp, token: r.json.access_token as string, id: r.json.device_id as string } };
}

function sign(kp: DeviceKeyPair, deviceId: string, sessionId: string, body: CommandBody) {
  const now = h!.clock.now().getTime();
  return signCommand(
    { v: 2, kind: "command", command: body.command, session_id: sessionId, payload_hash: commandBodyHash(body), device_id: deviceId, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 60_000).toISOString(), nonce: Buffer.from(rnd(18)).toString("base64url") } as never,
    kp.privateKey,
  );
}
const cmd = (p: { kp: DeviceKeyPair; token: string; id: string }, sessionId: string, body: CommandBody) =>
  inject("POST", `/v1/agent-sessions/${sessionId}/commands`, { device_id: p.id, body, signed_command: sign(p.kp, p.id, sessionId, body) }, { token: p.token });

async function start(agent: string, cwd: string, prompt: string, provider = "claude-code") {
  const r = await inject("POST", "/v1/agent-sessions", { cwd, prompt, provider }, { token: agent });
  expect(r.status).toBe(201);
  return r.json.session.id as string;
}
const session = async (agent: string, id: string) => AgentSession.parse((await inject("GET", `/v1/agent-sessions/${id}`, undefined, { token: agent })).json);
const tasks = async (agent: string, id: string) => (await inject("GET", `/v1/agent-sessions/${id}/tasks`, undefined, { token: agent })).json.items.map((t: unknown) => AgentTask.parse(t)) as AgentTask[];

async function until<T>(get: () => Promise<T>, pred: (v: T) => boolean, ms = 60_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    await h!.supervisor!.settle();
    const v = await get();
    if (pred(v)) return v;
    if (Date.now() > end) throw new Error(`timeout: ${JSON.stringify(v).slice(0, 400)}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe("task queue", () => {
  it("first prompt is task #1; queued tasks auto-advance in order as --resume turns; notifications", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "ticks:3;say:t1 done");
    await until(() => session(agent, id), (s) => s.status === "running");
    for (const n of [2, 3]) expect((await cmd(phone, id, { command: "enqueue_task", text: `say:t${n} done`, title: `Task ${n}` })).json.status).toBe("queued");
    const mid = await session(agent, id);
    expect(mid.queued_tasks).toBe(2);
    const done = await until(() => tasks(agent, id), (ts) => ts.every((t) => t.status === "completed"));
    expect(done.map((t) => [t.position, t.title, t.status])).toEqual([
      [0, "ticks:3;say:t1 done", "completed"],
      [1, "Task 2", "completed"],
      [2, "Task 3", "completed"],
    ]);
    expect(done.map((t) => t.summary?.last_message)).toEqual(["t1 done", "t2 done", "t3 done"]);
    expect(done.every((t) => t.usage?.turns === 1 && t.started_at && t.ended_at)).toBe(true);
    const s = await session(agent, id);
    expect(s).toMatchObject({ status: "waiting_input", queued_tasks: 0, current_task_id: done[2]!.id, usage: { turns: 3 } });
    const bodies = h!.push.sent.filter((m) => m.data.session_id === id).map((m) => m.body);
    expect(bodies[0]).toBe("Claude Code finished a task");
    expect(bodies.at(-1)).toBe("Claude Code finished all tasks");
  }, T);

  it("enqueue on an idle session starts immediately", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "say:first");
    await until(() => session(agent, id), (s) => s.status === "waiting_input");
    expect((await cmd(phone, id, { command: "enqueue_task", text: "say:second" })).json.status).toBe("applied");
    const ts = await until(() => tasks(agent, id), (x) => x.length === 2 && x[1]!.status === "completed");
    expect(ts[1]!.summary?.last_message).toBe("second");
  }, T);

  it("a question pauses the task (waiting); answering continues the SAME task, then the queue advances", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "ticks:2;ask:Which file?");
    await until(() => session(agent, id), (s) => s.status === "running");
    await cmd(phone, id, { command: "enqueue_task", text: "say:t2 done" });
    const s = await until(() => session(agent, id), (x) => x.status === "waiting_input" && x.pending_interaction_id !== null);
    let ts = await tasks(agent, id);
    expect(ts.map((t) => t.status)).toEqual(["waiting", "queued"]);
    expect((await cmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "say:deleted" })).json.status).toBe("applied");
    ts = await until(() => tasks(agent, id), (x) => x.every((t) => t.status === "completed"));
    expect(ts[0]!.usage?.turns).toBe(2); // question turn + answer turn, same task
    expect(ts[0]!.summary?.last_message).toBe("deleted");
  }, T);

  it("a failed task pauses the queue; enqueue_task resumes it", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "ticks:3;fail");
    await until(() => session(agent, id), (s) => s.status === "running");
    await cmd(phone, id, { command: "enqueue_task", text: "say:t2 done" });
    await until(() => session(agent, id), (s) => s.status === "failed");
    await new Promise((r) => setTimeout(r, 300));
    expect((await tasks(agent, id)).map((t) => t.status)).toEqual(["failed", "queued"]); // not auto-run
    expect(h!.push.sent.some((m) => m.body === "Claude Code failed a task")).toBe(true);
    await cmd(phone, id, { command: "enqueue_task", text: "say:t3 done" });
    const ts = await until(() => tasks(agent, id), (x) => x.slice(1).every((t) => t.status === "completed"));
    expect(ts.map((t) => t.status)).toEqual(["failed", "completed", "completed"]);
  }, T);

  it("resume: continues a queue paused by a failure; still SIGCONT for a paused turn", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "ticks:3;fail");
    await until(() => session(agent, id), (s) => s.status === "running");
    await cmd(phone, id, { command: "enqueue_task", text: "say:after failure" });
    const failed = await until(() => session(agent, id), (s) => s.status === "failed");
    expect(failed.can).toMatchObject({ resume: true, pause: false });
    expect((await cmd(phone, id, { command: "resume" })).json.status).toBe("applied");
    const ts = await until(() => tasks(agent, id), (x) => x[1]!.status === "completed");
    expect(ts.map((t) => t.status)).toEqual(["failed", "completed"]);
    const idle = await session(agent, id);
    expect(idle.can.resume).toBe(false); // nothing left to continue
    // failed with an EMPTY queue → resume not offered
    const other = await start(agent, dir, "fail");
    expect((await until(() => session(agent, other), (s) => s.status === "failed")).can.resume).toBe(false);
    // classic meaning: paused turn → SIGCONT
    const p = await start(agent, dir, "ticks:900");
    await until(() => session(agent, p), (s) => s.status === "running");
    expect((await cmd(phone, p, { command: "pause" })).json.session).toMatchObject({ status: "paused", can: { resume: true } });
    expect((await cmd(phone, p, { command: "resume" })).json.session.status).toBe("running");
    await cmd(phone, p, { command: "kill" });
    await until(() => session(agent, p), (s) => s.status === "killed");
  }, T);

  it("instruct on a failed session retries the failed task", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "say:x;fail");
    await until(() => session(agent, id), (s) => s.status === "failed");
    await cmd(phone, id, { command: "instruct", text: "say:fixed" });
    const ts = await until(() => tasks(agent, id), (x) => x[0]!.status === "completed");
    expect(ts).toHaveLength(1);
    expect(ts[0]!.summary?.last_message).toBe("fixed");
  }, T);

  it("move_task reorders queued tasks; cancel_task only queued; kill leaves the queue queued", async () => {
    const { agent, phone, dir } = await server();
    const id = await start(agent, dir, "hang");
    await until(() => session(agent, id), (s) => s.status === "running");
    const ids: string[] = [];
    for (const n of ["a", "b", "c"]) ids.push((await cmd(phone, id, { command: "enqueue_task", text: `say:${n}`, title: n })).json.command_id);
    let ts = await tasks(agent, id);
    const [, a, b, c] = ts;
    expect((await cmd(phone, id, { command: "move_task", task_id: c!.id, position: 0 })).json.status).toBe("applied");
    ts = await tasks(agent, id);
    expect(ts.filter((t) => t.status === "queued").map((t) => t.title)).toEqual(["c", "a", "b"]);
    expect((await cmd(phone, id, { command: "cancel_task", task_id: a!.id })).json.status).toBe("applied");
    const running = await cmd(phone, id, { command: "cancel_task", task_id: ts[0]!.id });
    expect(running.json).toMatchObject({ status: "rejected", reason: expect.stringMatching(/use stop/) });
    const moveRunning = await cmd(phone, id, { command: "move_task", task_id: ts[0]!.id, position: 1 });
    expect(moveRunning.json.status).toBe("rejected");
    await cmd(phone, id, { command: "kill" });
    await until(() => session(agent, id), (s) => s.status === "killed");
    ts = await tasks(agent, id);
    expect(ts.map((t) => [t.title, t.status])).toEqual([
      ["hang", "cancelled"],
      ["c", "queued"],
      ["a", "cancelled"],
      ["b", "queued"],
    ]);
    expect((await session(agent, id)).queued_tasks).toBe(2);
    void b;
  }, T);

  it("restart: the running task fails with 'server restarted'; the queue stays paused", async () => {
    const database = await openDatabase({ kind: "memory" });
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "ag-tasks-")));
    const signer = createSigner(generateSigningKeyPair().privateKeyPem);
    const mk = () => buildApp({ db: database.db, signer, authSecret: "test-secret-test-secret-test-secret", push: () => new RecordingPush(), clock: new TestClock(), logLevel: false, mode: "local", control: control(), rateLimit: false });
    const a = await mk();
    const tok = JSON.parse((await a.app.inject({ method: "POST", url: "/v1/auth/login", remoteAddress: "127.0.0.1", headers: { "content-type": "application/json" }, payload: '{"client":"agent"}' })).body).access_token;
    const call = async (app: typeof a, method: "GET" | "POST", url: string, body?: unknown) =>
      JSON.parse((await app.app.inject({ method, url, remoteAddress: "127.0.0.1", headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" }, ...(body ? { payload: JSON.stringify(body) } : {}) })).body);
    const id = (await call(a, "POST", "/v1/agent-sessions", { cwd: dir, prompt: "say:hi;hang" })).session.id;
    await call(a, "POST", `/v1/agent-sessions/${id}/commands`, { body: { command: "enqueue_task", text: "say:later" } });
    for (let i = 0; i < 200 && (await call(a, "GET", `/v1/agent-sessions/${id}`)).status !== "running"; i++) await new Promise((r) => setTimeout(r, 50));
    await a.app.close();
    const b = await mk();
    const s = await call(b, "GET", `/v1/agent-sessions/${id}`);
    expect(s.status).toBe("lost");
    const ts = (await call(b, "GET", `/v1/agent-sessions/${id}/tasks`)).items;
    expect(ts.map((t: any) => t.status)).toEqual(["failed", "queued"]);
    expect(ts[0].summary.error).toBe("server restarted");
    await new Promise((r) => setTimeout(r, 300));
    expect((await call(b, "GET", `/v1/agent-sessions/${id}/tasks`)).items[1].status).toBe("queued");
    await b.app.close();
    await database.close();
  }, T);
});

describe("providers + fleet", () => {
  it("GET /v1/providers: availability by binary lookup; claude always listed; unavailable provider can't start", async () => {
    const { agent, phone, dir } = await server();
    const list = ListProvidersResponse.parse((await inject("GET", "/v1/providers", undefined, { token: phone.token })).json).items;
    expect(list.map((p) => [p.id, p.available])).toEqual([
      ["claude-code", true],
      ["other-agent", true],
      ["ghost-cli", false],
    ]);
    expect(list[2]!.reason).toBe("ghost-cli-not-installed not found on PATH");
    expect(list[0]!.capabilities).toEqual({ resume: true, pause: true, cost: true, observe: true });
    const bad = await inject("POST", "/v1/agent-sessions", { cwd: dir, prompt: "x", provider: "ghost-cli" }, { token: agent });
    expect([bad.status, bad.json.error.code]).toEqual([400, "provider_unavailable"]);
    expect((await inject("POST", "/v1/agent-sessions", { cwd: dir, prompt: "x", provider: "nope" }, { token: agent })).status).toBe(400);
  }, T);

  it("claude listed as unavailable when not configured", async () => {
    await server({ providers: { "other-agent": other } });
    const list = (await inject("GET", "/v1/providers", undefined, { token: (await inject("POST", "/v1/auth/login", { client: "agent" })).json.access_token })).json.items;
    expect(list[0]).toMatchObject({ id: "claude-code", available: false });
  }, T);

  it("3 concurrent sessions (2 claude + 1 other provider) are controlled independently", async () => {
    const { agent, phone, dir } = await server();
    const a = await start(agent, dir, "ticks:900");
    const b = await start(agent, dir, "ticks:900");
    const c = await start(agent, dir, "ticks:900", "other-agent");
    for (const id of [a, b, c]) await until(() => session(agent, id), (s) => s.status === "running");
    expect((await session(agent, c)).provider).toBe("other-agent");
    expect((await cmd(phone, a, { command: "pause" })).json.session.status).toBe("paused");
    expect((await cmd(phone, b, { command: "kill" })).status).toBe(200);
    await until(() => session(agent, b), (s) => s.status === "killed");
    const count = async (id: string) => (await inject("GET", `/v1/agent-sessions/${id}/events?limit=500`, undefined, { token: agent })).json.items.filter((e: any) => e.type === "message.assistant").length;
    const c1 = await count(c);
    await until(() => count(c), (n) => n > c1 + 2); // c keeps running
    expect((await session(agent, a)).status).toBe("paused");
    expect((await session(agent, c)).status).toBe("running");
    for (const id of [a, c]) await cmd(phone, id, { command: "kill" });
    for (const id of [a, c]) await until(() => session(agent, id), (s) => s.status === "killed");
  }, T);

  it("global cap: an extra turn waits in `starting` and runs when a slot frees", async () => {
    const { agent, phone, dir } = await server({ maxConcurrentTurns: 2 });
    const a = await start(agent, dir, "hang");
    const b = await start(agent, dir, "hang");
    const c = await start(agent, dir, "say:finally ran");
    for (const id of [a, b]) await until(() => session(agent, id), (s) => s.status === "running");
    const parked = await session(agent, c);
    expect(parked.status).toBe("starting");
    const ev = (await inject("GET", `/v1/agent-sessions/${c}/events`, undefined, { token: agent })).json.items;
    expect(ev.some((e: any) => e.type === "status.changed" && /waiting for a free slot/.test(e.payload.reason ?? ""))).toBe(true);
    // stop of a parked session works without a process
    const d = await start(agent, dir, "say:never");
    expect((await cmd(phone, d, { command: "stop" })).json.session.status).toBe("stopped");
    await cmd(phone, a, { command: "kill" });
    await until(() => session(agent, c), (s) => s.status === "waiting_input");
    expect((await session(agent, c)).summary?.last_message).toBe("finally ran");
    await cmd(phone, b, { command: "kill" });
    await until(() => session(agent, b), (s) => s.status === "killed");
  }, T);
});
