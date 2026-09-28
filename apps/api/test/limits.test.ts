import { mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { codexProvider } from "@agentgate/adapter-codex";
import { SessionMetrics, UsageReport, type Limits } from "@agentgate/protocol";
import { agentSessions } from "../src/db/schema.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE, FAKE_CODEX, type Phone } from "./control-harness.ts";
import { TestClock } from "./helpers.ts";

/** Control Center Phase 4: resources, retries, limits (every on_exceed), usage, smart notifications, kill. */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());

let fakePs: ((pid: number) => string) | null = null;
function control(extra: Partial<SupervisorOptions> = {}, env: Record<string, string> = {}): SupervisorOptions {
  const homes = realpathSync(mkdtempSync(join(tmpdir(), "ag-l-")));
  return {
    providers: {
      "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }),
      codex: codexProvider({ binary: FAKE_CODEX, codexHome: (sid) => join(homes, sid) }),
    },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, ...env }),
    stopGraceMs: 300,
    tickMs: 0,
    ...extra,
  };
}
/** ps stand-in: the turn leader (pid from the DB) + one child; values chosen by the test. */
function psFor(cpu: number, rssKb: number) {
  return (pid: number) =>
    [`1 0 1 0.0 1000 Sat Sep 26 10:00:00 2026`, `${pid} 1 ${pid} ${cpu} ${rssKb} Sat Sep 26 12:00:00 2026`, `${pid + 900000} ${pid} ${pid} ${cpu} ${rssKb} Sat Sep 26 12:00:01 2026`].join("\n");
}
async function pidOf(id: string) {
  return (await c.h.database.db.select().from(agentSessions).where(eq(agentSessions.id, id)))[0]!.pid!;
}
async function withFakePs(ctl: Partial<SupervisorOptions> = {}) {
  let current = 0;
  const ps = async () => (fakePs ? fakePs(current) : "");
  const setPid = (p: number) => (current = p);
  return { extra: { ...ctl, ps }, setPid };
}
const metrics = async (agent: string, id: string) => {
  const r = await c.inject("GET", `/v1/agent-sessions/${id}/metrics`, undefined, { token: agent });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
  return SessionMetrics.passthrough().parse(r.json) as SessionMetrics & { notes?: string[] };
};
const setLimits = (p: Phone, id: string, limits: Limits) => c.cmd(p, id, { command: "set_limits", limits } as never);
const pushes = (id: string) => c.h.push.sent.filter((m) => m.data.session_id === id).map((m) => m.data.kind as string);

describe("resources", () => {
  it("sampler sums CPU/RSS over the turn's tree (fake ps); ring buffer; nothing when idle", async () => {
    const f = await withFakePs();
    const { agent, dir } = await c.server(control(f.extra));
    const id = await c.start(agent, dir, "hang");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    f.setPid(await pidOf(id));
    fakePs = psFor(12.5, 51200);
    await c.h.supervisor!.tick();
    await c.h.supervisor!.tick();
    const m = await metrics(agent, id);
    expect(m.resources).toMatchObject({ cpu_percent: 25, rss_mb: 100, processes: 2 });
    expect(m.history).toHaveLength(2);
    for (let i = 0; i < 125; i++) await c.h.supervisor!.tick();
    expect((await metrics(agent, id)).history).toHaveLength(120);
  }, T);
});

describe("limits: every on_exceed action", () => {
  it("notify: push + exceeded entry; the queue keeps going", async () => {
    const { agent, phone, dir } = await c.server(control(), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "sleep:300;cost:3;say:t1");
    await setLimits(phone, id, { max_cost_usd_per_task: 2, on_exceed: "notify" });
    await c.cmd(phone, id, { command: "enqueue_task", text: "cost:0.5;say:t2" });
    await c.until(() => c.tasks(agent, id), (x) => x.length === 2 && x[1]!.status === "completed");
    const m = await metrics(agent, id);
    expect(m.exceeded).toEqual([expect.objectContaining({ limit: "max_cost_usd_per_task", value: 3, action: "notify" })]);
    expect(pushes(id)).toContain("budget_exceeded");
    expect(c.h.push.sent.find((p) => p.data.kind === "budget_exceeded")!.body).toBe("Claude Code reached a limit");
  }, T);

  it("ask at turn end: budget interaction (kind in input.required), queue held; 'continue' goes on", async () => {
    const { agent, phone, dir } = await c.server(control(), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "sleep:300;cost:3;say:t1");
    await setLimits(phone, id, { max_cost_usd_per_task: 2, on_exceed: "ask" });
    await c.cmd(phone, id, { command: "enqueue_task", text: "cost:0.5;say:t2" });
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.pending_interaction_id !== null);
    const ev = (await c.events(agent, id)).find((e) => e.type === "input.required")!;
    expect(ev.payload).toMatchObject({ kind: "budget", interaction_id: s.pending_interaction_id });
    expect(ev.payload.prompt).toBe('Cost $3.00 exceeded your $2.00 per-task limit. Reply "continue" to go on, or "stop".');
    expect(ev.payload).toMatchObject({ limit: "max_cost_usd_per_task", value: 3, limit_value: 2, unit: "usd", estimated: false, cost_kind: "api" });
    expect((await c.tasks(agent, id)).map((t) => t.status)).toEqual(["completed", "queued"]);
    expect(pushes(id)).toContain("budget_exceeded");
    await c.cmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "continue" });
    await c.until(() => c.tasks(agent, id), (x) => x[1]!.status === "completed");
  }, T);

  it("ask while running (RSS via sampler): SIGSTOP + budget question; kill allowed; 'continue' → SIGCONT, suppressed; 'stop' stops", async () => {
    const f = await withFakePs();
    const { agent, phone, dir } = await c.server(control(f.extra), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "ticks:30;say:done");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    await setLimits(phone, id, { max_rss_mb: 50, on_exceed: "ask" });
    f.setPid(await pidOf(id));
    fakePs = psFor(1, 51200); // 100 MB
    await c.h.supervisor!.tick();
    let s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s.can.kill).toBe(true);
    // SIGSTOPped: after lines already in the pipe drain, no new ticks arrive.
    await new Promise((r) => setTimeout(r, 300));
    await c.h.supervisor!.settle();
    const seqBefore = (await c.events(agent, id)).length;
    await new Promise((r) => setTimeout(r, 600));
    await c.h.supervisor!.settle();
    expect((await c.events(agent, id)).length).toBe(seqBefore);
    await c.cmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "continue" });
    s = await c.until(() => c.session(agent, id), (x) => x.status === "running");
    await c.h.supervisor!.tick(); // same limit, same task → suppressed
    expect((await c.session(agent, id)).status).toBe("running");
    // New limit → asks again; answer "stop".
    await setLimits(phone, id, { max_rss_mb: 10, on_exceed: "ask" });
    await c.h.supervisor!.tick();
    s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.pending_interaction_id !== null);
    await c.cmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "stop" });
    s = await c.until(() => c.session(agent, id), (x) => x.status === "stopped");
    expect((await c.tasks(agent, id))[0]!.status).toBe("cancelled");
  }, T);

  it("pause: SIGSTOP + paused + push; resume continues", async () => {
    const f = await withFakePs();
    const { agent, phone, dir } = await c.server(control(f.extra), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "ticks:20;say:done");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    await setLimits(phone, id, { max_rss_mb: 50, on_exceed: "pause" });
    f.setPid(await pidOf(id));
    fakePs = psFor(1, 51200);
    await c.h.supervisor!.tick();
    await c.until(() => c.session(agent, id), (x) => x.status === "paused");
    expect(pushes(id)).toContain("budget_exceeded");
    await c.cmd(phone, id, { command: "resume" });
    await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input", 30_000);
  }, T);

  it("stop: the turn is stopped with the limit as the reason", async () => {
    const f = await withFakePs();
    const { agent, phone, dir } = await c.server(control(f.extra), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "hang");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    await setLimits(phone, id, { max_rss_mb: 50, on_exceed: "stop" });
    f.setPid(await pidOf(id));
    fakePs = psFor(1, 51200);
    await c.h.supervisor!.tick();
    await c.until(() => c.session(agent, id), (x) => x.status === "stopped");
    const reasons = (await c.events(agent, id)).filter((e) => e.type === "status.changed").map((e) => e.payload.reason);
    expect(reasons).toContain("limit reached: Memory use 100 MB, over your 50 MB limit.");
    expect(pushes(id)).toContain("budget_exceeded");
  }, T);

  it("null cost (Codex): cost limits never trip and metrics say so", async () => {
    const { agent, phone, dir } = await c.server(control());
    const id = await c.start(agent, dir, "say:hi", "codex");
    await setLimits(phone, id, { max_cost_usd_per_task: 0.000001, max_cost_usd_per_session: 0.000001, on_exceed: "stop" });
    await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    await c.cmd(phone, id, { command: "instruct", text: "say:again" });
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 2);
    expect(s.usage.cost_usd).toBeNull();
    const m = await metrics(agent, id);
    expect(m.exceeded).toEqual([]);
    expect(m.notes?.[0]).toMatch(/Codex reports no cost; cost limits are not enforced/);
  }, T);

  it("retries: api_retry events + a failed task re-run; max_retries notify", async () => {
    const { agent, phone, dir } = await c.server(control(), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "sleep:200;retry;retry;fail");
    await setLimits(phone, id, { max_retries: 2, on_exceed: "notify" });
    await c.until(() => c.session(agent, id), (x) => x.status === "failed");
    await c.cmd(phone, id, { command: "instruct", text: "say:ok now" }); // re-runs the failed task
    await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    const m = await metrics(agent, id);
    expect(m.retries).toBe(3);
    expect(m.exceeded.map((e) => e.limit)).toContain("max_retries");
  }, T);
});

describe("global limits + usage", () => {
  it("signed set_limits on 'global' (single use); defaults apply to sessions; GET /v1/usage aggregates + global_limits", async () => {
    const { agent, phone, dir } = await c.server(control());
    const body = { command: "set_limits", limits: { max_cost_usd_per_session: 5, on_exceed: "notify" } } as never;
    const signed = c.sign(phone.kp, phone.id, "global", body);
    const r = await c.inject("POST", "/v1/agent-sessions/global/commands", { device_id: phone.id, body, signed_command: signed }, { token: phone.token });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ status: "applied", session: null });
    const replay = await c.inject("POST", "/v1/agent-sessions/global/commands", { device_id: phone.id, body, signed_command: signed }, { token: phone.token });
    expect(replay.status).toBe(403);
    // Signed for a session id can't be used for "global".
    const wrong = await c.inject("POST", "/v1/agent-sessions/global/commands", { device_id: phone.id, body, signed_command: c.sign(phone.kp, phone.id, "ags_x", body) }, { token: phone.token });
    expect(wrong.status).toBe(403);
    // Only set_limits is accepted there.
    const other = { command: "pause" } as never;
    expect((await c.inject("POST", "/v1/agent-sessions/global/commands", { device_id: phone.id, body: other, signed_command: c.sign(phone.kp, phone.id, "global", other) }, { token: phone.token })).status).toBe(400);

    const a = await c.start(agent, dir, "say:one");
    const b = await c.start(agent, dir, "say:two");
    const x = await c.start(agent, dir, "say:three", "codex");
    for (const id of [a, b, x]) await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    expect((await metrics(agent, a)).limits).toMatchObject({ max_cost_usd_per_session: 5, on_exceed: "notify" });
    const u = UsageReport.parse((await c.inject("GET", "/v1/usage?range=today", undefined, { token: phone.token })).json);
    expect(u.total_cost_usd).toBeCloseTo(0.02);
    expect(u.by_provider).toEqual([
      { provider: "claude-code", sessions: 2, cost_usd: 0.02, input_tokens: 20, output_tokens: 10, duration_ms: 100, cost_kind: "api" },
      { provider: "codex", sessions: 1, cost_usd: null, input_tokens: 10, output_tokens: 5, duration_ms: 0, cost_kind: "unknown" },
    ]);
    expect(u.by_day).toEqual([{ day: c.h.clock.now().toISOString().slice(0, 10), cost_usd: 0.02, sessions: 3 }]);
    expect(u.global_limits).toMatchObject({ max_cost_usd_per_session: 5 });
    expect((await c.inject("GET", "/v1/usage?range=1y", undefined, { token: phone.token })).status).toBe(400);
  }, T);
});

describe("smart notifications", () => {
  it("stuck: running without events for N minutes → one push per episode (fake clock)", async () => {
    const clock = new TestClock();
    const { agent, dir } = await c.server(control({ stuckAfterMs: 10 * 60_000 }), { clock, sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "hang");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    await c.h.supervisor!.tick();
    expect(pushes(id)).not.toContain("stuck");
    clock.advance(11 * 60_000);
    await c.h.supervisor!.tick();
    await c.h.supervisor!.tick();
    expect(pushes(id).filter((k) => k === "stuck")).toHaveLength(1);
    expect(c.h.push.sent.find((m) => m.data.kind === "stuck")!.body).toBe("Claude Code seems stuck");
  }, T);

  it("repeated_failure: the same error twice (or 3 failures in a row) → 'keeps failing' instead of 'failed a task'", async () => {
    const { agent, phone, dir } = await c.server(control(), { sessionPushIntervalMs: 0 });
    const id = await c.start(agent, dir, "fail");
    await c.until(() => c.session(agent, id), (s) => s.status === "failed");
    await c.cmd(phone, id, { command: "instruct", text: "fail" });
    await c.until(() => c.session(agent, id), (s) => s.status === "failed" && s.usage.turns === 2);
    expect(pushes(id)).toEqual(["task_failed", "repeated_failure"]);
    expect(c.h.push.sent.at(-1)!.body).toBe("Claude Code keeps failing");
  }, T);
});

describe("emergency kill", () => {
  it("kill also kills a descendant that escaped the process group (setsid)", async () => {
    const pidFile = join(realpathSync(mkdtempSync(join(tmpdir(), "ag-esc-"))), "child.pid");
    const { agent, phone, dir } = await c.server(control({}, { FAKE_CHILD_PID: pidFile }));
    const id = await c.start(agent, dir, "escape");
    await c.until(() => c.session(agent, id), (s) => s.status === "running");
    const childPid = Number((await c.until(async () => { try { return readFileSync(pidFile, "utf8"); } catch { return ""; } }, (v) => v.length > 0)).trim());
    const alive = (p: number) => {
      try {
        process.kill(p, 0);
        return true;
      } catch {
        return false;
      }
    };
    expect(alive(childPid)).toBe(true);
    const r = await c.cmd(phone, id, { command: "kill" });
    expect(r.json.status).toBe("applied");
    await c.until(() => c.session(agent, id), (s) => s.status === "killed");
    await c.until(async () => alive(childPid), (v) => v === false, 5_000);
    const applied = (await c.events(agent, id)).find((e) => e.type === "control.applied" && e.payload.command === "kill")!;
    expect(applied.payload.escaped_processes_killed).toBeGreaterThanOrEqual(1);
  }, T);
});
