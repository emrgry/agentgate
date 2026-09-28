import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { computeActionHash } from "@agentgate/core";
import { ApprovalDetail, SessionMetrics } from "@agentgate/protocol";
import { signDecision } from "@agentgate/signing";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE } from "./control-harness.ts";
import { draft } from "./helpers.ts";

/** Real-device follow-ups: cost kind, mid-turn cost limits, human budget prompts, approval ↔ session linkage. */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());
const rnd = (n: number) => new Uint8Array(randomBytes(n));

function control(env: Record<string, string> = {}): SupervisorOptions {
  return {
    providers: { "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }) },
    hookSettingsPath: () => "/dev/null",
    turnEnv: () => ({ ...process.env, ...env }),
    stopGraceMs: 300,
    tickMs: 0,
  };
}

describe("cost kind", () => {
  it("claude.ai login → usage.cost_kind subscription_estimate on sessions, tasks, metrics and usage", async () => {
    const { agent, phone, dir } = await c.server(control({ FAKE_AUTH_METHOD: "claude.ai" }));
    await new Promise((r) => setTimeout(r, 500)); // detection at start (auth status)
    const id = await c.start(agent, dir, "say:hi");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input");
    expect(s.usage.cost_kind).toBe("subscription_estimate");
    expect((await c.tasks(agent, id))[0]!.usage?.cost_kind).toBe("subscription_estimate");
    const m = SessionMetrics.parse((await c.inject("GET", `/v1/agent-sessions/${id}/metrics`, undefined, { token: phone.token })).json);
    expect(m.usage.cost_kind).toBe("subscription_estimate");
    const u = (await c.inject("GET", "/v1/usage?range=today", undefined, { token: phone.token })).json;
    expect(u.by_provider[0]).toMatchObject({ provider: "claude-code", cost_kind: "subscription_estimate" });
  }, T);
});

describe("mid-turn cost limits", () => {
  it("the running estimate trips the limit before the turn ends: tree paused + human budget question; continue resumes; the real total is used at the end", async () => {
    const { agent, phone, dir } = await c.server(control({ FAKE_AUTH_METHOD: "claude.ai" }));
    await new Promise((r) => setTimeout(r, 500));
    await c.inject("POST", "/v1/agent-sessions/global/commands", { body: { command: "set_limits", limits: { max_cost_usd_per_task: 0.1, on_exceed: "ask" } } }, { token: agent });
    // sonnet: 20k in × $3 + 5k out × $15 = $0.135 estimated, then the turn keeps going.
    const id = await c.start(agent, dir, "usage:claude-sonnet-4-5:20000:5000;ticks:30;cost:0.87;say:done");
    const s = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.pending_interaction_id !== null, 20_000);
    const evs = await c.events(agent, id);
    expect(evs.some((e) => e.type === "turn.completed")).toBe(false); // still mid-turn (SIGSTOPped)
    const hit = evs.find((e) => e.type === "limit.exceeded")!;
    expect(hit.payload).toMatchObject({ when: "mid_turn", estimated: true, limit: "max_cost_usd_per_task", limit_value: 0.1, unit: "usd", cost_kind: "subscription_estimate" });
    expect(hit.payload.value).toBeCloseTo(0.135, 3);
    const ask = evs.find((e) => e.type === "input.required")!;
    expect(ask.payload.prompt).toBe('Estimated cost $0.14 exceeded your $0.10 per-task limit (included in your subscription — estimate). Reply "continue" to go on, or "stop".');
    expect(ask.payload).toMatchObject({ kind: "budget", limit_value: 0.1, unit: "usd", estimated: true, cost_kind: "subscription_estimate" });
    const ticksAtPause = evs.filter((e) => e.type === "message.assistant").length;
    await new Promise((r) => setTimeout(r, 600));
    expect((await c.events(agent, id)).filter((e) => e.type === "message.assistant").length).toBe(ticksAtPause);
    await c.cmd(phone, id, { command: "answer", interaction_id: s.pending_interaction_id!, text: "continue" });
    const done = await c.until(() => c.session(agent, id), (x) => x.status === "waiting_input" && x.usage.turns === 1, 20_000);
    expect(done.usage.cost_usd).toBe(0.87); // reconciled with the real total
    expect(done.pending_interaction_id).toBeNull(); // same limit, same task → not asked again
    const m = SessionMetrics.parse((await c.inject("GET", `/v1/agent-sessions/${id}/metrics`, undefined, { token: agent })).json);
    expect(m.exceeded).toHaveLength(1);
  }, T);

  it("time / retries / memory limits get human texts too", async () => {
    const { limitDetail } = await import("../src/control/supervisor.ts");
    const l = { max_task_minutes: 15, max_session_minutes: 60, max_retries: 3, max_rss_mb: 512, max_cost_usd_per_session: 5, on_exceed: "ask" as const };
    const k = { estimated: false, costKind: "api" as const };
    expect(limitDetail({ limit: "max_task_minutes", value: 16.4 }, l, k).text).toBe("Task has run 16 min, over your 15 min limit.");
    expect(limitDetail({ limit: "max_session_minutes", value: 61 }, l, k).text).toBe("Session has run 61 min, over your 60 min limit.");
    expect(limitDetail({ limit: "max_retries", value: 4 }, l, k).text).toBe("4 retries, over your limit of 3.");
    expect(limitDetail({ limit: "max_rss_mb", value: 612.3 }, l, k)).toMatchObject({ text: "Memory use 612 MB, over your 512 MB limit.", unit: "mb", limit_value: 512 });
    expect(limitDetail({ limit: "max_cost_usd_per_session", value: 5.2 }, l, k).text).toBe("Cost $5.20 exceeded your $5.00 per-session limit.");
    expect(limitDetail({ limit: "max_cost_usd_per_session", value: 5.2 }, l, { estimated: true, costKind: "api" }).text).toBe("Estimated cost $5.20 exceeded your $5.00 per-session limit (estimate).");
  });
});

describe("approval ↔ session linkage (inline approval card)", () => {
  it("an approval raised by a managed turn: approval.requested carries approval_id; the device fetches it (GET /v1/approvals/:id) and resolves it while the session is awaiting_approval", async () => {
    const { agent, phone, dir } = await c.server(control());
    const id = await c.start(agent, dir, "say:working;hang");
    await c.until(() => c.session(agent, id), (x) => x.status === "running" && x.provider_session_id !== null);
    // What the Codex/generic hooks do: action context carries the control session.
    const ag = await c.inject("POST", "/v1/agents", { name: "m", type: "claude-code", machine_id: "m" }, { token: agent });
    const ses = await c.inject("POST", "/v1/sessions", { agent_id: ag.json.id }, { token: agent });
    const d = { ...draft(ses.json.id), context: { agentgate_control_session: id } };
    const act = await c.inject("POST", "/v1/actions", { action: d, policy: { decision: "ask", rule_id: null, risk: "high", reason: "r" }, action_hash: computeActionHash(d) }, { token: agent });
    const approvalId = act.json.approval.approval_id as string;
    await c.until(() => c.session(agent, id), (x) => x.status === "awaiting_approval");
    const ev = (await c.events(agent, id)).find((e) => e.type === "approval.requested")!;
    expect(ev.payload.approval_id).toBe(approvalId);
    const got = await c.inject("GET", `/v1/approvals/${approvalId}`, undefined, { token: phone.token });
    expect(got.status).toBe(200);
    const detail = ApprovalDetail.parse(got.json);
    expect(detail.approval.status).toBe("pending");
    const now = c.h.clock.now();
    const signed = signDecision(
      { v: 2, approval_id: approvalId, action_id: detail.action.action_id, session_id: detail.action.session_id, action_hash: detail.action_hash, decision: "approve", device_id: phone.id, issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 60_000).toISOString(), nonce: Buffer.from(rnd(18)).toString("base64url") },
      phone.kp.privateKey,
    );
    expect((await c.inject("POST", `/v1/approvals/${approvalId}/approve`, { device_id: phone.id, signed_decision: signed }, { token: phone.token })).status).toBe(200);
    await c.until(() => c.session(agent, id), (x) => x.status === "running");
    await c.cmd(phone, id, { command: "kill" });
  }, T);
});
