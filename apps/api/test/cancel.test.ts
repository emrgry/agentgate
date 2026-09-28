import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { auditLogs } from "../src/db/schema.ts";
import { call, createHarness, setup, submitBody, type Harness } from "./helpers.ts";

let h: Harness;
beforeEach(async () => {
  h = await createHarness();
});
afterEach(async () => {
  await h.close();
});

async function pending() {
  const s = await setup(h);
  const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
  return { ...s, id: sub.json.approval.approval_id as string, actionId: sub.json.action.action_id as string };
}

describe("POST /v1/approvals/:id/cancel", () => {
  it("cancels a pending approval, audits with reason, blocks later approve and execution", async () => {
    const s = await pending();
    const r = await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken, { session_id: s.sessionId, reason: "hook_deadline" });
    expect(r.status).toBe(200);
    expect(r.json.approval.status).toBe("cancelled");
    const audit = await h.database.db.select().from(auditLogs).where(eq(auditLogs.event, "approval.cancelled"));
    expect(audit).toHaveLength(1);
    expect(audit[0]!.payload_json).toMatchObject({ reason: "hook_deadline" });
    expect((await call(h, "POST", `/v1/approvals/${s.id}/approve`, s.deviceToken, { device_id: s.deviceId })).status).toBe(409);
    expect((await call(h, "POST", `/v1/actions/${s.actionId}/execution`, s.agentToken, { status: "started" })).status).toBe(409);
  });

  it("is idempotent; body is optional", async () => {
    const s = await pending();
    expect((await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken, {})).status).toBe(200);
    const again = await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken);
    expect(again.status).toBe(200);
    expect(again.json.approval.status).toBe("cancelled");
    const audit = await h.database.db.select().from(auditLogs).where(eq(auditLogs.event, "approval.cancelled"));
    expect(audit).toHaveLength(1);
  });

  it("already approved → 409 with the current approval (cannot un-approve by cancel race)", async () => {
    const s = await pending();
    await call(h, "POST", `/v1/approvals/${s.id}/approve`, s.deviceToken, { device_id: s.deviceId });
    const r = await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken, {});
    expect(r.status).toBe(409);
    expect(r.json.error.code).toBe("approval_already_resolved");
  });

  it("wrong session → 403; other user → 404; device token → 403", async () => {
    const s = await pending();
    expect((await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken, { session_id: "ses_other" })).status).toBe(403);
    const other = await setup(h, "mallory@example.com");
    expect((await call(h, "POST", `/v1/approvals/${s.id}/cancel`, other.agentToken, {})).status).toBe(404);
    expect((await call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.deviceToken, {})).status).toBe(403);
    const detail = await call(h, "GET", `/v1/approvals/${s.id}`, s.deviceToken);
    expect(detail.json.approval.status).toBe("pending");
  });

  it("concurrent cancel + approve: exactly one wins", async () => {
    const s = await pending();
    const [c, a] = await Promise.all([
      call(h, "POST", `/v1/approvals/${s.id}/cancel`, s.agentToken, {}),
      call(h, "POST", `/v1/approvals/${s.id}/approve`, s.deviceToken, { device_id: s.deviceId }),
    ]);
    expect([c.status, a.status].filter((x) => x === 200)).toHaveLength(1);
  });
});
