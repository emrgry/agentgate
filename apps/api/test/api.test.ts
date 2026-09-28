import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { computeActionHash, MemoryNonceStore, verifyApprovalToken } from "@agentgate/core";
import { ActivityResponse, ApprovalDetail, ResolveApprovalResponse, SubmitActionResponse } from "@agentgate/protocol";
import { call, createHarness, draft, login, setup, submitBody, type Harness } from "./helpers.ts";

let h: Harness;
beforeEach(async () => {
  h = await createHarness();
});
afterEach(async () => {
  await h.close();
});

describe("auth", () => {
  it("rejects unauthenticated and wrong-audience requests", async () => {
    expect((await call(h, "GET", "/v1/approvals")).status).toBe(401);
    expect((await call(h, "GET", "/v1/approvals", "garbage.token.x")).json.error.code).toBe("unauthorized");
    const agentToken = await login(h, "agent");
    const r = await call(h, "POST", "/v1/devices", agentToken, { name: "x", platform: "ios", push_token: null });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("wrong_client");
  });

  it("serves the public signing key", async () => {
    const r = await call(h, "GET", "/v1/keys");
    expect(r.status).toBe(200);
    expect(r.json.approval_signing_key.alg).toBe("Ed25519");
    expect(r.json.approval_signing_key.pem).toContain("BEGIN PUBLIC KEY");
  });
});

describe("approval flow", () => {
  it("ask → approve → token verifies against /v1/keys", async () => {
    const s = await setup(h);
    const body = submitBody(s.sessionId, { ttl: 5 });
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, body);
    expect(sub.status).toBe(201);
    const record = SubmitActionResponse.parse(sub.json);
    expect(record.policy_decision).toBe("ask");
    expect(record.approval?.status).toBe("pending");
    // TTL clamped to the 30 s minimum.
    expect(Date.parse(record.approval!.expires_at) - Date.parse(record.approval!.requested_at)).toBe(30_000);

    // Push sent to the registered device.
    await new Promise((r) => setTimeout(r, 10));
    expect(h.push.sent).toHaveLength(1);
    expect(h.push.sent[0]).toMatchObject({
      title: "AgentGate",
      body: "Claude Code needs approval · HIGH",
      data: {
        approval_id: record.approval!.approval_id,
        url: `agentgate://approvals/${record.approval!.approval_id}`,
        server_fingerprint: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
      },
    });

    expect(JSON.stringify(h.push.sent[0])).not.toContain("git push"); // no command on the lock screen

    const id = record.approval!.approval_id;
    const inbox = await call(h, "GET", "/v1/approvals?status=pending", s.deviceToken);
    expect(inbox.json.items.map((i: any) => i.approval.approval_id)).toEqual([id]);

    const detail = await call(h, "GET", `/v1/approvals/${id}`, s.deviceToken);
    expect(ApprovalDetail.parse(detail.json).action.action.command).toBe("git push origin main");

    const res = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    expect(res.status).toBe(200);
    const resolved = ResolveApprovalResponse.parse(res.json);
    expect(resolved.approval.status).toBe("approved");
    expect(resolved.approval.resolved_by_device_id).toBe(s.deviceId);

    const keys = await call(h, "GET", "/v1/keys");
    const nonces = new MemoryNonceStore();
    const verify = () =>
      verifyApprovalToken(resolved.approval_token!, {
        publicKeyPem: keys.json.approval_signing_key.pem,
        expectedActionHash: computeActionHash(draft(s.sessionId)),
        expectedApprovalId: id,
        now: h.clock.now(),
        nonceStore: nonces,
      });
    const v = verify();
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.payload.session_id).toBe(s.sessionId);
      // expires_at = min(approval expiry + 60 s, now + 5 min)
      expect(Date.parse(v.payload.expires_at)).toBe(Date.parse(record.approval!.expires_at) + 60_000);
    }
    expect(verify()).toEqual({ ok: false, reason: "replayed" });

    // A different command cannot use this approval.
    const other = verifyApprovalToken(resolved.approval_token!, {
      publicKeyPem: keys.json.approval_signing_key.pem,
      expectedActionHash: computeActionHash(draft(s.sessionId, "git push --force origin main")),
      now: h.clock.now(),
    });
    expect(other).toEqual({ ok: false, reason: "hash_mismatch" });

    // Reconnecting daemon can recover the identical token via GET.
    const agentView = await call(h, "GET", `/v1/approvals/${id}`, s.agentToken);
    expect(agentView.json.approval_token).toBe(resolved.approval_token);

    // Execution lifecycle.
    const started = await call(h, "POST", `/v1/actions/${record.action.action_id}/execution`, s.agentToken, { status: "started" });
    expect(started.json.execution).toBe("started");
    const done = await call(h, "POST", `/v1/actions/${record.action.action_id}/execution`, s.agentToken, {
      status: "completed",
      exit_code: 0,
    });
    expect(done.json.execution).toBe("completed");

    const activity = ActivityResponse.parse((await call(h, "GET", "/v1/activity?limit=50", s.deviceToken)).json);
    const events = activity.items.map((i) => i.event);
    expect(events.slice(0, 6)).toEqual([
      "execution.completed",
      "execution.started",
      "approval.approved",
      "approval.viewed",
      "approval.requested",
      "action.reported",
    ]);
    expect(activity.items.find((i) => i.event === "approval.approved")!.summary).toBe("git push origin main — approved");
    expect(activity.items[0]!.summary).toBe("git push origin main — completed (exit 0)");
  });

  it("deny path returns no token and blocks execution start", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    const res = await call(h, "POST", `/v1/approvals/${id}/deny`, s.deviceToken, { device_id: s.deviceId });
    expect(res.status).toBe(200);
    expect(res.json.approval.status).toBe("denied");
    expect(res.json.approval.decision).toBe("deny");
    expect(res.json.approval_token).toBeNull();

    const start = await call(h, "POST", `/v1/actions/${sub.json.action.action_id}/execution`, s.agentToken, { status: "started" });
    expect(start.status).toBe(409);
    expect(start.json.error.code).toBe("not_approved");
  });

  it("double approve → 409", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    const [a, b] = await Promise.all([
      call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId }),
      call(h, "POST", `/v1/approvals/${id}/deny`, s.deviceToken, { device_id: s.deviceId }),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    const again = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe("approval_already_resolved");
    expect(again.json.approval.approval_id).toBe(id);
  });

  it("rejects a device that belongs to another user", async () => {
    const s = await setup(h);
    const other = await setup(h, "other@example.com");
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    const r = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: other.deviceId });
    expect(r.status).toBe(403);
    // …and other users cannot see the approval at all.
    const r2 = await call(h, "POST", `/v1/approvals/${id}/approve`, other.deviceToken, { device_id: other.deviceId });
    expect(r2.status).toBe(404);
  });

  it("expiry: sweeper expires, late approve → 409 approval_expired", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;

    h.clock.advance(119_000);
    expect(await h.sweep()).toBe(0);
    h.clock.advance(1_000);
    expect(await h.sweep()).toBe(1);

    const late = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    expect(late.status).toBe(409);
    expect(late.json.error.code).toBe("approval_expired");
    expect(late.json.approval.status).toBe("expired");

    const inbox = await call(h, "GET", "/v1/approvals?status=pending", s.deviceToken);
    expect(inbox.json.items).toEqual([]);
  });

  it("expiry: a decision arriving after expires_at (before the sweeper) is expired by the state machine", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId, { ttl: 60 }));
    const id = sub.json.approval.approval_id;
    h.clock.advance(60_000);
    const late = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    expect(late.status).toBe(409);
    expect(late.json.error.code).toBe("approval_expired");
    expect(late.json.approval.decision).toBeNull();
  });

  it("hash_mismatch → 400", async () => {
    const s = await setup(h);
    const body = submitBody(s.sessionId);
    body.action_hash = computeActionHash(draft(s.sessionId, "echo harmless"));
    const r = await call(h, "POST", "/v1/actions", s.agentToken, body);
    expect(r.status).toBe(400);
    expect(r.json.error.code).toBe("hash_mismatch");
  });

  it("allow / deny decisions create no approval and are audited", async () => {
    const s = await setup(h);
    const allow = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId, { decision: "allow", command: "ls" }));
    expect(allow.json.approval).toBeNull();
    const deny = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId, { decision: "deny", command: "rm -rf /" }));
    expect(deny.json.execution).toBe("blocked");
    const events = (await call(h, "GET", "/v1/activity", s.deviceToken)).json.items.map((i: any) => i.summary);
    expect(events).toContain("ls — allowed by policy");
    expect(events).toContain("rm -rf / — denied by policy");
    expect(h.push.sent).toHaveLength(0);
  });

  it("session end cancels pending approvals", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    const id = sub.json.approval.approval_id;
    const end = await call(h, "POST", `/v1/sessions/${s.sessionId}/end`, s.agentToken);
    expect(end.status).toBe(200);
    expect(end.json.status).toBe("ended");
    const detail = await call(h, "GET", `/v1/approvals/${id}`, s.deviceToken);
    expect(detail.json.approval.status).toBe("cancelled");
    const approve = await call(h, "POST", `/v1/approvals/${id}/approve`, s.deviceToken, { device_id: s.deviceId });
    expect(approve.status).toBe(409);
    const more = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    expect(more.status).toBe(409);
    expect(more.json.error.code).toBe("session_ended");
    const actions = await call(h, "GET", `/v1/sessions/${s.sessionId}/actions`, s.deviceToken);
    expect(actions.json.items).toHaveLength(1);
  });

  it("push failure never fails the request", async () => {
    const s = await setup(h);
    h.push.fail = true;
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId));
    expect(sub.status).toBe(201);
  });

  it("explicit POST /v1/approvals for an existing action", async () => {
    const s = await setup(h);
    const sub = await call(h, "POST", "/v1/actions", s.agentToken, submitBody(s.sessionId, { decision: "allow" }));
    const r = await call(h, "POST", "/v1/approvals", s.agentToken, { action_id: sub.json.action.action_id, ttl_seconds: 300 });
    expect(r.status).toBe(201);
    expect(r.json.approval.status).toBe("pending");
    const dup = await call(h, "POST", "/v1/approvals", s.agentToken, { action_id: sub.json.action.action_id });
    expect(dup.status).toBe(409);
  });
});
