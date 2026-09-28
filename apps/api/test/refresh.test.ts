import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { auditLogs, refreshTokens } from "../src/db/schema.ts";
import { REFRESH_REUSE_AUDIT_EVENT, REFRESH_TTL_MS } from "../src/domain/refresh.ts";
import { call, createHarness, type Harness } from "./helpers.ts";

let h: Harness;
beforeEach(async () => {
  h = await createHarness();
});
afterEach(async () => {
  await h.close();
});

async function agentLogin(email = "dev@example.com") {
  const r = await call(h, "POST", "/v1/auth/login", undefined, { email, client: "agent" });
  expect(r.status).toBe(200);
  return r.json as { access_token: string; expires_at: string; refresh_token: string; user: { id: string } };
}
const refresh = (token: string) => call(h, "POST", "/v1/auth/refresh", undefined, { refresh_token: token });

describe("refresh tokens", () => {
  it("agent login returns a refresh token; unbound (open, dev-only) device login does not", async () => {
    const a = await agentLogin();
    expect(a.refresh_token).toMatch(/^agr_/);
    const d = await call(h, "POST", "/v1/auth/login", undefined, { email: "dev@example.com", client: "device" });
    expect(d.json.refresh_token).toBeUndefined();
  });

  it("stores only a hash of the token", async () => {
    const a = await agentLogin();
    const rows = await h.database.db.select().from(refreshTokens);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.token_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(rows)).not.toContain(a.refresh_token);
  });

  it("happy path: refresh yields a working agent access token and a NEW refresh token", async () => {
    const a = await agentLogin();
    h.clock.advance(61 * 60 * 1000); // access token (1 h) expired
    expect((await call(h, "POST", "/v1/sessions", a.access_token, { agent_id: "x" })).status).toBe(401);

    const r = await refresh(a.refresh_token);
    expect(r.status).toBe(200);
    expect(r.json.refresh_token).toMatch(/^agr_/);
    expect(r.json.refresh_token).not.toBe(a.refresh_token);
    expect(Date.parse(r.json.expires_at)).toBe(h.clock.now().getTime() + 3600_000);

    const agent = await call(h, "POST", "/v1/agents", r.json.access_token, { name: "m", type: "cli", machine_id: "m1" });
    expect(agent.status).toBe(201);
  });

  it("rotation: the new token works, chain continues", async () => {
    const a = await agentLogin();
    const r1 = await refresh(a.refresh_token);
    const r2 = await refresh(r1.json.refresh_token);
    const r3 = await refresh(r2.json.refresh_token);
    expect([r1.status, r2.status, r3.status]).toEqual([200, 200, 200]);
  });

  it("reuse detection: presenting a rotated token → 401 reused, whole family revoked, audited", async () => {
    const a = await agentLogin();
    const r1 = await refresh(a.refresh_token);
    expect(r1.status).toBe(200);

    const reuse = await refresh(a.refresh_token); // attacker (or a buggy client) replays the old one
    expect(reuse.status).toBe(401);
    expect(reuse.json.error.code).toBe("refresh_token_reused");

    // the legit successor is now revoked too
    const legit = await refresh(r1.json.refresh_token);
    expect(legit.status).toBe(401);
    expect(legit.json.error.code).toBe("refresh_token_revoked");

    const rows = await h.database.db.select().from(refreshTokens);
    expect(rows.every((r) => r.revoked_at !== null)).toBe(true);
    const audit = await h.database.db.select().from(auditLogs).where(eq(auditLogs.event, REFRESH_REUSE_AUDIT_EVENT));
    expect(audit).toHaveLength(1);
    expect(audit[0]!.user_id).toBe(a.user.id);

    // the internal event does not break the public activity feed
    const dev = await call(h, "POST", "/v1/auth/login", undefined, { email: "dev@example.com", client: "device" });
    expect((await call(h, "GET", "/v1/activity", dev.json.access_token)).status).toBe(200);
  });

  it("reuse revokes only that family (another login keeps working)", async () => {
    const a = await agentLogin();
    const b = await agentLogin();
    await refresh(a.refresh_token);
    await refresh(a.refresh_token); // reuse → family A revoked
    expect((await refresh(b.refresh_token)).status).toBe(200);
  });

  it("expired refresh token → 401 refresh_token_expired", async () => {
    const a = await agentLogin();
    h.clock.advance(REFRESH_TTL_MS + 1000);
    const r = await refresh(a.refresh_token);
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("refresh_token_expired");
  });

  it("unknown / malformed token → 401 / 400", async () => {
    expect((await refresh("agr_nope")).json.error.code).toBe("invalid_refresh_token");
    expect((await call(h, "POST", "/v1/auth/refresh", undefined, {})).status).toBe(400);
  });

  it("concurrent refreshes of the same token: exactly one wins, the other is treated as reuse", async () => {
    const a = await agentLogin();
    const [x, y] = await Promise.all([refresh(a.refresh_token), refresh(a.refresh_token)]);
    const statuses = [x.status, y.status].sort();
    expect(statuses).toEqual([200, 401]);
  });
});
