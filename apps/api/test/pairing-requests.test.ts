import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { ListDevicesResponse, PairingPollResponse, ServerEvent } from "@agentgate/protocol";
import { auditLogs, devices } from "../src/db/schema.ts";
import { PAIRING_REQUEST_TTL_MS } from "../src/domain/pairing.ts";
import { signAccessToken } from "../src/auth/tokens.ts";
import { createHarness, submitBody, type Harness } from "./helpers.ts";

/** C2 residual: a new device can only pair if an already-paired device approves it. */

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

type R = { status: number; json: any };
async function inject(method: "GET" | "POST", url: string, body?: unknown, o: { token?: string; ip?: string; headers?: Record<string, string> } = {}): Promise<R> {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: o.ip ?? "127.0.0.1",
    headers: {
      ...(o.token ? { authorization: `Bearer ${o.token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...o.headers,
    },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

const EMAIL = "dev@example.com";
async function agent() {
  return (await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" })).json.access_token as string;
}
async function code(agentToken: string) {
  return (await inject("POST", "/v1/pairing", {}, { token: agentToken })).json.code as string;
}
const deviceLogin = (pairing_code: string, device_name = "iPhone 15 Pro", ip = "192.168.1.110") =>
  inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code, device_name, platform: "ios" }, { ip });
const poll = (id: string, secret: string) => inject("GET", `/v1/pairing/requests/${id}`, undefined, { headers: { "x-pairing-secret": secret } });

/** First device (bootstrap) → {token, id}; then a pending second device. */
async function pairedUser() {
  h = await createHarness({ openDeviceLogin: false });
  const a = await agent();
  const first = await deviceLogin(await code(a), "Alex's iPhone");
  expect(first.status).toBe(200);
  return { a, first: { token: first.json.access_token as string, id: first.json.device_id as string } };
}
async function pending(a: string, name = "iPad") {
  const r = await deviceLogin(await code(a), name, "192.168.1.111");
  expect(r.status).toBe(202);
  return r.json as { status: string; pairing_request_id: string; poll_secret: string; expires_at: string };
}
const events = async (event: string) =>
  (await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, event))).map((r) => r.payload_json as Record<string, unknown>);

describe("bootstrap", () => {
  it("first device of a user: 200 LoginResponse with device_id, did-bound token, device.paired{bootstrap}", async () => {
    const { first } = await pairedUser();
    const list = await inject("GET", "/v1/devices", undefined, { token: first.token });
    expect(list.status).toBe(200);
    const items = ListDevicesResponse.parse(list.json).items;
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: first.id, name: "Alex's iPhone", platform: "ios", current: true, revoked_at: null, has_push: false });
    expect(await events("device.paired")).toEqual([expect.objectContaining({ bootstrap: true, device_id: first.id })]);
    const activity = await inject("GET", "/v1/activity", undefined, { token: first.token });
    expect(activity.json.items.map((i: any) => i.summary)).toContain("New device paired: Alex's iPhone (bootstrap)");
  });

  it("defaults device_name/platform", async () => {
    h = await createHarness({ openDeviceLogin: false });
    const r = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: await code(await agent()) });
    expect(r.status).toBe(200);
    const [d] = await h.database.db.select().from(devices);
    expect(d).toMatchObject({ name: "Unnamed device", platform: "ios" });
  });
});

describe("second device needs approval", () => {
  it("202 → pairing.requested on WS + push → first device approves → poll returns login exactly once", async () => {
    const { a, first } = await pairedUser();
    await inject("POST", "/v1/devices", { name: "Alex's iPhone", platform: "ios", push_token: "ExponentPushToken[first]" }, { token: first.token });

    await h!.app.listen({ port: 0, host: "127.0.0.1" });
    const port = (h!.app.server.address() as { port: number }).port;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/device/connect`, { headers: { authorization: `Bearer ${first.token}` } });
    const got: ServerEvent[] = [];
    ws.on("message", (d) => got.push(ServerEvent.parse(JSON.parse(d.toString()))));
    await new Promise((r) => ws.once("open", r));

    const p = await pending(a);
    expect(p.status).toBe("pending_approval");
    expect(p.poll_secret.length).toBeGreaterThanOrEqual(16);

    // pending: long-poll returns the current status after the window
    expect((await poll(p.pairing_request_id, p.poll_secret)).json).toEqual({ status: "pending", login: null });

    await new Promise((r) => setTimeout(r, 50));
    const requested = got.find((e) => e.type === "pairing.requested");
    expect(requested).toMatchObject({ request: { id: p.pairing_request_id, device_name: "iPad", ip: "192.168.1.111", status: "pending" } });
    expect(h!.push.sent.at(-1)).toMatchObject({
      to: "ExponentPushToken[first]",
      title: "AgentGate",
      body: "New device wants to pair: iPad",
      data: { url: `agentgate://pairing/${p.pairing_request_id}`, pairing_request_id: p.pairing_request_id },
    });

    const list = await inject("GET", "/v1/pairing/requests?status=pending", undefined, { token: first.token });
    expect(list.json.items.map((i: any) => i.id)).toEqual([p.pairing_request_id]);

    // a long-poll in flight resolves early when the first device approves
    const inflight = poll(p.pairing_request_id, p.poll_secret);
    await new Promise((r) => setTimeout(r, 30));
    const ok = await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: first.token });
    expect(ok.status).toBe(200);
    expect(ok.json.request).toMatchObject({ status: "approved" });
    const first_ = PairingPollResponse.parse((await inflight).json);
    expect(first_.status).toBe("approved");
    expect(first_.login?.device_id).toMatch(/^dev_/);
    const later = await poll(p.pairing_request_id, p.poll_secret);
    expect(later.json).toEqual({ status: "approved", login: null });

    // the new device's token works and is bound to its own device
    const devs = await inject("GET", "/v1/devices", undefined, { token: first_.login!.access_token });
    expect(devs.json.items.find((d: any) => d.current)).toMatchObject({ id: first_.login!.device_id, name: "iPad" });

    await new Promise((r) => setTimeout(r, 50));
    expect(got.some((e) => e.type === "pairing.resolved" && e.request.status === "approved")).toBe(true);
    ws.close();

    const summaries = (await inject("GET", "/v1/activity", undefined, { token: first.token })).json.items.map((i: any) => i.summary);
    expect(summaries).toEqual(
      expect.arrayContaining([
        "Device pairing requested: iPad from 192.168.1.111",
        "Device pairing approved by Alex's iPhone: iPad",
        "New device paired: iPad",
        "Pairing code created",
      ]),
    );
  });

  it("login is delivered exactly once under concurrent polls", async () => {
    const { a, first } = await pairedUser();
    const p = await pending(a);
    await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: first.token });
    const results = await Promise.all(Array.from({ length: 8 }, () => poll(p.pairing_request_id, p.poll_secret)));
    expect(results.every((r) => r.status === 200 && r.json.status === "approved")).toBe(true);
    expect(results.filter((r) => r.json.login !== null)).toHaveLength(1);
    const rows = await h!.database.db.select().from(devices);
    expect(rows).toHaveLength(2);
  });

  it("deny → poll says denied, no login, no device", async () => {
    const { a, first } = await pairedUser();
    const p = await pending(a);
    const d = await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/deny`, { device_id: first.id }, { token: first.token });
    expect(d.status).toBe(200);
    expect((await poll(p.pairing_request_id, p.poll_secret)).json).toEqual({ status: "denied", login: null });
    expect(await h!.database.db.select().from(devices)).toHaveLength(1);
    expect((await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: first.token })).json.error.code).toBe(
      "pairing_request_already_resolved",
    );
  });

  it("expiry → poll says expired; late approve → 409 pairing_request_expired", async () => {
    const { a, first } = await pairedUser();
    const p = await pending(a);
    h!.clock.advance(PAIRING_REQUEST_TTL_MS + 1);
    expect((await poll(p.pairing_request_id, p.poll_secret)).json).toEqual({ status: "expired", login: null });
    const late = await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: first.token });
    expect(late.status).toBe(409);
    expect(late.json.error.code).toBe("pairing_request_expired");
  });

  it("wrong / missing secret or unknown id → 404", async () => {
    const { a } = await pairedUser();
    const p = await pending(a);
    expect((await poll(p.pairing_request_id, "x".repeat(43))).status).toBe(404);
    expect((await inject("GET", `/v1/pairing/requests/${p.pairing_request_id}`)).status).toBe(404);
    expect((await poll("prq_nope", p.poll_secret)).status).toBe(404);
  });

  it("agent token cannot list/approve pairing requests (403); device_id must be the caller's", async () => {
    const { a, first } = await pairedUser();
    const p = await pending(a);
    expect((await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: a })).status).toBe(403);
    expect((await inject("GET", "/v1/pairing/requests", undefined, { token: a })).status).toBe(403);
    // a did-bound token cannot act as another device
    const other = h!.database.db;
    const [second] = await other.insert(devices).values({ id: "dev_other", user_id: (await other.select().from(devices))[0]!.user_id, name: "x", platform: "ios", push_token: null, created_at: new Date() }).returning();
    expect((await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: second!.id }, { token: first.token })).status).toBe(403);
    expect((await poll(p.pairing_request_id, p.poll_secret)).json.status).toBe("pending");
  });
});

describe("revocation", () => {
  it("revoked device token → 401 device_revoked on every route incl. WS; socket dropped; audited", async () => {
    const { a, first } = await pairedUser();
    const p = await pending(a);
    await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: first.token });
    const second = PairingPollResponse.parse((await poll(p.pairing_request_id, p.poll_secret)).json).login!;

    await h!.app.listen({ port: 0, host: "127.0.0.1" });
    const port = (h!.app.server.address() as { port: number }).port;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/device/connect`, { headers: { authorization: `Bearer ${second.access_token}` } });
    await new Promise((r) => ws.once("open", r));
    const closed = new Promise<number>((r) => ws.once("close", (code) => r(code)));

    const rv = await inject("POST", `/v1/devices/${second.device_id}/revoke`, {}, { token: first.token });
    expect(rv.status).toBe(200);
    expect(rv.json.device).toMatchObject({ id: second.device_id, revoked_at: expect.any(String), has_push: false, current: false });
    expect(await closed).toBe(4001);

    const t = second.access_token;
    for (const [m, u] of [
      ["GET", "/v1/devices"],
      ["GET", "/v1/approvals"],
      ["GET", "/v1/activity"],
      ["GET", "/v1/pairing/requests"],
    ] as const) {
      const r = await inject(m, u, undefined, { token: t });
      expect([u, r.status, r.json.error?.code]).toEqual([u, 401, "device_revoked"]);
    }
    const ag = await inject("POST", "/v1/agents", { name: "m", type: "cli", machine_id: "m" }, { token: a });
    const ses = await inject("POST", "/v1/sessions", { agent_id: ag.json.id }, { token: a });
    const act = await inject("POST", "/v1/actions", submitBody(ses.json.id), { token: a });
    const apr = act.json.approval.approval_id;
    expect((await inject("POST", `/v1/approvals/${apr}/approve`, { device_id: second.device_id }, { token: t })).status).toBe(401);
    const wsRej = await new Promise<number>((resolve) => {
      const w = new WebSocket(`ws://127.0.0.1:${port}/v1/device/connect`, { headers: { authorization: `Bearer ${t}` } });
      w.once("unexpected-response", (_q, res) => resolve(res.statusCode ?? 0));
      w.once("open", () => resolve(101));
    });
    expect(wsRej).toBe(401);
    expect(await events("device.revoked")).toEqual([expect.objectContaining({ device_id: second.device_id, name: "iPad", by_device_id: first.id })]);
  });

  it("a revoked device cannot approve a pairing request, even with a legacy (no did) token", async () => {
    const { a, first } = await pairedUser();
    // legacy token (pre-pairing) for the same user, naming the first device
    const [row] = await h!.database.db.select().from(devices);
    const legacy = signAccessToken("test-secret-test-secret-test-secret", { sub: row!.user_id, email: EMAIL, aud: "device" }, h!.clock.now()).token;
    const p = await pending(a);
    await inject("POST", `/v1/devices/${first.id}/revoke`, {}, { token: first.token });
    const r = await inject("POST", `/v1/pairing/requests/${p.pairing_request_id}/approve`, { device_id: first.id }, { token: legacy });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe("device_revoked");
    expect((await poll(p.pairing_request_id, p.poll_secret)).json.status).toBe("pending");
    // revoking the last device → the next login is a bootstrap again
    expect((await deviceLogin(await code(a), "New phone")).status).toBe(200);
  });

  it("legacy device tokens (no did) keep working", async () => {
    h = await createHarness({ openDeviceLogin: true });
    const legacy = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device" });
    expect(legacy.json.device_id).toBeUndefined();
    const reg = await inject("POST", "/v1/devices", { name: "old", platform: "ios", push_token: null }, { token: legacy.json.access_token });
    expect(reg.status).toBe(201);
    expect((await inject("GET", "/v1/devices", undefined, { token: legacy.json.access_token })).json.items[0]).toMatchObject({ current: false });
    expect((await inject("GET", "/v1/approvals", undefined, { token: legacy.json.access_token })).status).toBe(200);
  });
});
