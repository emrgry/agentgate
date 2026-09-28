import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { PairingPollResponse } from "@agentgate/protocol";
import { auditLogs } from "../src/db/schema.ts";
import { createHarness, type Harness } from "./helpers.ts";

/** Multi-machine: remote agent login needs phone approval; tailscale-serve proxying is remote. */

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
    headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}), ...o.headers },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

const EMAIL = "dev@example.com";
const TS_PROXY: Record<string, string> = { "x-forwarded-for": "100.101.102.103", "tailscale-user-login": "dev@github", "x-forwarded-proto": "https" };
const remoteLogin = (o: { ip?: string; headers?: Record<string, string> } = { ip: "100.101.102.103" }) =>
  inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent", machine_name: "Work Laptop", platform: "linux" }, o);

/** Local agent + bootstrap phone. */
async function withPhone(trustedProxies: string[] = ["127.0.0.1/32", "::1/128"]) {
  h = await createHarness({ openDeviceLogin: false, trustedProxies });
  await h.app.ready();
  const local = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" });
  expect(local.status).toBe(200);
  const code = (await inject("POST", "/v1/pairing", {}, { token: local.json.access_token })).json.code;
  const phone = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: code, device_name: "iPhone" });
  expect(phone.status).toBe(200);
  await inject("POST", "/v1/devices", { name: "iPhone", platform: "ios", push_token: "ExponentPushToken[p]" }, { token: phone.json.access_token });
  return { phone: { token: phone.json.access_token as string, id: phone.json.device_id as string } };
}

const poll = (id: string, secret: string) => inject("GET", `/v1/pairing/requests/${id}`, undefined, { headers: { "x-pairing-secret": secret } });

describe("remote agent login", () => {
  it("another computer → 202 → phone approves → poll returns agent token + refresh token once", async () => {
    const { phone } = await withPhone();
    const r = await remoteLogin();
    expect(r.status).toBe(202);
    expect(r.json.status).toBe("pending_approval");

    const pending = await inject("GET", "/v1/pairing/requests?status=pending", undefined, { token: phone.token });
    expect(pending.json.items).toEqual([
      expect.objectContaining({ id: r.json.pairing_request_id, kind: "agent", machine_name: "Work Laptop", device_name: "Work Laptop", platform: "linux", ip: "100.101.102.103" }),
    ]);
    expect(h!.push.sent.at(-1)).toMatchObject({ body: "New computer wants to run agents: Work Laptop", data: { pairing_request_id: r.json.pairing_request_id } });

    const ok = await inject("POST", `/v1/pairing/requests/${r.json.pairing_request_id}/approve`, { device_id: phone.id }, { token: phone.token });
    expect(ok.status).toBe(200);
    expect(ok.json.request.kind).toBe("agent");

    const p = PairingPollResponse.parse((await poll(r.json.pairing_request_id, r.json.poll_secret)).json);
    expect(p.status).toBe("approved");
    expect(p.login?.refresh_token).toMatch(/^agr_/);
    expect(p.login?.device_id).toBeUndefined();
    expect((await poll(r.json.pairing_request_id, r.json.poll_secret)).json.login).toBeNull();

    // it is a working agent token (not a device token), and refresh works
    const agent = await inject("POST", "/v1/agents", { name: "laptop", type: "cli", machine_id: "m2" }, { token: p.login!.access_token, ip: "100.101.102.103" });
    expect(agent.status).toBe(201);
    expect((await inject("GET", "/v1/pairing/requests", undefined, { token: p.login!.access_token })).status).toBe(403);
    expect((await inject("POST", "/v1/auth/refresh", { refresh_token: p.login!.refresh_token }, { ip: "100.101.102.103" })).status).toBe(200);

    const events = (await h!.database.db.select().from(auditLogs)).map((a) => a.event);
    expect(events).toEqual(expect.arrayContaining(["agent.login_requested", "agent.login_approved"]));
    const summaries = (await inject("GET", "/v1/activity", undefined, { token: phone.token })).json.items.map((i: any) => i.summary);
    expect(summaries).toEqual(expect.arrayContaining(["Computer login requested: Work Laptop from 100.101.102.103", "Computer login approved by iPhone: Work Laptop"]));
  });

  it("deny → poll says denied, no token", async () => {
    const { phone } = await withPhone();
    const r = await remoteLogin();
    await inject("POST", `/v1/pairing/requests/${r.json.pairing_request_id}/deny`, { device_id: phone.id }, { token: phone.token });
    expect((await poll(r.json.pairing_request_id, r.json.poll_secret)).json).toEqual({ status: "denied", login: null });
    expect((await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, "agent.login_denied")))).toHaveLength(1);
  });

  it("no paired device (or unknown user) → 403 pair_phone_first, no user created", async () => {
    h = await createHarness({ openDeviceLogin: false });
    await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" }); // local login, but no phone
    expect((await remoteLogin()).json.error.code).toBe("pair_phone_first");
    const unknown = await inject("POST", "/v1/auth/login", { email: "nobody@example.com", client: "agent" }, { ip: "100.64.0.9" });
    expect(unknown.status).toBe(403);
    expect(unknown.json.error.code).toBe("pair_phone_first");
  });

  it("request proxied by tailscale serve (loopback + forwarded headers) is REMOTE", async () => {
    await withPhone();
    const variants: Record<string, string>[] = [TS_PROXY, { "tailscale-user-login": "dev@github" }, { "x-forwarded-for": "100.1.2.3" }, { forwarded: "for=100.1.2.3" }];
    for (const headers of variants) {
      const r = await remoteLogin({ ip: "127.0.0.1", headers });
      expect([JSON.stringify(headers), r.status]).toEqual([JSON.stringify(headers), 202]);
    }
    const r = await remoteLogin({ ip: "127.0.0.1", headers: TS_PROXY });
    const req = (await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, "agent.login_requested"))).at(-1)!;
    expect((req.payload_json as any).ip).toBe("100.101.102.103"); // real client IP from X-Forwarded-For
    expect(r.status).toBe(202);
  });

  it("direct loopback (no forwarding headers) stays local → 200 immediately", async () => {
    await withPhone();
    const r = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" }, { ip: "127.0.0.1" });
    expect(r.status).toBe(200);
    expect(r.json.refresh_token).toMatch(/^agr_/);
    expect((await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" }, { ip: "::1" })).status).toBe(200);
  });

  it("proxied requests are remote even when the proxy is NOT trusted (default TRUSTED_PROXIES=none)", async () => {
    await withPhone([]);
    const r = await remoteLogin({ ip: "127.0.0.1", headers: TS_PROXY });
    expect(r.status).toBe(202);
    const req = (await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, "agent.login_requested"))).at(-1)!;
    expect((req.payload_json as any).ip).toBe("127.0.0.1"); // untrusted → header ignored for the IP
  });

  it("X-Forwarded-For: right-most untrusted hop wins; client-supplied left entries are ignored", async () => {
    await withPhone(["127.0.0.1/32", "10.0.0.0/8"]);
    await remoteLogin({ ip: "127.0.0.1", headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.7, 10.1.2.3" } });
    const req = (await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, "agent.login_requested"))).at(-1)!;
    expect((req.payload_json as any).ip).toBe("203.0.113.7");
  });

  it("forwarded headers from a NON-trusted peer are ignored (cannot spoof the client IP)", async () => {
    await withPhone();
    await remoteLogin({ ip: "100.70.0.5", headers: { "x-forwarded-for": "127.0.0.1" } });
    const req = (await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, "agent.login_requested"))).at(-1)!;
    expect((req.payload_json as any).ip).toBe("100.70.0.5");
  });

  it("rate limiting keys on the real client behind the proxy", async () => {
    h = await createHarness({ openDeviceLogin: false, trustedProxies: ["127.0.0.1/32"], rateLimit: { authPerMinute: 2, defaultPerMinute: 100 } });
    const via = (xff: string) => inject("POST", "/v1/auth/login", { email: "x@example.com", client: "device", pairing_code: "AAAAAAAA" }, { ip: "127.0.0.1", headers: { "x-forwarded-for": xff } });
    expect([(await via("100.1.1.1")).status, (await via("100.1.1.1")).status, (await via("100.1.1.1")).status]).toEqual([401, 401, 429]);
    expect((await via("100.2.2.2")).status).toBe(401); // different tailnet client, own bucket
  });
});

describe("ProxyPolicy", () => {
  it("parses CIDRs, rejects garbage", async () => {
    const { ProxyPolicy } = await import("../src/http/client-ip.ts");
    const p = new ProxyPolicy(["10.0.0.0/8", "::1", "fd00::/8"]);
    expect(p.isTrusted("10.9.9.9")).toBe(true);
    expect(p.isTrusted("::ffff:10.9.9.9")).toBe(true);
    expect(p.isTrusted("11.0.0.1")).toBe(false);
    expect(p.isTrusted("::1")).toBe(true);
    expect(p.isTrusted("fd12::1")).toBe(true);
    expect(() => new ProxyPolicy(["nope"])).toThrow(/TRUSTED_PROXIES/);
    expect(() => new ProxyPolicy(["10.0.0.0/33"])).toThrow(/prefix/);
  });
});
