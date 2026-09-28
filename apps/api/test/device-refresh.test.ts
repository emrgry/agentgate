import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { LoginResponse, PairingPollResponse, RefreshResponse } from "@agentgate/protocol";
import { base64urlEncode, generateDeviceKeyPair, signRekey } from "@agentgate/signing";
import { verifyAccessToken } from "../src/auth/tokens.ts";
import { auditLogs, devices, refreshTokens } from "../src/db/schema.ts";
import { DEVICE_REFRESH_TTL_MS, REFRESH_REUSE_AUDIT_EVENT } from "../src/domain/refresh.ts";
import { createHarness, type Harness } from "./helpers.ts";

/** Phones get rotating refresh tokens too (access 12 h, refresh 90 d sliding, device-bound). */

const SECRET = "test-secret-test-secret-test-secret";
const EMAIL = "dev@example.com";
const GOOD = "/tmp/agentgate-recovery-testtesttesttest";
const rnd = (n: number) => new Uint8Array(randomBytes(n));

let h: Harness | null = null;
let proofNonce: string | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
  proofNonce = null;
});

type R = { status: number; json: any };
async function inject(method: "GET" | "POST", url: string, body?: unknown, o: { token?: string; headers?: Record<string, string> } = {}): Promise<R> {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: "127.0.0.1",
    headers: {
      ...(o.token ? { authorization: `Bearer ${o.token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...o.headers,
    },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

const refresh = (token: string) => inject("POST", "/v1/auth/refresh", { refresh_token: token });
const devicesList = (token: string) => inject("GET", "/v1/devices", undefined, { token });

async function setup() {
  h = await createHarness({ openDeviceLogin: false, recoveryProof: (p, n) => p === GOOD && n === proofNonce });
  const agent = (await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" })).json.access_token as string;
  const code = async () => (await inject("POST", "/v1/pairing", {}, { token: agent })).json.code as string;
  const kp = generateDeviceKeyPair(rnd);
  const r = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: await code(), device_name: "iPhone", platform: "ios", device_public_key: kp.publicKey });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
  return { agent, code, kp, phone: LoginResponse.parse(r.json) };
}

async function recovery(agent: string, body: { action: "revoke" | "reset"; device_id?: string }) {
  proofNonce = base64urlEncode(rnd(32));
  const r = await inject("POST", "/v1/devices/recovery", { ...body, nonce: proofNonce, proof_path: GOOD }, { token: agent });
  expect(r.status, JSON.stringify(r.json)).toBe(200);
  return r;
}

describe("device refresh tokens", () => {
  it("pairing-code login returns a device-bound refresh token (90 d)", async () => {
    const { phone } = await setup();
    expect(phone.refresh_token).toMatch(/^agr_/);
    expect(phone.device_id).toMatch(/^dev_/);
    const rows = await h!.database.db.select().from(refreshTokens).where(eq(refreshTokens.audience, "device"));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ device_id: phone.device_id, user_id: phone.user.id });
    expect(rows[0]!.expires_at.getTime() - rows[0]!.created_at.getTime()).toBe(DEVICE_REFRESH_TTL_MS);
  });

  it("after the 12 h access token expires, refresh yields a working device token bound to the same device + rotated refresh", async () => {
    const { phone } = await setup();
    h!.clock.advance(13 * 60 * 60 * 1000);
    expect((await devicesList(phone.access_token)).status).toBe(401);

    const r = await refresh(phone.refresh_token!);
    expect(r.status, JSON.stringify(r.json)).toBe(200);
    const body = RefreshResponse.parse(r.json);
    expect(body.device_id).toBe(phone.device_id);
    expect(body.refresh_token).not.toBe(phone.refresh_token);
    expect(Date.parse(body.expires_at)).toBe(h!.clock.now().getTime() + 12 * 3600_000);
    const claims = verifyAccessToken(SECRET, body.access_token, h!.clock.now());
    expect(claims).toMatchObject({ aud: "device", did: phone.device_id, sub: phone.user.id });

    const list = await devicesList(body.access_token);
    expect(list.status).toBe(200);
    expect(list.json.items.find((d: { id: string }) => d.id === phone.device_id).current).toBe(true);
    // device-only endpoint accepts it; agent-only endpoint doesn't
    expect((await inject("POST", "/v1/pairing", {}, { token: body.access_token })).status).toBe(403);
  });

  it("sliding 90 d lifetime: rotating every 60 d keeps the pairing alive; 91 d idle expires", async () => {
    const { phone } = await setup();
    let token = phone.refresh_token!;
    for (let i = 0; i < 3; i++) {
      h!.clock.advance(60 * 24 * 3600_000);
      const r = await refresh(token);
      expect(r.status).toBe(200);
      token = r.json.refresh_token;
    }
    h!.clock.advance(91 * 24 * 3600_000);
    const r = await refresh(token);
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("refresh_token_expired");
  });

  it("reuse detection: replaying a rotated device token revokes the family (audited)", async () => {
    const { phone } = await setup();
    const r1 = await refresh(phone.refresh_token!);
    expect(r1.status).toBe(200);
    const reuse = await refresh(phone.refresh_token!);
    expect(reuse.status).toBe(401);
    expect(reuse.json.error.code).toBe("refresh_token_reused");
    const legit = await refresh(r1.json.refresh_token);
    expect(legit.status).toBe(401);
    expect(legit.json.error.code).toBe("refresh_token_revoked");
    const audit = await h!.database.db.select().from(auditLogs).where(eq(auditLogs.event, REFRESH_REUSE_AUDIT_EVENT));
    expect(audit).toHaveLength(1);
  });

  it("revoked device (by another device): its refresh families are revoked → 401 device_revoked", async () => {
    const { phone, code } = await setup();
    // second phone, approved by the first
    const p = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: await code(), device_name: "iPad", platform: "ios" });
    expect(p.status).toBe(202);
    await inject("POST", `/v1/pairing/requests/${p.json.pairing_request_id}/approve`, { device_id: phone.device_id }, { token: phone.access_token });
    const polled = PairingPollResponse.parse((await inject("GET", `/v1/pairing/requests/${p.json.pairing_request_id}`, undefined, { headers: { "x-pairing-secret": p.json.poll_secret } })).json);
    const ipad = polled.login!;

    const rv = await inject("POST", `/v1/devices/${phone.device_id}/revoke`, {}, { token: ipad.access_token });
    expect(rv.status, JSON.stringify(rv.json)).toBe(200);
    const rows = await h!.database.db.select().from(refreshTokens).where(eq(refreshTokens.device_id, phone.device_id!));
    expect(rows.every((r) => r.revoked_at !== null)).toBe(true);
    const r = await refresh(phone.refresh_token!);
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("device_revoked");
    // the other device is unaffected
    expect((await refresh(ipad.refresh_token!)).status).toBe(200);
  });

  it("device revoked directly in the DB (no family revoke): refresh still 401 device_revoked", async () => {
    const { phone } = await setup();
    await h!.database.db.update(devices).set({ revoked_at: new Date() }).where(eq(devices.id, phone.device_id!));
    const r = await refresh(phone.refresh_token!);
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("device_revoked");
  });

  it("local recovery revoke → refresh 401 device_revoked", async () => {
    const { agent, phone } = await setup();
    await recovery(agent, { action: "revoke", device_id: phone.device_id! });
    expect((await refresh(phone.refresh_token!)).json.error.code).toBe("device_revoked");
  });

  it("recovery reset → refresh 401; next pairing is a bootstrap with a working refresh token", async () => {
    const { agent, phone, code } = await setup();
    await recovery(agent, { action: "reset" });
    const r = await refresh(phone.refresh_token!);
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("device_revoked");
    const fresh = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: await code(), device_name: "iPhone", platform: "ios" });
    expect(fresh.status).toBe(200);
    expect((await refresh(fresh.json.refresh_token)).status).toBe(200);
  });

  it("rekey returns a working refresh token; pre-rekey refresh tokens die; a later revoke kills the new family", async () => {
    const { agent, phone, kp } = await setup();
    const now = h!.clock.now().getTime();
    const next = generateDeviceKeyPair(rnd);
    const body = signRekey(
      { device_id: phone.device_id!, new_public_key: next.publicKey, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 120_000).toISOString(), nonce: base64urlEncode(rnd(18)) },
      kp.privateKey,
    );
    const rk = await inject("POST", `/v1/devices/${phone.device_id}/rekey`, body);
    expect(rk.status, JSON.stringify(rk.json)).toBe(200);
    const login = LoginResponse.parse(rk.json);
    expect(login.refresh_token).toMatch(/^agr_/);

    const old = await refresh(phone.refresh_token!);
    expect(old.status).toBe(401);
    expect(old.json.error.code).toBe("refresh_token_revoked");

    const r = await refresh(login.refresh_token!);
    expect(r.status).toBe(200);
    expect(r.json.device_id).toBe(phone.device_id);
    expect((await devicesList(r.json.access_token)).status).toBe(200);

    await recovery(agent, { action: "revoke", device_id: phone.device_id! });
    expect((await refresh(r.json.refresh_token)).json.error.code).toBe("device_revoked");
  });

  it("device approved via a pairing request gets a device-bound refresh token on the poll", async () => {
    const { phone, code } = await setup();
    const p = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "device", pairing_code: await code(), device_name: "iPad", platform: "ios" });
    expect(p.status).toBe(202);
    await inject("POST", `/v1/pairing/requests/${p.json.pairing_request_id}/approve`, { device_id: phone.device_id }, { token: phone.access_token });
    const polled = PairingPollResponse.parse((await inject("GET", `/v1/pairing/requests/${p.json.pairing_request_id}`, undefined, { headers: { "x-pairing-secret": p.json.poll_secret } })).json);
    const login = polled.login!;
    expect(login.refresh_token).toMatch(/^agr_/);
    expect(login.device_id).toBeTruthy();
    expect(login.device_id).not.toBe(phone.device_id);
    const r = await refresh(login.refresh_token!);
    expect(r.status).toBe(200);
    expect(r.json.device_id).toBe(login.device_id);
  });

  it("agent refresh unchanged: aud agent, no device_id", async () => {
    const { agent: _a } = await setup();
    const a = await inject("POST", "/v1/auth/login", { email: EMAIL, client: "agent" });
    const r = await refresh(a.json.refresh_token);
    expect(r.status).toBe(200);
    expect(r.json.device_id).toBeUndefined();
    expect(verifyAccessToken(SECRET, r.json.access_token, h!.clock.now())?.aud).toBe("agent");
  });
});

describe("migration", () => {
  it("widens the audience CHECK of databases created before device refresh tokens", async () => {
    const { openDatabase } = await import("../src/db/client.ts");
    const { bootstrapSchema } = await import("../src/db/bootstrap.ts");
    const { sql } = await import("drizzle-orm");
    const database = await openDatabase({ kind: "memory" });
    try {
      await database.db.execute(sql.raw(`DROP TABLE refresh_tokens`));
      await database.db.execute(
        sql.raw(`CREATE TABLE refresh_tokens (
          id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), family_id text NOT NULL,
          token_hash char(64) NOT NULL UNIQUE, audience text NOT NULL CHECK (audience IN ('agent')),
          created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz,
          replaced_by text, revoked_at timestamptz)`),
      );
      await bootstrapSchema(database.db);
      await bootstrapSchema(database.db); // idempotent
      await database.db.execute(sql.raw(`INSERT INTO users (id, email, created_at) VALUES ('usr_m', 'm@example.com', now())`));
      await database.db.execute(
        sql.raw(`INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, audience, device_id, created_at, expires_at)
                 VALUES ('rtk_m', 'usr_m', 'rtf_m', '${"a".repeat(64)}', 'device', 'dev_m', now(), now())`),
      );
      await expect(
        database.db.execute(
          sql.raw(`INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, audience, created_at, expires_at)
                   VALUES ('rtk_x', 'usr_m', 'rtf_x', '${"b".repeat(64)}', 'bogus', now(), now())`),
        ),
      ).rejects.toThrow();
    } finally {
      await database.close();
    }
  });
});
