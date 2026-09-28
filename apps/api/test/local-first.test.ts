import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateDeviceKeyPair,
  publicKeyFingerprint,
  signDecision,
  verifyServerHello,
  type DecisionPayloadV2,
} from "@agentgate/signing";
import { DeviceKeysResponse, PairingHelloResponse } from "@agentgate/protocol";
import { computeActionHash } from "@agentgate/core";
import { createHarness, draft, type Harness } from "./helpers.ts";

/** M7 local-first: owner, email-less login, pairing hello, device keys, phone-signed decisions. */

let h: Harness | null = null;
afterEach(async () => {
  await h?.close();
  h = null;
});

const rnd = (n: number) => new Uint8Array(randomBytes(n));
type R = { status: number; json: any };
async function inject(method: "GET" | "POST", url: string, body?: unknown, o: { token?: string; ip?: string } = {}): Promise<R> {
  const res = await h!.app.inject({
    method,
    url,
    remoteAddress: o.ip ?? "127.0.0.1",
    headers: { ...(o.token ? { authorization: `Bearer ${o.token}` } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    ...(body !== undefined ? { payload: JSON.stringify(body) } : {}),
  });
  return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : {} };
}

async function localServer(opts: { require?: boolean } = {}) {
  h = await createHarness({ mode: "local", openDeviceLogin: false, ownerName: "Damla Ipci", machineName: "Damla's MacBook", requireDeviceSignatures: opts.require ?? false });
  await h.app.ready();
  const agent = await inject("POST", "/v1/auth/login", { client: "agent" });
  expect(agent.status).toBe(200);
  return agent.json.access_token as string;
}

async function pairPhone(agent: string, name = "iPhone", withKey = true) {
  const kp = generateDeviceKeyPair(rnd);
  const code = (await inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
  const r = await inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_name: name, ...(withKey ? { device_public_key: kp.publicKey } : {}) }, { ip: "192.168.1.50" });
  return { r, kp, token: r.json.access_token as string, id: r.json.device_id as string };
}

async function askApproval(agent: string) {
  const ag = await inject("POST", "/v1/agents", { name: "m", type: "cli", machine_id: "m1" }, { token: agent });
  const ses = await inject("POST", "/v1/sessions", { agent_id: ag.json.id }, { token: agent });
  const d = draft(ses.json.id);
  const hash = computeActionHash(d);
  const act = await inject("POST", "/v1/actions", { action: d, policy: { decision: "ask", rule_id: null, risk: "high", reason: "r" }, action_hash: hash }, { token: agent });
  expect(act.status).toBe(201);
  return { approval: act.json.approval, actionId: act.json.action.action_id as string, sessionId: ses.json.id as string, hash };
}

function decision(a: Awaited<ReturnType<typeof askApproval>>, deviceId: string, over: Partial<DecisionPayloadV2> = {}): DecisionPayloadV2 {
  const now = h!.clock.now();
  return {
    v: 2,
    approval_id: a.approval.approval_id,
    action_id: a.actionId,
    session_id: a.sessionId,
    action_hash: a.hash,
    decision: "approve",
    device_id: deviceId,
    issued_at: now.toISOString(),
    expires_at: new Date(Math.min(now.getTime() + 60_000, Date.parse(a.approval.expires_at))).toISOString(),
    nonce: Buffer.from(rnd(18)).toString("base64url"),
    ...over,
  };
}

describe("local-first mode", () => {
  it("email-less loopback agent login maps to the owner; remote agent login refused", async () => {
    await localServer();
    const remote = await inject("POST", "/v1/auth/login", { client: "agent" }, { ip: "192.168.1.9" });
    expect(remote.status).toBe(403);
    expect(remote.json.error.code).toBe("agent_login_loopback_only");
  });

  it("pairing hello: signed by the server identity key; phone verifies against the QR fingerprint", async () => {
    await localServer();
    const challenge = Buffer.from(rnd(32)).toString("base64url");
    const r = await inject("POST", "/v1/pairing/hello", { challenge }, { ip: "192.168.1.50" });
    expect(r.status).toBe(200);
    const hello = PairingHelloResponse.parse(r.json);
    expect(hello).toMatchObject({ machine_name: "Damla's MacBook", owner: { display_name: "Damla Ipci" } });
    const fp = publicKeyFingerprint(hello.server_public_key);
    expect(verifyServerHello(challenge, hello.signature, hello.server_public_key, fp)).toBe(true);
    // a MITM with another key, or a QR fingerprint that doesn't match → rejected client-side
    const otherFp = publicKeyFingerprint(generateDeviceKeyPair(rnd).publicKey);
    expect(verifyServerHello(challenge, hello.signature, hello.server_public_key, otherFp)).toBe(false);
    expect(verifyServerHello(Buffer.from(rnd(32)).toString("base64url"), hello.signature, hello.server_public_key, fp)).toBe(false);
  });

  it("device key registration: bootstrap device and approved second device carry their keys; keys endpoint is loopback-only", async () => {
    const agent = await localServer();
    const a = await pairPhone(agent, "iPhone");
    expect(a.r.status).toBe(200);
    const b = await pairPhone(agent, "iPad");
    expect(b.r.status).toBe(202);
    await inject("POST", `/v1/pairing/requests/${b.r.json.pairing_request_id}/approve`, { device_id: a.id }, { token: a.token });
    const res = await h!.app.inject({ method: "GET", url: `/v1/pairing/requests/${b.r.json.pairing_request_id}`, headers: { "x-pairing-secret": b.r.json.poll_secret } });
    const bId = JSON.parse(res.body).login.device_id;
    const keys = DeviceKeysResponse.parse((await inject("GET", "/v1/devices/keys", undefined, { token: agent })).json).items;
    expect(keys).toEqual([
      { device_id: a.id, public_key: a.kp.publicKey, fingerprint: publicKeyFingerprint(a.kp.publicKey), revoked_at: null, rekeyed_at: null, rekey_proof: null },
      { device_id: bId, public_key: b.kp.publicKey, fingerprint: publicKeyFingerprint(b.kp.publicKey), revoked_at: null, rekeyed_at: null, rekey_proof: null },
    ]);
    expect((await inject("GET", "/v1/devices/keys", undefined, { token: agent, ip: "192.168.1.9" })).status).toBe(403);
    expect((await inject("GET", "/v1/devices/keys", undefined, { token: a.token })).status).toBe(403); // device token
  });

  it("invalid device key → 400", async () => {
    const agent = await localServer();
    const code = (await inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
    const r = await inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_public_key: "x".repeat(43) });
    expect(r.status).toBe(400);
  });
});

describe("phone-signed approvals", () => {
  it("every push carries server_fingerprint = the QR v2 fp (approval + pairing pushes)", async () => {
    const agent = await localServer();
    const p = await pairPhone(agent);
    await inject("POST", "/v1/devices", { name: "iPhone", platform: "ios", push_token: "ExponentPushToken[x]" }, { token: p.token });
    const challenge = Buffer.from(rnd(32)).toString("base64url");
    const fp = publicKeyFingerprint((await inject("POST", "/v1/pairing/hello", { challenge })).json.server_public_key);
    await askApproval(agent);
    await pairPhone(agent, "iPad"); // → pairing request push to the first phone
    await new Promise((r) => setTimeout(r, 20));
    expect(h!.push.sent.length).toBe(2);
    for (const m of h!.push.sent) expect(m.data.server_fingerprint).toBe(fp);
  });

  it("valid signed decision → approved; the relayed token IS the phone's signed decision", async () => {
    const agent = await localServer({ require: true });
    const p = await pairPhone(agent);
    const a = await askApproval(agent);
    const signed = signDecision(decision(a, p.id), p.kp.privateKey);
    const r = await inject("POST", `/v1/approvals/${a.approval.approval_id}/approve`, { device_id: p.id, signed_decision: signed }, { token: p.token });
    expect(r.status).toBe(200);
    expect(r.json.approval_token).toBe(signed);
    expect(signed.length).toBeLessThan(8192);
    const got = await inject("GET", `/v1/approvals/${a.approval.approval_id}`, undefined, { token: agent });
    expect(got.json.approval_token).toBe(signed);
  });

  it("signed deny → denied, no token", async () => {
    const agent = await localServer({ require: true });
    const p = await pairPhone(agent);
    const a = await askApproval(agent);
    const r = await inject("POST", `/v1/approvals/${a.approval.approval_id}/deny`, { device_id: p.id, signed_decision: signDecision(decision(a, p.id, { decision: "deny" }), p.kp.privateKey) }, { token: p.token });
    expect(r.status).toBe(200);
    expect(r.json.approval.status).toBe("denied");
    expect(r.json.approval_token).toBeNull();
  });

  const bad: Array<[string, (a: any, p: any, other: any) => { body: Record<string, unknown>; status: number; code: string }]> = [
    ["forged (random key)", (a, p) => ({ body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id), generateDeviceKeyPair(rnd).privateKey) }, status: 403, code: "invalid_signed_decision" })],
    ["signed by another device, claiming this one", (a, p, o) => ({ body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id), o.kp.privateKey) }, status: 403, code: "invalid_signed_decision" })],
    ["tampered action hash", (a, p) => ({ body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id, { action_hash: "0".repeat(64) }), p.kp.privateKey) }, status: 403, code: "invalid_signed_decision" })],
    ["wrong approval", (a, p) => ({ body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id, { approval_id: "apr_other" }), p.kp.privateKey) }, status: 403, code: "invalid_signed_decision" })],
    [
      "expired",
      (a, p) => {
        const t = h!.clock.now().getTime();
        return { body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id, { issued_at: new Date(t - 120_000).toISOString(), expires_at: new Date(t - 60_000).toISOString() }), p.kp.privateKey) }, status: 403, code: "invalid_signed_decision" };
      },
    ],
    ["decision says deny, route says approve", (a, p) => ({ body: { device_id: p.id, signed_decision: signDecision(decision(a, p.id, { decision: "deny" }), p.kp.privateKey) }, status: 400, code: "decision_mismatch" })],
    ["missing signature from a keyed device", (_a, p) => ({ body: { device_id: p.id }, status: 400, code: "signed_decision_required" })],
  ];
  for (const [name, make] of bad) {
    it(`rejects: ${name}`, async () => {
      const agent = await localServer();
      const p = await pairPhone(agent, "iPhone");
      const other = { kp: generateDeviceKeyPair(rnd) };
      const a = await askApproval(agent);
      const { body, status, code } = make(a, p, other);
      const r = await inject("POST", `/v1/approvals/${a.approval.approval_id}/approve`, body, { token: p.token });
      expect([r.status, r.json.error?.code]).toEqual([status, code]);
      expect((await inject("GET", `/v1/approvals/${a.approval.approval_id}`, undefined, { token: agent })).json.approval.status).toBe("pending");
    });
  }

  it("replayed decision cannot resolve a second time (409)", async () => {
    const agent = await localServer();
    const p = await pairPhone(agent);
    const a = await askApproval(agent);
    const body = { device_id: p.id, signed_decision: signDecision(decision(a, p.id), p.kp.privateKey) };
    expect((await inject("POST", `/v1/approvals/${a.approval.approval_id}/approve`, body, { token: p.token })).status).toBe(200);
    expect((await inject("POST", `/v1/approvals/${a.approval.approval_id}/approve`, body, { token: p.token })).status).toBe(409);
  });

  it("legacy device without a key: v1 server-signed path when allowed; refused when signatures are required", async () => {
    const agent = await localServer({ require: false });
    const legacy = await pairPhone(agent, "old phone", false);
    const a = await askApproval(agent);
    const ok = await inject("POST", `/v1/approvals/${a.approval.approval_id}/approve`, { device_id: legacy.id }, { token: legacy.token });
    expect(ok.status).toBe(200);
    expect(ok.json.approval_token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/); // v1

    await h!.close();
    const agent2 = await localServer({ require: true });
    const noKey = await (async () => {
      const code = (await inject("POST", "/v1/pairing", {}, { token: agent2 })).json.code;
      return inject("POST", "/v1/auth/login", { client: "device", pairing_code: code });
    })();
    expect([noKey.status, noKey.json.error.code]).toEqual([400, "device_key_required"]);
  });
});
