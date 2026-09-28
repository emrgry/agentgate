import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import { claudeCodeProvider } from "@agentgate/adapter-claude-code";
import { DeviceKeysResponse, LoginResponse } from "@agentgate/protocol";
import { base64urlEncode, generateDeviceKeyPair, publicKeyFingerprint, signRekey } from "@agentgate/signing";
import { auditLogs, devices, pairingRequests } from "../src/db/schema.ts";
import { rootOwnedProof } from "../src/domain/device-recovery.ts";
import type { SupervisorOptions } from "../src/control/supervisor.ts";
import { controlHarness, FAKE_CLAUDE, type Phone } from "./control-harness.ts";

/** Re-pairing deadlock fix: signed rekey, hello already_paired, sudo-backed local recovery. */

const T = 60_000;
const c = controlHarness();
afterEach(() => c.close());
const rnd = (n: number) => new Uint8Array(randomBytes(n));
const control = (): SupervisorOptions => ({ providers: { "claude-code": claudeCodeProvider({ binary: FAKE_CLAUDE }) }, hookSettingsPath: () => "/dev/null", turnEnv: () => ({ ...process.env }), tickMs: 0 });

function rekeyBody(p: Phone, newKey: string, o: { key?: Uint8Array; deviceId?: string; issuedAt?: number; nonce?: string } = {}) {
  const now = o.issuedAt ?? c.h.clock.now().getTime();
  return signRekey(
    { device_id: o.deviceId ?? p.id, new_public_key: newKey, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 120_000).toISOString(), nonce: o.nonce ?? base64urlEncode(rnd(18)) },
    o.key ?? p.kp.privateKey,
  );
}
const rekey = (id: string, body: unknown) => c.inject("POST", `/v1/devices/${id}/rekey`, body);

describe("rekey (same phone, still holds its old key)", () => {
  it("new key works, old key is rejected afterwards; keys list shows rekeyed_at + proof; audited", async () => {
    const { agent, phone, dir } = await c.server(control());
    const id = await c.start(agent, dir, "say:hi");
    await c.until(() => c.session(agent, id), (s) => s.status === "waiting_input");
    const next = generateDeviceKeyPair(rnd);
    const body = rekeyBody(phone, next.publicKey);
    const r = await rekey(phone.id, body);
    expect(r.status, JSON.stringify(r.json)).toBe(200);
    const login = LoginResponse.parse(r.json);
    expect(login.device_id).toBe(phone.id);
    const newPhone: Phone = { kp: next, token: login.access_token, id: phone.id };
    // Commands signed with the OLD key are refused now; the new key works.
    expect((await c.cmd(phone, id, { command: "instruct", text: "say:x" })).status).toBe(403);
    expect((await c.cmd(newPhone, id, { command: "instruct", text: "say:y" })).json.status).toBe("applied");
    const keys = DeviceKeysResponse.parse((await c.inject("GET", "/v1/devices/keys", undefined, { token: agent })).json).items.find((k) => k.device_id === phone.id)!;
    expect(keys).toMatchObject({ public_key: next.publicKey, fingerprint: publicKeyFingerprint(next.publicKey) });
    expect(keys.rekeyed_at).toBeTruthy();
    expect(keys.rekey_proof).toMatchObject({ new_public_key: next.publicKey, signature: body.signature });
    const act = (await c.inject("GET", "/v1/activity?limit=50", undefined, { token: login.access_token })).json.items.map((i: { event: string }) => i.event);
    expect(act).toContain("device.rekeyed");
  }, T);

  it("rejects forged, other-device, replayed, expired, mismatched and revoked-device rekeys", async () => {
    const { phone } = await c.server(control());
    const k = () => generateDeviceKeyPair(rnd).publicKey;
    // A second device row with its own key (as if paired earlier).
    const other = generateDeviceKeyPair(rnd);
    const [me] = await c.h.database.db.select().from(devices).where(eq(devices.id, phone.id));
    await c.h.database.db.insert(devices).values({ ...me!, id: "dev_other", public_key: other.publicKey, name: "iPad" });
    const cases: Array<[string, () => Promise<{ status: number; json: any }>, number, RegExp]> = [
      ["forged (random key)", () => rekey(phone.id, rekeyBody(phone, k(), { key: generateDeviceKeyPair(rnd).privateKey })), 403, /bad_signature/],
      ["other device's key", () => rekey(phone.id, rekeyBody(phone, k(), { key: other.privateKey })), 403, /bad_signature/],
      ["path/body mismatch", () => rekey("dev_other", rekeyBody(phone, k())), 400, /device_id/],
      ["expired", () => rekey(phone.id, rekeyBody(phone, k(), { issuedAt: c.h.clock.now().getTime() - 3_600_000 })), 403, /expired/],
      ["key already used by another device", () => rekey(phone.id, rekeyBody(phone, other.publicKey)), 409, /already belongs/],
      ["unknown device", () => rekey("dev_nope", rekeyBody(phone, k(), { deviceId: "dev_nope" })), 403, /unknown device/],
    ];
    for (const [name, run, status, re] of cases) {
      const r = await run();
      expect(r.status, name).toBe(status);
      expect(r.json.error.message, name).toMatch(re);
    }
    // Replay: the same nonce can't be used twice (second rotation back with the same nonce).
    const nonce = base64urlEncode(rnd(18));
    const k1 = generateDeviceKeyPair(rnd);
    expect((await rekey(phone.id, rekeyBody(phone, k1.publicKey, { nonce }))).status).toBe(200);
    const back = await rekey(phone.id, rekeyBody({ ...phone, kp: k1 }, generateDeviceKeyPair(rnd).publicKey, { nonce }));
    expect(back.status).toBe(403);
    expect(back.json.error.message).toMatch(/replayed/);
    // Revoked device: refused.
    await c.h.database.db.update(devices).set({ revoked_at: new Date() }).where(eq(devices.id, "dev_other"));
    const rv = await rekey("dev_other", rekeyBody({ ...phone, id: "dev_other", kp: other }, k()));
    expect(rv.status).toBe(403);
    expect(rv.json.error.code).toBe("device_revoked");
  }, T);

  it("pairing hello: already_paired for an active device id; false for unknown/revoked; absent without device_id", async () => {
    const { phone } = await c.server(control());
    const challenge = base64urlEncode(rnd(32));
    const hello = (device_id?: string) => c.inject("POST", "/v1/pairing/hello", { challenge, ...(device_id ? { device_id } : {}) });
    expect((await hello(phone.id)).json.already_paired).toBe(true);
    expect((await hello("dev_unknown")).json.already_paired).toBe(false);
    expect("already_paired" in (await hello()).json).toBe(false);
    await c.h.database.db.update(devices).set({ revoked_at: new Date() }).where(eq(devices.id, phone.id));
    expect((await hello(phone.id)).json.already_paired).toBe(false);
  }, T);
});

describe("local recovery (POST /v1/devices/recovery)", () => {
  const GOOD = "/tmp/agentgate-recovery-testtesttesttest";
  const nonce = () => base64urlEncode(rnd(32));

  it("refused without the root-owned proof (real check), for devices, and remotely; accepted with it", async () => {
    let expect_: string | null = null;
    const { agent, phone } = await c.server(control(), { recoveryProof: (path, n) => path === GOOD && n === expect_ });
    // Real default check: a user-owned file with the right name + content is NOT enough.
    const own = `/tmp/agentgate-recovery-${base64urlEncode(rnd(16))}`;
    const n0 = nonce();
    writeFileSync(own, n0);
    expect(rootOwnedProof(own, n0)).toBe(false);
    expect(rootOwnedProof("/etc/hosts", n0)).toBe(false);
    // Injected check: wrong proof → 403; device token → 403.
    expect((await c.inject("POST", "/v1/devices/recovery", { action: "reset", nonce: n0, proof_path: own }, { token: agent })).status).toBe(403);
    expect((await c.inject("POST", "/v1/devices/recovery", { action: "reset", nonce: n0, proof_path: GOOD }, { token: phone.token })).status).toBe(403);
    // With a valid proof: revoke one.
    expect_ = nonce();
    const r1 = await c.inject("POST", "/v1/devices/recovery", { action: "revoke", device_id: phone.id, nonce: expect_, proof_path: GOOD }, { token: agent });
    expect(r1.status, JSON.stringify(r1.json)).toBe(200);
    expect(r1.json.revoked).toEqual([phone.id]);
    // Nonce single use.
    expect((await c.inject("POST", "/v1/devices/recovery", { action: "reset", nonce: expect_, proof_path: GOOD }, { token: agent })).status).toBe(403);
    // Revoked device token no longer works.
    expect((await c.inject("GET", "/v1/devices", undefined, { token: phone.token })).status).toBe(401);
    // Agents can list devices locally (`agentgate devices list`).
    const list = await c.inject("GET", "/v1/devices", undefined, { token: agent });
    expect(list.json.items.find((d: { id: string }) => d.id === phone.id).revoked_at).toBeTruthy();
  }, T);

  it("reset: revokes every device and expires pending pairing requests → the next pairing is a bootstrap (the deadlock is gone)", async () => {
    let ok: string | null = null;
    const { agent, phone } = await c.server(control(), { recoveryProof: (p, n) => p === GOOD && n === ok });
    // The deadlock: same phone scans a new code → 202 (its own old record would have to approve).
    const code = (await c.inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
    const again = await c.inject("POST", "/v1/auth/login", { client: "device", pairing_code: code, device_name: "iPhone", device_public_key: generateDeviceKeyPair(rnd).publicKey });
    expect(again.status).toBe(202);
    ok = nonce();
    const r = await c.inject("POST", "/v1/devices/recovery", { action: "reset", nonce: ok, proof_path: GOOD }, { token: agent });
    expect(r.json).toEqual({ revoked: [phone.id], expired_pairing_requests: 1 });
    const pr = await c.h.database.db.select().from(pairingRequests);
    expect(pr.every((x) => x.status === "expired")).toBe(true);
    const audit = await c.h.database.db.select().from(auditLogs).where(eq(auditLogs.event, "device.recovery_reset"));
    expect(audit).toHaveLength(1);
    const code2 = (await c.inject("POST", "/v1/pairing", {}, { token: agent })).json.code;
    const fresh = await c.inject("POST", "/v1/auth/login", { client: "device", pairing_code: code2, device_name: "iPhone", device_public_key: generateDeviceKeyPair(rnd).publicKey });
    expect(fresh.status).toBe(200); // bootstrap
  }, T);
});
