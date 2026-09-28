import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { base64urlEncode, canonicalJson, generateDeviceKeyPair, MemoryNonceStore, REKEY_PREFIX, rekeyMessage, signDecision, signRekey, utf8Encode, verifyDecision, verifyRekey } from "../src/index.ts";

const rnd = (n: number) => new Uint8Array(randomBytes(n));
const T0 = Date.parse("2026-09-28T10:00:00Z");
const iso = (ms: number) => new Date(ms).toISOString();

function setup() {
  const oldKp = generateDeviceKeyPair(rnd);
  const newKp = generateDeviceKeyPair(rnd);
  const payload = { device_id: "dev_1", new_public_key: newKp.publicKey, issued_at: iso(T0), expires_at: iso(T0 + 120_000), nonce: base64urlEncode(rnd(18)) };
  return { oldKp, newKp, payload, keyFor: (id: string) => (id === "dev_1" ? oldKp.publicKey : null) };
}

describe("rekey signing", () => {
  it("signs UTF-8(\"agentgate-rekey:v1:\" + canonicalJson(payload)) with the OLD key; verifies; single use", () => {
    const { oldKp, payload, keyFor } = setup();
    const req = signRekey(payload, oldKp.privateKey);
    expect(Object.keys(req).sort()).toEqual(["device_id", "expires_at", "issued_at", "new_public_key", "nonce", "signature"]);
    // exact message bytes (for the mobile implementation)
    expect(rekeyMessage(payload)).toEqual(utf8Encode(REKEY_PREFIX + canonicalJson(payload)));
    expect(ed25519.verify(Buffer.from(req.signature, "base64url"), utf8Encode(`agentgate-rekey:v1:${canonicalJson(payload)}`), Buffer.from(oldKp.publicKey, "base64url"))).toBe(true);
    const store = new MemoryNonceStore();
    expect(verifyRekey(req, { publicKeyFor: keyFor, now: new Date(T0 + 1000), nonceStore: store })).toMatchObject({ ok: true });
    expect(verifyRekey(req, { publicKeyFor: keyFor, now: new Date(T0 + 1000), nonceStore: store })).toEqual({ ok: false, reason: "replayed" });
  });

  it.each([
    ["forged (random key)", (s: ReturnType<typeof setup>) => signRekey(s.payload, generateDeviceKeyPair(rnd).privateKey), "bad_signature"],
    ["new key swapped after signing", (s: ReturnType<typeof setup>) => ({ ...signRekey(s.payload, s.oldKp.privateKey), new_public_key: generateDeviceKeyPair(rnd).publicKey }), "bad_signature"],
    ["other device id", (s: ReturnType<typeof setup>) => signRekey({ ...s.payload, device_id: "dev_2" }, s.oldKp.privateKey), "unknown_device"],
    ["expired", (s: ReturnType<typeof setup>) => signRekey({ ...s.payload, issued_at: iso(T0 - 600_000), expires_at: iso(T0 - 500_000) }, s.oldKp.privateKey), "expired"],
    ["malformed", () => ({ device_id: "dev_1" }), "malformed"],
  ] as const)("rejects: %s", (_n, make, reason) => {
    const s = setup();
    expect(verifyRekey(make(s), { publicKeyFor: s.keyFor, now: new Date(T0 + 1000) })).toEqual({ ok: false, reason });
  });

  it("refuses to sign bad lifetimes / same key; signatureOnly ignores time (executor proof check)", () => {
    const { oldKp, payload, keyFor } = setup();
    expect(() => signRekey({ ...payload, expires_at: iso(T0 + 600_000) }, oldKp.privateKey)).toThrow(/at most 5 minutes/);
    expect(() => signRekey({ ...payload, new_public_key: oldKp.publicKey }, oldKp.privateKey)).toThrow(/must differ/);
    const req = signRekey(payload, oldKp.privateKey);
    expect(verifyRekey(req, { publicKeyFor: keyFor, now: new Date(T0 + 86_400_000) })).toEqual({ ok: false, reason: "expired" });
    expect(verifyRekey(req, { publicKeyFor: keyFor, signatureOnly: true })).toMatchObject({ ok: true });
  });

  it("domain separation: a rekey signature is not a decision and vice versa", () => {
    const { oldKp, payload } = setup();
    const req = signRekey(payload, oldKp.privateKey);
    const fakeToken = `v2.${base64urlEncode(utf8Encode(canonicalJson(payload)))}.${req.signature}`;
    expect(verifyDecision(fakeToken, { publicKeyFor: () => oldKp.publicKey, expectedApprovalId: "a", expectedActionHash: "0".repeat(64), now: new Date(T0) }).ok).toBe(false);
    const dec = signDecision({ v: 2, approval_id: "a", action_id: "b", session_id: "c", action_hash: "0".repeat(64), decision: "approve", device_id: "dev_1", issued_at: iso(T0), expires_at: iso(T0 + 60_000), nonce: base64urlEncode(rnd(18)) }, oldKp.privateKey);
    expect(verifyRekey({ ...payload, signature: dec.split(".")[2] }, { publicKeyFor: () => oldKp.publicKey, now: new Date(T0) })).toEqual({ ok: false, reason: "bad_signature" });
  });
});
