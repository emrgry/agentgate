import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import type { DecisionPayloadV2 } from "@agentgate/protocol";
import { SignedDecision } from "@agentgate/protocol";
import {
  base64urlDecode,
  base64urlEncode,
  canonicalJson,
  generateDeviceKeyPair,
  MAX_DECISION_LIFETIME_MS,
  MemoryNonceStore,
  publicKeyFingerprint,
  publicKeyFromPrivateKey,
  signDecision,
  signServerHello,
  utf8Decode,
  utf8Encode,
  verifyDecision,
  verifyServerHello,
  type VerifyDecisionOptions,
} from "../src/index.ts";

const rng = (n: number) => new Uint8Array(nodeRandomBytes(n));
const T0 = Date.parse("2026-09-26T12:00:00.000Z");
const iso = (ms: number) => new Date(T0 + ms).toISOString();
const HASH = "a".repeat(64);
const OTHER_HASH = "b".repeat(64);

const phone = generateDeviceKeyPair(rng);
const otherPhone = generateDeviceKeyPair(rng);

function payload(o: Partial<DecisionPayloadV2> = {}): DecisionPayloadV2 {
  return {
    v: 2,
    approval_id: "apr_1",
    action_id: "act_1",
    session_id: "ses_1",
    action_hash: HASH,
    decision: "approve",
    device_id: "dev_phone",
    issued_at: iso(0),
    expires_at: iso(120_000),
    nonce: base64urlEncode(rng(18)),
    ...o,
  };
}

const keys: Record<string, string> = { dev_phone: phone.publicKey, dev_other: otherPhone.publicKey };
function opts(o: Partial<VerifyDecisionOptions> = {}): VerifyDecisionOptions {
  return {
    publicKeyFor: (id) => keys[id] ?? null,
    expectedApprovalId: "apr_1",
    expectedActionHash: HASH,
    expectedSessionId: "ses_1",
    now: new Date(T0 + 1_000),
    ...o,
  };
}

/** Re-sign an arbitrary JSON body with a key (bypasses signDecision's validation). */
function signRaw(body: unknown, privateKey = phone.privateKey): string {
  const seg = base64urlEncode(utf8Encode(typeof body === "string" ? body : canonicalJson(body)));
  return `v2.${seg}.${signSegment(seg, privateKey)}`;
}
function signSegment(seg: string, privateKey: Uint8Array): string {
  const bytes = Uint8Array.from(seg, (c) => c.charCodeAt(0));
  return base64urlEncode(ed25519.sign(bytes, privateKey));
}

// ── keys ────────────────────────────────────────────────────────────────────────────
describe("generateDeviceKeyPair / publicKeyFingerprint", () => {
  it("uses the injected CSPRNG and returns a raw 32-byte key + 43-char base64url public key", () => {
    const seed = new Uint8Array(32).fill(7);
    const kp = generateDeviceKeyPair(() => seed);
    expect(kp.privateKey).toEqual(seed);
    expect(kp.privateKey).not.toBe(seed); // copied
    expect(kp.publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateDeviceKeyPair(() => new Uint8Array(32).fill(7)).publicKey).toBe(kp.publicKey);
  });

  it("matches the RFC 8032 test vector 1", () => {
    const sk = Uint8Array.from(Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex"));
    const pk = Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex");
    expect(publicKeyFromPrivateKey(sk)).toBe(pk.toString("base64url"));
    expect(Buffer.from(ed25519.sign(new Uint8Array(0), sk)).toString("hex")).toBe(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
  });

  it.each([
    ["short", () => new Uint8Array(31)],
    ["long", () => new Uint8Array(33)],
    ["not a Uint8Array", () => [1, 2, 3] as unknown as Uint8Array],
    ["all zeros", () => new Uint8Array(32)],
  ])("rejects a bad RNG result (%s)", (_n, bad) => {
    expect(() => generateDeviceKeyPair(bad)).toThrow();
  });

  it("fingerprint = first 16 bytes of SHA-256(raw), base64url (22 chars)", () => {
    const raw = Buffer.from(phone.publicKey, "base64url");
    const expected = createHash("sha256").update(raw).digest().subarray(0, 16).toString("base64url");
    expect(publicKeyFingerprint(phone.publicKey)).toBe(expected);
    expect(publicKeyFingerprint(phone.publicKey)).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(publicKeyFingerprint(otherPhone.publicKey)).not.toBe(expected);
  });

  it.each(["", "abc", phone.publicKey + "A", phone.publicKey.slice(0, 42) + "=", "!".repeat(43)])(
    "fingerprint rejects a malformed key %j",
    (k) => {
      expect(() => publicKeyFingerprint(k)).toThrow();
    },
  );
});

// ── round trips ─────────────────────────────────────────────────────────────────────
describe("signDecision / verifyDecision round trip", () => {
  it("approve verifies and returns the payload", () => {
    const p = payload();
    const token = signDecision(p, phone.privateKey);
    expect(SignedDecision.safeParse(token).success).toBe(true);
    expect(verifyDecision(token, opts({ requireDecision: "approve" }))).toEqual({ ok: true, payload: p });
  });

  it("deny verifies when no decision is required", () => {
    const token = signDecision(payload({ decision: "deny" }), phone.privateKey);
    expect(verifyDecision(token, opts())).toMatchObject({ ok: true, payload: { decision: "deny" } });
  });

  it("the middle segment is base64url(canonicalJson(payload))", () => {
    const p = payload();
    const reordered = Object.fromEntries(Object.entries(p).reverse()) as DecisionPayloadV2;
    const [, a] = signDecision(p, phone.privateKey).split(".");
    const [, b] = signDecision(reordered, phone.privateKey).split(".");
    expect(a).toBe(b);
    expect(Buffer.from(a!, "base64url").toString("utf8")).toBe(canonicalJson(p));
  });

  it("signatures are deterministic (Ed25519)", () => {
    const p = payload();
    expect(signDecision(p, phone.privateKey)).toBe(signDecision(p, phone.privateKey));
  });

  it("expectedSessionId is optional", () => {
    const token = signDecision(payload(), phone.privateKey);
    expect(verifyDecision(token, opts({ expectedSessionId: undefined })).ok).toBe(true);
  });

  it("uses the real clock when now is omitted", () => {
    const token = signDecision(payload(), phone.privateKey); // 2026-09-26 12:00–12:02
    const r = verifyDecision(token, opts({ now: undefined }));
    expect(r.ok ? "ok" : r.reason).toBe(Date.now() < T0 + 120_000 ? "ok" : "expired");
  });
});

describe("signDecision input validation", () => {
  it.each<[string, Partial<DecisionPayloadV2> | Record<string, unknown>]>([
    ["bad hash", { action_hash: "zz" }],
    ["bad decision", { decision: "maybe" }],
    ["bad version", { v: 1 }],
    ["short nonce", { nonce: "abc" }],
    ["bad issued_at", { issued_at: "yesterday" }],
    ["expires before issued", { expires_at: iso(-1) }],
    ["expires == issued", { expires_at: iso(0) }],
    ["lifetime > 5 min", { expires_at: iso(MAX_DECISION_LIFETIME_MS + 1) }],
  ])("throws on %s", (_n, o) => {
    expect(() => signDecision({ ...payload(), ...o } as DecisionPayloadV2, phone.privateKey)).toThrow();
  });

  it("lifetime of exactly 5 min is allowed", () => {
    expect(() => signDecision(payload({ expires_at: iso(MAX_DECISION_LIFETIME_MS) }), phone.privateKey)).not.toThrow();
  });

  it.each([new Uint8Array(31), new Uint8Array(64)])("throws on a bad private key", (k) => {
    expect(() => signDecision(payload(), k)).toThrow();
  });
});

// ── every failure reason ────────────────────────────────────────────────────────────
describe("verifyDecision failure reasons", () => {
  const good = () => signDecision(payload(), phone.privateKey);

  it.each([
    ["empty", ""],
    ["no dots", "abc"],
    ["two parts", "v2.abc"],
    ["four parts", "v2.a.b.c"],
    ["wrong version tag", () => good().replace(/^v2/, "v1")],
    ["empty body", () => `v2..${good().split(".")[2]}`],
    ["empty signature", () => `${good().split(".").slice(0, 2).join(".")}.`],
    ["non-base64url body", () => `v2.@@@@.${good().split(".")[2]}`],
    ["padded body", () => `v2.${good().split(".")[1]}=.${good().split(".")[2]}`],
    ["short signature", () => `${good().split(".").slice(0, 2).join(".")}.AAAA`],
    ["body not JSON", () => signRaw("not json")],
    ["body is an array", () => signRaw([1, 2])],
    ["body missing device_id", () => signRaw({ ...payload(), device_id: undefined })],
    ["body with numeric device_id", () => signRaw({ ...payload(), device_id: 7 })],
    ["invalid UTF-8 body", () => `v2.${base64urlEncode(Uint8Array.from([0xff, 0xfe]))}.${good().split(".")[2]}`],
    ["not a string", 42 as unknown as string],
  ])("malformed: %s", (_n, t) => {
    const token = typeof t === "function" ? t() : t;
    expect(verifyDecision(token, opts())).toEqual({ ok: false, reason: "malformed" });
  });

  it("unknown_device: no key for the device id", () => {
    const token = signDecision(payload({ device_id: "dev_unknown" }), phone.privateKey);
    expect(verifyDecision(token, opts())).toEqual({ ok: false, reason: "unknown_device" });
  });

  it.each([
    ["garbage key", "not-a-key"],
    ["wrong length", phone.publicKey.slice(0, 40)],
    ["key lookup throws", null],
  ])("unknown_device: %s", (_n, k) => {
    const token = good();
    const o = k === null ? opts({ publicKeyFor: () => { throw new Error("db down"); } }) : opts({ publicKeyFor: () => k });
    expect(verifyDecision(token, o)).toEqual({ ok: false, reason: "unknown_device" });
  });

  it("bad_signature: flipped signature byte", () => {
    const [v, body, sig] = good().split(".") as [string, string, string];
    const bytes = base64urlDecode(sig)!;
    bytes[5] = bytes[5]! ^ 1;
    expect(verifyDecision(`${v}.${body}.${base64urlEncode(bytes)}`, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("bad_signature: signed by another device, presented as this device", () => {
    const token = signDecision(payload({ device_id: "dev_phone" }), otherPhone.privateKey);
    expect(verifyDecision(token, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("bad_signature: device A's token re-labelled as device B (device_id is signed)", () => {
    const token = signDecision(payload({ device_id: "dev_phone" }), phone.privateKey);
    const [, , sig] = token.split(".");
    const relabelled = base64urlEncode(utf8Encode(canonicalJson({ ...payload(), device_id: "dev_other" })));
    expect(verifyDecision(`v2.${relabelled}.${sig}`, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("bad_signature: verifying a correctly signed token against another device's pinned key", () => {
    const token = signDecision(payload(), phone.privateKey);
    expect(verifyDecision(token, opts({ publicKeyFor: () => otherPhone.publicKey }))).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("invalid_payload: validly signed but schema-invalid", () => {
    expect(verifyDecision(signRaw({ ...payload(), action_hash: "XYZ" }), opts())).toEqual({ ok: false, reason: "invalid_payload" });
    expect(verifyDecision(signRaw({ ...payload(), decision: "maybe" }), opts())).toEqual({ ok: false, reason: "invalid_payload" });
    expect(verifyDecision(signRaw({ ...payload(), v: 1 }), opts())).toEqual({ ok: false, reason: "invalid_payload" });
  });

  it("invalid_payload: expires_at not after issued_at", () => {
    const t = signRaw({ ...payload(), issued_at: iso(60_000), expires_at: iso(30_000) });
    expect(verifyDecision(t, opts())).toEqual({ ok: false, reason: "invalid_payload" });
  });

  it("expired: now at / after expires_at", () => {
    const token = signDecision(payload({ expires_at: iso(60_000) }), phone.privateKey);
    expect(verifyDecision(token, opts({ now: new Date(T0 + 60_000) }))).toEqual({ ok: false, reason: "expired" });
    expect(verifyDecision(token, opts({ now: new Date(T0 + 60_001) }))).toEqual({ ok: false, reason: "expired" });
    expect(verifyDecision(token, opts({ now: new Date(T0 + 59_999) })).ok).toBe(true);
  });

  it("expired: an invalid `now` fails closed", () => {
    expect(verifyDecision(good(), opts({ now: new Date(NaN) }))).toEqual({ ok: false, reason: "expired" });
  });

  it("lifetime_too_long: expires_at − issued_at > 5 min (validly signed)", () => {
    const t = signRaw({ ...payload(), expires_at: iso(MAX_DECISION_LIFETIME_MS + 1) });
    expect(verifyDecision(t, opts())).toEqual({ ok: false, reason: "lifetime_too_long" });
  });

  it("lifetime_too_long: issued far in the future to stretch the window", () => {
    const t = signDecision(payload({ issued_at: iso(3_600_000), expires_at: iso(3_600_000 + 60_000) }), phone.privateKey);
    expect(verifyDecision(t, opts())).toEqual({ ok: false, reason: "lifetime_too_long" });
  });

  it("small phone clock skew (issued ≤ 60 s ahead) is tolerated", () => {
    const t = signDecision(payload({ issued_at: iso(30_000), expires_at: iso(30_000 + MAX_DECISION_LIFETIME_MS) }), phone.privateKey);
    expect(verifyDecision(t, opts()).ok).toBe(true);
  });

  it("approval_mismatch", () => {
    expect(verifyDecision(good(), opts({ expectedApprovalId: "apr_other" }))).toEqual({ ok: false, reason: "approval_mismatch" });
  });

  it("session_mismatch", () => {
    expect(verifyDecision(good(), opts({ expectedSessionId: "ses_other" }))).toEqual({ ok: false, reason: "session_mismatch" });
  });

  it("hash_mismatch (approved one action, executing another)", () => {
    expect(verifyDecision(good(), opts({ expectedActionHash: OTHER_HASH }))).toEqual({ ok: false, reason: "hash_mismatch" });
    expect(verifyDecision(good(), opts({ expectedActionHash: HASH.slice(0, 63) }))).toEqual({ ok: false, reason: "hash_mismatch" });
    expect(verifyDecision(good(), opts({ expectedActionHash: HASH.toUpperCase() }))).toEqual({ ok: false, reason: "hash_mismatch" });
  });

  it("not_approved: a valid deny when approve is required", () => {
    const t = signDecision(payload({ decision: "deny" }), phone.privateKey);
    expect(verifyDecision(t, opts({ requireDecision: "approve" }))).toEqual({ ok: false, reason: "not_approved" });
  });

  it("replayed: nonce store makes a decision single-use", () => {
    const store = new MemoryNonceStore();
    const t = good();
    expect(verifyDecision(t, opts({ nonceStore: store })).ok).toBe(true);
    expect(verifyDecision(t, opts({ nonceStore: store }))).toEqual({ ok: false, reason: "replayed" });
  });

  it("replayed: a different token re-using a consumed nonce", () => {
    const store = new MemoryNonceStore();
    const nonce = base64urlEncode(rng(18));
    expect(verifyDecision(signDecision(payload({ nonce }), phone.privateKey), opts({ nonceStore: store })).ok).toBe(true);
    const again = signDecision(payload({ nonce, issued_at: iso(1) }), phone.privateKey);
    expect(verifyDecision(again, opts({ nonceStore: store }))).toEqual({ ok: false, reason: "replayed" });
  });

  it("a failed verification does not burn the nonce", () => {
    const store = new MemoryNonceStore();
    const t = good();
    expect(verifyDecision(t, opts({ nonceStore: store, expectedActionHash: OTHER_HASH })).ok).toBe(false);
    expect(verifyDecision(t, opts({ nonceStore: store, requireDecision: "approve" })).ok).toBe(true);
  });

  it("reason precedence follows the documented order", () => {
    // unknown device beats bad signature; bad signature beats schema/expiry/ids.
    const forged = `v2.${base64urlEncode(utf8Encode(canonicalJson({ ...payload(), device_id: "nobody" })))}.${good().split(".")[2]}`;
    expect(verifyDecision(forged, opts())).toMatchObject({ reason: "unknown_device" });
    const badSigExpired = signDecision(payload(), otherPhone.privateKey);
    expect(verifyDecision(badSigExpired, opts({ now: new Date(T0 + 10 ** 9), expectedActionHash: OTHER_HASH }))).toMatchObject({ reason: "bad_signature" });
    // expired beats ids / hash / decision
    expect(verifyDecision(good(), opts({ now: new Date(T0 + 10 ** 9), expectedApprovalId: "x", expectedActionHash: OTHER_HASH }))).toMatchObject({ reason: "expired" });
    // approval beats session beats hash beats decision
    const deny = signDecision(payload({ decision: "deny" }), phone.privateKey);
    expect(verifyDecision(deny, opts({ expectedApprovalId: "x", expectedSessionId: "y", expectedActionHash: OTHER_HASH, requireDecision: "approve" }))).toMatchObject({ reason: "approval_mismatch" });
    expect(verifyDecision(deny, opts({ expectedSessionId: "y", expectedActionHash: OTHER_HASH, requireDecision: "approve" }))).toMatchObject({ reason: "session_mismatch" });
    expect(verifyDecision(deny, opts({ expectedActionHash: OTHER_HASH, requireDecision: "approve" }))).toMatchObject({ reason: "hash_mismatch" });
  });
});

// ── tamper each field ───────────────────────────────────────────────────────────────
describe("tampering with any payload field breaks the signature", () => {
  const base = payload();
  const token = signDecision(base, phone.privateKey);
  const sig = token.split(".")[2]!;
  const tampered: Array<[keyof DecisionPayloadV2, unknown]> = [
    ["v", 3],
    ["approval_id", "apr_2"],
    ["action_id", "act_2"],
    ["session_id", "ses_2"],
    ["action_hash", OTHER_HASH],
    ["decision", "deny"],
    ["device_id", "dev_other"],
    ["issued_at", iso(1)],
    ["expires_at", iso(299_000)],
    ["nonce", base64urlEncode(rng(18))],
  ];
  it.each(tampered)("%s", (field, value) => {
    const body = base64urlEncode(utf8Encode(canonicalJson({ ...base, [field]: value })));
    const r = verifyDecision(`v2.${body}.${sig}`, opts({ publicKeyFor: () => phone.publicKey }));
    expect(r).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("adding an extra field breaks the signature", () => {
    const body = base64urlEncode(utf8Encode(canonicalJson({ ...base, extra: 1 })));
    expect(verifyDecision(`v2.${body}.${sig}`, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("re-encoding the same JSON non-canonically breaks the signature", () => {
    const body = base64urlEncode(utf8Encode(JSON.stringify(base, null, 1)));
    expect(verifyDecision(`v2.${body}.${sig}`, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("non-canonical base64url of the same bytes is rejected (no malleability)", () => {
    // Flip the unused low bits of the last signature char: same bytes under a lenient decoder.
    const last = sig[sig.length - 1]!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alt = alphabet[alphabet.indexOf(last) ^ 1]!;
    // A lenient decoder (Buffer) maps both spellings to the same 64 bytes…
    expect(Buffer.from(alt === last ? "" : `${sig.slice(0, -1)}${alt}`, "base64url")).toEqual(Buffer.from(sig, "base64url"));
    // …the strict decoder refuses the non-canonical one.
    expect(verifyDecision(`${token.slice(0, -1)}${alt}`, opts())).toEqual({ ok: false, reason: "malformed" });
  });
});

// ── server hello ────────────────────────────────────────────────────────────────────
describe("signServerHello / verifyServerHello", () => {
  const server = generateDeviceKeyPair(rng);
  const fp = publicKeyFingerprint(server.publicKey);
  const challenge = base64urlEncode(rng(32));

  it("round trip", () => {
    const sig = signServerHello(challenge, server.privateKey);
    expect(sig).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(verifyServerHello(challenge, sig, server.publicKey, fp)).toBe(true);
  });

  it("signs the UTF-8 bytes of the documented prefix + challenge", () => {
    const sig = signServerHello(challenge, server.privateKey);
    const msg = utf8Encode(`agentgate-pairing-hello:v1:${challenge}`);
    expect(ed25519.verify(base64urlDecode(sig)!, msg, base64urlDecode(server.publicKey)!)).toBe(true);
  });

  it("MITM: a different key (with its own valid signature) fails the pinned fingerprint", () => {
    const mitm = generateDeviceKeyPair(rng);
    const sig = signServerHello(challenge, mitm.privateKey);
    expect(verifyServerHello(challenge, sig, mitm.publicKey, fp)).toBe(false);
  });

  it("right key, wrong signature (replayed for another challenge) fails", () => {
    const sig = signServerHello(base64urlEncode(rng(32)), server.privateKey);
    expect(verifyServerHello(challenge, sig, server.publicKey, fp)).toBe(false);
  });

  it.each([
    ["garbage signature", () => [challenge, "x".repeat(86), server.publicKey, fp]],
    ["short signature", () => [challenge, "AAAA", server.publicKey, fp]],
    ["garbage key", () => [challenge, signServerHello(challenge, server.privateKey), "nope", fp]],
    ["short challenge", () => ["abc", signServerHello(challenge, server.privateKey), server.publicKey, fp]],
    ["wrong fingerprint", () => [challenge, signServerHello(challenge, server.privateKey), server.publicKey, "A".repeat(22)]],
  ])("false (never throws) for %s", (_n, args) => {
    const [c, s, k, f] = args() as [string, string, string, string];
    expect(verifyServerHello(c, s, k, f)).toBe(false);
  });

  it("signServerHello rejects a challenge that is too short", () => {
    expect(() => signServerHello("short", server.privateKey)).toThrow();
  });
});

// ── encodings & canonical JSON ──────────────────────────────────────────────────────
describe("encoding helpers match Node's implementations", () => {
  it("base64url encode/decode vs Buffer for lengths 0..130", () => {
    for (let n = 0; n <= 130; n++) {
      const bytes = rng(n);
      const enc = base64urlEncode(bytes);
      expect(enc).toBe(Buffer.from(bytes).toString("base64url"));
      expect(base64urlDecode(enc)).toEqual(bytes);
    }
  });

  it.each(["a", "ab=", "a+b", "a/b", "ab c", "AB==", "AAB", "AAAAAB"])("strict decode rejects %j", (s) => {
    expect(base64urlDecode(s)).toBeNull();
  });

  it("UTF-8 encode matches TextEncoder; decode matches TextDecoder (fatal)", () => {
    const samples = ["", "ascii", "héllo wörld", "日本語", "🚀 emoji 👍🏽", "\u0000\u007f\u0080߿ࠀ￿", "lone \ud800 surrogate"];
    for (const s of samples) {
      const bytes = utf8Encode(s);
      expect(bytes).toEqual(new TextEncoder().encode(s));
      expect(utf8Decode(bytes)).toBe(new TextDecoder().decode(bytes));
    }
  });

  it.each<[string, number[]]>([
    ["invalid lead byte", [0xff]],
    ["truncated 2-byte", [0xc3]],
    ["truncated 4-byte", [0xf0, 0x9f, 0x9a]],
    ["overlong '/'", [0xc0, 0xaf]],
    ["overlong 3-byte", [0xe0, 0x80, 0xaf]],
    ["encoded surrogate", [0xed, 0xa0, 0x80]],
    ["above U+10FFFF", [0xf4, 0x90, 0x80, 0x80]],
    ["bad continuation", [0xe2, 0x28, 0xa1]],
  ])("strict UTF-8 decode rejects %s", (_n, bytes) => {
    expect(utf8Decode(Uint8Array.from(bytes))).toBeNull();
  });
});

describe("canonicalJson (moved here from core)", () => {
  it("is key-order independent and stable", () => {
    expect(canonicalJson({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: "é" } })).toBe('{"a":{"c":"é","d":[1,{"y":2,"z":1}]},"b":1}');
    const p = payload();
    expect(canonicalJson(p)).toBe(canonicalJson(Object.fromEntries(Object.entries(p).reverse())));
  });

  it("is the same function core re-exports", async () => {
    const core = await import("@agentgate/core");
    expect(core.canonicalJson).toBe(canonicalJson);
  });

  it("rejects non-finite numbers and drops undefined members", () => {
    expect(() => canonicalJson({ a: NaN })).toThrow(TypeError);
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}');
  });
});
