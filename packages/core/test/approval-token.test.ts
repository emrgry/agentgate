import { createPrivateKey, sign } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApprovalTokenPayload } from "@agentgate/protocol";
import {
  computeActionHash,
  generateSigningKeyPair,
  MemoryNonceStore,
  newNonce,
  signApprovalToken,
  verifyApprovalToken,
  type VerifyOptions,
} from "../src/index.ts";
import { makeAction, T0, at } from "./fixtures.ts";

const keys = generateSigningKeyPair();
const otherKeys = generateSigningKeyPair();

const approvedAction = makeAction({ action: { category: "shell", operation: "execute", command: "rm temp.txt" } });
const swappedAction = makeAction({ action: { category: "shell", operation: "execute", command: "rm -rf /" } });
const APPROVED_HASH = computeActionHash(approvedAction);
const SWAPPED_HASH = computeActionHash(swappedAction);

function makePayload(overrides: Partial<ApprovalTokenPayload> = {}): ApprovalTokenPayload {
  return {
    v: 1,
    approval_id: "apr_1",
    action_id: "act_1",
    session_id: "ses_1",
    action_hash: APPROVED_HASH,
    decision: "approved",
    expires_at: at(60_000).toISOString(),
    nonce: newNonce(),
    issued_at: T0.toISOString(),
    ...overrides,
  };
}

function opts(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    publicKeyPem: keys.publicKeyPem,
    expectedActionHash: APPROVED_HASH,
    expectedApprovalId: "apr_1",
    now: at(1_000),
    ...overrides,
  };
}

/** Sign an arbitrary body string with the real key (bypasses payload validation). */
function signRawBody(bodyJson: string): string {
  const body = Buffer.from(bodyJson, "utf8").toString("base64url");
  const sig = sign(null, Buffer.from(body, "utf8"), createPrivateKey(keys.privateKeyPem));
  return `${body}.${sig.toString("base64url")}`;
}

function decodeBody(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0]!, "base64url").toString("utf8"));
}

describe("signApprovalToken", () => {
  it("produces a compact two-part base64url token", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("encodes the payload as canonical JSON (deterministic body)", () => {
    const p = makePayload();
    const reordered = Object.fromEntries(Object.entries(p).reverse()) as ApprovalTokenPayload;
    const a = signApprovalToken(p, keys.privateKeyPem).split(".")[0];
    const b = signApprovalToken(reordered, keys.privateKeyPem).split(".")[0];
    expect(a).toBe(b);
    expect(decodeBody(signApprovalToken(p, keys.privateKeyPem))).toEqual(p);
  });

  it.each<[string, Partial<ApprovalTokenPayload> | Record<string, unknown>]>([
    ["non-hex action_hash", { action_hash: "zz".repeat(32) }],
    ["short action_hash", { action_hash: "ab" }],
    ["decision other than approved", { decision: "denied" }],
    ["short nonce", { nonce: "short" }],
    ["bad expires_at", { expires_at: "tomorrow" }],
    ["wrong version", { v: 2 }],
  ])("refuses to sign an invalid payload: %s", (_name, override) => {
    expect(() => signApprovalToken({ ...makePayload(), ...override } as ApprovalTokenPayload, keys.privateKeyPem)).toThrow();
  });
});

describe("verifyApprovalToken", () => {
  it("accepts a valid token and returns the payload", () => {
    const payload = makePayload();
    const res = verifyApprovalToken(signApprovalToken(payload, keys.privateKeyPem), opts());
    expect(res).toEqual({ ok: true, payload });
  });

  it("accepts without expectedApprovalId (binding is then by hash only)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ expectedApprovalId: undefined })).ok).toBe(true);
  });

  it("rejects a tampered payload (action_hash swapped, signature unchanged)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    const [, sig] = token.split(".");
    const forgedBody = Buffer.from(JSON.stringify({ ...decodeBody(token), action_hash: SWAPPED_HASH })).toString(
      "base64url",
    );
    expect(verifyApprovalToken(`${forgedBody}.${sig}`, opts({ expectedActionHash: SWAPPED_HASH }))).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("rejects a tampered payload (expiry extended)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    const [, sig] = token.split(".");
    const forgedBody = Buffer.from(
      JSON.stringify({ ...decodeBody(token), expires_at: "2099-01-01T00:00:00.000Z" }),
    ).toString("base64url");
    expect(verifyApprovalToken(`${forgedBody}.${sig}`, opts()).ok).toBe(false);
  });

  it("rejects a tampered signature", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    const [body, sig] = token.split(".") as [string, string];
    const bytes = Buffer.from(sig, "base64url");
    bytes[10] = bytes[10]! ^ 0x01;
    expect(verifyApprovalToken(`${body}.${bytes.toString("base64url")}`, opts())).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("rejects a truncated signature", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    const [body, sig] = token.split(".") as [string, string];
    expect(verifyApprovalToken(`${body}.${sig.slice(0, 40)}`, opts()).ok).toBe(false);
  });

  it("rejects a token signed by a different key", () => {
    const token = signApprovalToken(makePayload(), otherKeys.privateKeyPem);
    expect(verifyApprovalToken(token, opts())).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects when verifying against the wrong public key", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ publicKeyPem: otherKeys.publicKeyPem }))).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("fails closed on an unusable public key", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ publicKeyPem: "not a pem" })).ok).toBe(false);
  });

  it("rejects an expired token (now after expires_at)", () => {
    const token = signApprovalToken(makePayload({ expires_at: at(60_000).toISOString() }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ now: at(60_001) }))).toEqual({ ok: false, reason: "expired" });
  });

  it("rejects at exactly expires_at", () => {
    const token = signApprovalToken(makePayload({ expires_at: at(60_000).toISOString() }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ now: at(60_000) }))).toEqual({ ok: false, reason: "expired" });
  });

  it("accepts 1 ms before expires_at", () => {
    const token = signApprovalToken(makePayload({ expires_at: at(60_000).toISOString() }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ now: at(59_999) })).ok).toBe(true);
  });

  it("fails closed on an invalid `now`", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ now: new Date(NaN) }))).toEqual({ ok: false, reason: "expired" });
  });

  it("uses the real clock when `now` is omitted", () => {
    const past = signApprovalToken(makePayload({ expires_at: "2000-01-01T00:00:00.000Z" }), keys.privateKeyPem);
    expect(verifyApprovalToken(past, opts({ now: undefined }))).toEqual({ ok: false, reason: "expired" });
  });

  it("TOCTOU: token approved for `rm temp.txt` does not authorize `rm -rf /`", () => {
    expect(APPROVED_HASH).not.toBe(SWAPPED_HASH);
    const token = signApprovalToken(makePayload({ action_hash: APPROVED_HASH }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ expectedActionHash: SWAPPED_HASH }))).toEqual({
      ok: false,
      reason: "hash_mismatch",
    });
  });

  it("rejects an expected hash of a different length (no prefix match)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ expectedActionHash: APPROVED_HASH.slice(0, 32) })).ok).toBe(false);
    expect(verifyApprovalToken(token, opts({ expectedActionHash: "" })).ok).toBe(false);
  });

  it("hash comparison is case-sensitive (hex must be lowercase)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ expectedActionHash: APPROVED_HASH.toUpperCase() })).ok).toBe(false);
  });

  it("rejects a token bound to a different approval", () => {
    const token = signApprovalToken(makePayload({ approval_id: "apr_other" }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ expectedApprovalId: "apr_1" }))).toEqual({
      ok: false,
      reason: "approval_mismatch",
    });
  });

  it.each([
    ["empty string", ""],
    ["no dot", "abc"],
    ["three parts", "a.b.c"],
    ["empty body", ".abc"],
    ["empty signature", "abc."],
    ["only a dot", "."],
    ["two dots", ".."],
  ])("rejects malformed token: %s", (_name, token) => {
    expect(verifyApprovalToken(token, opts())).toEqual({ ok: false, reason: "malformed" });
  });

  it.each([
    ["garbage body and signature", "!!!!.????"],
    ["valid body, garbage signature", () => `${signApprovalToken(makePayload(), keys.privateKeyPem).split(".")[0]}.AAAA`],
    ["jwt-looking string", "eyJhbGciOiJub25lIn0.eyJ2IjoxfQ"],
  ])("rejects garbage: %s", (_name, t) => {
    const token = typeof t === "function" ? t() : t;
    const res = verifyApprovalToken(token, opts());
    expect(res.ok).toBe(false);
  });

  it("rejects a correctly signed body that is not JSON", () => {
    expect(verifyApprovalToken(signRawBody("not json"), opts())).toEqual({ ok: false, reason: "invalid_payload" });
  });

  it("rejects a correctly signed payload that fails the schema (decision != approved)", () => {
    const body = JSON.stringify({ ...makePayload(), decision: "denied" });
    expect(verifyApprovalToken(signRawBody(body), opts())).toEqual({ ok: false, reason: "invalid_payload" });
  });

  it("rejects a correctly signed payload missing the nonce", () => {
    const { nonce: _n, ...rest } = makePayload();
    expect(verifyApprovalToken(signRawBody(JSON.stringify(rest)), opts())).toEqual({
      ok: false,
      reason: "invalid_payload",
    });
  });
});

describe("replay protection (nonce store)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("accepts a token once and rejects the replay", () => {
    const store = new MemoryNonceStore();
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ nonceStore: store })).ok).toBe(true);
    expect(verifyApprovalToken(token, opts({ nonceStore: store }))).toEqual({ ok: false, reason: "replayed" });
  });

  it("rejects a different token re-using a consumed nonce", () => {
    const store = new MemoryNonceStore();
    const nonce = newNonce();
    const a = signApprovalToken(makePayload({ nonce }), keys.privateKeyPem);
    const b = signApprovalToken(makePayload({ nonce, issued_at: at(5).toISOString() }), keys.privateKeyPem);
    expect(a).not.toBe(b);
    expect(verifyApprovalToken(a, opts({ nonceStore: store })).ok).toBe(true);
    expect(verifyApprovalToken(b, opts({ nonceStore: store }))).toEqual({ ok: false, reason: "replayed" });
  });

  it("does not burn the nonce when another check fails first", () => {
    const store = new MemoryNonceStore();
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ nonceStore: store, expectedActionHash: SWAPPED_HASH })).ok).toBe(false);
    expect(verifyApprovalToken(token, opts({ nonceStore: store })).ok).toBe(true);
  });

  it("allows distinct tokens with distinct nonces", () => {
    const store = new MemoryNonceStore();
    const a = signApprovalToken(makePayload(), keys.privateKeyPem);
    const b = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(a, opts({ nonceStore: store })).ok).toBe(true);
    expect(verifyApprovalToken(b, opts({ nonceStore: store })).ok).toBe(true);
  });

  it("regression: replay is rejected even when the verifier clock lags the wall clock", () => {
    // Before the fix the store purged by Date.now() while expiry was checked against
    // opts.now, so with a lagging verifier clock the nonce was forgotten and replay passed.
    vi.useFakeTimers();
    vi.setSystemTime(at(10 * 60_000)); // wall clock: 10 min after T0, token already "expired" by it
    const store = new MemoryNonceStore();
    const token = signApprovalToken(makePayload({ expires_at: at(60_000).toISOString() }), keys.privateKeyPem);
    const verifierNow = at(1_000); // e.g. server-synced time
    expect(verifyApprovalToken(token, opts({ nonceStore: store, now: verifierNow })).ok).toBe(true);
    expect(verifyApprovalToken(token, opts({ nonceStore: store, now: verifierNow }))).toEqual({
      ok: false,
      reason: "replayed",
    });
  });

  it("regression: replay is rejected when the wall clock lags the verifier clock", () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const store = new MemoryNonceStore();
    const token = signApprovalToken(makePayload({ expires_at: at(60_000).toISOString() }), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts({ nonceStore: store, now: at(59_000) })).ok).toBe(true);
    expect(verifyApprovalToken(token, opts({ nonceStore: store, now: at(59_500) }))).toEqual({
      ok: false,
      reason: "replayed",
    });
  });

  it("without a nonce store, verification is stateless (caller opted out of single-use)", () => {
    const token = signApprovalToken(makePayload(), keys.privateKeyPem);
    expect(verifyApprovalToken(token, opts()).ok).toBe(true);
    expect(verifyApprovalToken(token, opts()).ok).toBe(true);
  });
});

describe("MemoryNonceStore", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("consume is check-and-set", () => {
    const store = new MemoryNonceStore();
    const exp = new Date(Date.now() + 60_000);
    expect(store.consume("n1", exp)).toBe(true);
    expect(store.consume("n1", exp)).toBe(false);
    expect(store.consume("n2", exp)).toBe(true);
  });

  it("keeps a nonce at least until its expiry", () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const store = new MemoryNonceStore();
    expect(store.consume("n", at(60_000))).toBe(true);
    vi.setSystemTime(at(60_000));
    expect(store.consume("n", at(120_000))).toBe(false);
  });

  it("purges nonces after their expiry (bounded memory)", () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const store = new MemoryNonceStore();
    expect(store.consume("n", at(60_000))).toBe(true);
    vi.setSystemTime(at(60_001));
    // Purged — safe because a token carrying this nonce has itself expired by now.
    expect(store.consume("n", at(120_000))).toBe(true);
  });
});

describe("newNonce / generateSigningKeyPair", () => {
  it("nonces are unique, url-safe and long enough for the payload schema", () => {
    const set = new Set(Array.from({ length: 1000 }, () => newNonce()));
    expect(set.size).toBe(1000);
    for (const n of set) {
      expect(n).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(n.length).toBeGreaterThanOrEqual(16);
    }
  });

  it("generates PEM-encoded Ed25519 key pairs", () => {
    expect(keys.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    expect(keys.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(keys.publicKeyPem).not.toBe(otherKeys.publicKeyPem);
  });
});
