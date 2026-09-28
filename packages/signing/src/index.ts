/**
 * @agentgate/signing: Ed25519 signing shared byte-for-byte by the iPhone app (Hermes)
 * and the Node daemon. Pure JS (@noble/curves, @noble/hashes): this entry point must
 * never import a `node:` builtin or reference Buffer / process (enforced by a test).
 * Node-only PEM bridging lives in `@agentgate/signing/node`.
 *
 * Contract: packages/protocol/src/local-first.ts, docs/local-first.md.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CommandBody, CommandPayloadV2, DecisionPayloadV2, PairingHelloRequest, RekeyPayload, RekeyRequest, type ControlCommandName } from "@agentgate/protocol";
import { canonicalJson } from "./canonical-json.ts";
import { asciiBytes, base64urlDecode, base64urlEncode, constantTimeEqual, utf8Decode, utf8Encode } from "./encoding.ts";

export { canonicalJson } from "./canonical-json.ts";
export { base64urlDecode, base64urlEncode, utf8Decode, utf8Encode } from "./encoding.ts";
export type { CommandBody, CommandPayloadV2, ControlCommandName, DecisionPayloadV2, RekeyPayload, RekeyRequest, SignedDecision } from "@agentgate/protocol";

/** Maximum signed-decision lifetime (expires_at − issued_at). */
export const MAX_DECISION_LIFETIME_MS = 5 * 60 * 1000;
/** Tolerated clock skew for a decision issued "in the future" (phone clock ahead). */
export const MAX_CLOCK_SKEW_MS = 60 * 1000;
export const SERVER_HELLO_PREFIX = "agentgate-pairing-hello:v1:";

/** Strict RFC 8032 verification (no ZIP-215 leniency): one valid signature encoding. */
const VERIFY_OPTS = { zip215: false } as const;

// ── Keys ────────────────────────────────────────────────────────────────────────────

export interface DeviceKeyPair {
  /** Raw 32-byte Ed25519 secret key (seed). Keep in the Keychain; never serialize casually. */
  privateKey: Uint8Array;
  /** Raw 32-byte public key, base64url (43 chars). */
  publicKey: string;
}

/**
 * Generate an Ed25519 key pair from an injected CSPRNG
 * (RN: expo-crypto `getRandomBytes`; Node: `crypto.randomBytes`).
 */
export function generateDeviceKeyPair(randomBytes: (n: number) => Uint8Array): DeviceKeyPair {
  const seed = randomBytes(32);
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TypeError("generateDeviceKeyPair: randomBytes(32) must return a 32-byte Uint8Array");
  }
  if (seed.every((b) => b === 0)) throw new Error("generateDeviceKeyPair: CSPRNG returned all zeros");
  const privateKey = Uint8Array.from(seed);
  return { privateKey, publicKey: publicKeyFromPrivateKey(privateKey) };
}

/** base64url raw public key for a 32-byte secret key. */
export function publicKeyFromPrivateKey(privateKey: Uint8Array): string {
  assertPrivateKey(privateKey);
  return base64urlEncode(ed25519.getPublicKey(privateKey));
}

/** First 16 bytes of SHA-256(raw public key), base64url (22 chars). Throws on a malformed key. */
export function publicKeyFingerprint(publicKeyB64url: string): string {
  const raw = decodePublicKey(publicKeyB64url);
  if (!raw) throw new TypeError("publicKeyFingerprint: expected a base64url raw 32-byte Ed25519 public key");
  return base64urlEncode(sha256(raw).slice(0, 16));
}

// ── Phone-signed decisions (v2) ─────────────────────────────────────────────────────

/**
 * Sign a decision with the device's secret key. Validates the payload against the
 * protocol schema and the lifetime rules (expires_at > issued_at, ≤ 5 min) and throws
 * on violation, so a phone can never emit a token the executor would reject for shape.
 * Returns `"v2." + b64url(canonicalJson(payload)) + "." + b64url(signature)`; the
 * signature covers the ASCII bytes of the middle segment.
 */
export function signDecision(payload: DecisionPayloadV2, privateKey: Uint8Array): string {
  assertPrivateKey(privateKey);
  if (typeof payload === "object" && payload !== null && "kind" in payload) {
    throw new TypeError("signDecision: decision payloads must not carry `kind` (use signCommand)");
  }
  return sealEnvelope(DecisionPayloadV2.parse(payload), privateKey, "signDecision");
}

/** Shared by decisions and commands: lifetime rules + "v2.<body>.<sig>". */
function sealEnvelope(parsed: { issued_at: string; expires_at: string }, privateKey: Uint8Array, who: string): string {
  const iat = Date.parse(parsed.issued_at);
  const exp = Date.parse(parsed.expires_at);
  if (!(exp > iat)) throw new RangeError(`${who}: expires_at must be after issued_at`);
  if (exp - iat > MAX_DECISION_LIFETIME_MS) throw new RangeError(`${who}: lifetime exceeds 5 minutes`);
  const body = base64urlEncode(utf8Encode(canonicalJson(parsed)));
  const sig = ed25519.sign(asciiBytes(body), privateKey);
  return `v2.${body}.${base64urlEncode(sig)}`;
}

export type DecisionVerificationFailure =
  | "malformed"
  | "unknown_device"
  | "bad_signature"
  | "invalid_payload"
  | "expired"
  | "lifetime_too_long"
  | "approval_mismatch"
  | "hash_mismatch"
  | "session_mismatch"
  | "not_approved"
  | "replayed";

export type DecisionVerificationResult =
  | { ok: true; payload: DecisionPayloadV2 }
  | { ok: false; reason: DecisionVerificationFailure };

/** Consumed-nonce registry; must be an atomic check-and-set. Compatible with @agentgate/core's NonceStore. */
export interface NonceStore {
  /** true if newly consumed, false if already used. May forget a nonce only once `now` is past `expiresAt`. */
  consume(nonce: string, expiresAt: Date, now?: Date): boolean;
}

/** In-memory NonceStore (single process). */
export class MemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  consume(nonce: string, expiresAt: Date, at?: Date): boolean {
    const now = Math.min(Date.now(), at?.getTime() ?? Infinity);
    for (const [n, exp] of this.seen) if (exp < now) this.seen.delete(n);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiresAt.getTime());
    return true;
  }
}

export interface VerifyDecisionOptions {
  /** Pinned device public key (base64url raw) for a device id, or null if unknown / revoked. */
  publicKeyFor: (deviceId: string) => string | null;
  expectedApprovalId: string;
  /** Hash recomputed by the executor from the exact action it is about to run. */
  expectedActionHash: string;
  expectedSessionId?: string;
  now?: Date;
  /** When given, the decision is single-use (nonce consumed on success only). */
  nonceStore?: NonceStore;
  /** "approve": a valid *deny* decision fails with `not_approved`. */
  requireDecision?: "approve";
}

/**
 * Verify a phone-signed decision. Every failure must be treated as a hard deny.
 * Order: parse → device key lookup → signature → schema → expiry / lifetime →
 * ids (approval, session) → constant-time hash compare → decision → nonce.
 */
export function verifyDecision(token: string, opts: VerifyDecisionOptions): DecisionVerificationResult {
  const fail = (reason: DecisionVerificationFailure): DecisionVerificationResult => ({ ok: false, reason });

  // 1–3. parse, device key lookup, signature
  const env = openEnvelope(token, opts.publicKeyFor);
  if (!env.ok) return fail(env.reason);

  // 4. schema — and domain separation: a decision never carries `kind` (commands do).
  if ("kind" in env.raw) return fail("invalid_payload");
  const parsed = DecisionPayloadV2.safeParse(env.raw);
  if (!parsed.success) return fail("invalid_payload");
  const payload = parsed.data;

  // 5. expiry and lifetime
  const now = (opts.now ?? new Date()).getTime();
  const t = checkLifetime(payload, now);
  if (t) return fail(t);
  const exp = Date.parse(payload.expires_at);

  // 6. ids
  if (payload.approval_id !== opts.expectedApprovalId) return fail("approval_mismatch");
  if (opts.expectedSessionId !== undefined && payload.session_id !== opts.expectedSessionId) return fail("session_mismatch");

  // 7. action hash (constant time)
  if (!constantTimeEqual(payload.action_hash, opts.expectedActionHash)) return fail("hash_mismatch");

  // 8. decision
  if (opts.requireDecision === "approve" && payload.decision !== "approve") return fail("not_approved");

  // 9. nonce (single use), consumed only when everything else passed
  if (opts.nonceStore && !opts.nonceStore.consume(payload.nonce, new Date(exp), new Date(now))) return fail("replayed");

  return { ok: true, payload };
}

type EnvelopeFailure = "malformed" | "unknown_device" | "bad_signature";

/** Steps 1–3 shared by every v2 envelope: parse → device key lookup → signature. */
function openEnvelope(
  token: string,
  publicKeyFor: (deviceId: string) => string | null,
): { ok: true; raw: Record<string, unknown> } | { ok: false; reason: EnvelopeFailure } {
  if (typeof token !== "string") return { ok: false, reason: "malformed" };
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v2" || !parts[1] || !parts[2]) return { ok: false, reason: "malformed" };
  const [, body, sigB64] = parts as [string, string, string];
  const sig = base64urlDecode(sigB64);
  const bodyBytes = base64urlDecode(body);
  if (!sig || sig.length !== 64 || !bodyBytes) return { ok: false, reason: "malformed" };
  const json = utf8Decode(bodyBytes);
  if (json === null) return { ok: false, reason: "malformed" };
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return { ok: false, reason: "malformed" };
  const deviceId = (raw as Record<string, unknown>).device_id;
  if (typeof deviceId !== "string" || deviceId.length === 0) return { ok: false, reason: "malformed" };

  let keyB64: string | null;
  try {
    keyB64 = publicKeyFor(deviceId);
  } catch {
    return { ok: false, reason: "unknown_device" };
  }
  const publicKey = keyB64 ? decodePublicKey(keyB64) : null;
  if (!publicKey) return { ok: false, reason: "unknown_device" };

  let sigOk = false;
  try {
    sigOk = ed25519.verify(sig, asciiBytes(body), publicKey, VERIFY_OPTS);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ok: false, reason: "bad_signature" };
  return { ok: true, raw: raw as Record<string, unknown> };
}

/** Expiry / lifetime rules shared by decisions and commands (NaN-safe, fail closed). */
function checkLifetime(p: { issued_at: string; expires_at: string }, now: number): "expired" | "invalid_payload" | "lifetime_too_long" | null {
  const iat = Date.parse(p.issued_at);
  const exp = Date.parse(p.expires_at);
  if (!(now < exp)) return "expired";
  if (!(exp > iat)) return "invalid_payload";
  // A payload "issued in the future" could otherwise stretch its validity window.
  if (!(exp - iat <= MAX_DECISION_LIFETIME_MS) || !(exp - now <= MAX_DECISION_LIFETIME_MS + MAX_CLOCK_SKEW_MS)) {
    return "lifetime_too_long";
  }
  return null;
}

// ── Phone-signed control commands (Control Center) ──────────────────────────────────

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += (b < 16 ? "0" : "") + b.toString(16);
  return out;
}

/**
 * SHA-256 hex of canonicalJson(body) after validating it against CommandBody (unknown
 * keys are stripped by the schema, exactly as on the verifying side). Throws if invalid.
 */
export function commandBodyHash(body: CommandBody): string {
  const parsed = CommandBody.parse(body);
  return toHex(sha256(utf8Encode(canonicalJson(parsed))));
}

/**
 * Sign a control command (same "v2." envelope and device key as decisions, but
 * `kind: "command"`). Validates against CommandPayloadV2 and the 5-minute lifetime;
 * throws on violation. The caller computes `payload_hash` with commandBodyHash(body).
 */
export function signCommand(payload: CommandPayloadV2, privateKey: Uint8Array): string {
  assertPrivateKey(privateKey);
  return sealEnvelope(CommandPayloadV2.parse(payload), privateKey, "signCommand");
}

export type CommandVerificationFailure =
  | "malformed"
  | "unknown_device"
  | "bad_signature"
  | "invalid_payload"
  | "expired"
  | "lifetime_too_long"
  | "session_mismatch"
  | "body_mismatch"
  | "command_not_allowed"
  | "replayed";

export type CommandVerificationResult =
  | { ok: true; payload: CommandPayloadV2 }
  | { ok: false; reason: CommandVerificationFailure };

export interface VerifyCommandOptions {
  /** Pinned device public key (base64url raw) for a device id, or null if unknown / revoked. */
  publicKeyFor: (deviceId: string) => string | null;
  /** Target session id; "new" for a start command. */
  expectedSessionId: string;
  /** The command body that travelled next to the signature; its hash must equal payload_hash. */
  body: CommandBody;
  now?: Date;
  /** When given, the command is single-use (nonce consumed on success only). */
  nonceStore?: NonceStore;
  /** When given, only these commands are accepted (e.g. what the session `can` do right now). */
  allowedCommands?: readonly ControlCommandName[];
}

/**
 * Verify a phone-signed control command. Every failure must be treated as "do not act".
 * Order: parse → device key lookup → signature → schema (kind must be "command") →
 * expiry / lifetime → session → body (hash + command name, constant-time) →
 * allowed commands → nonce.
 */
export function verifyCommand(token: string, opts: VerifyCommandOptions): CommandVerificationResult {
  const fail = (reason: CommandVerificationFailure): CommandVerificationResult => ({ ok: false, reason });

  const env = openEnvelope(token, opts.publicKeyFor);
  if (!env.ok) return fail(env.reason);

  // Domain separation: CommandPayloadV2 requires kind === "command"; decisions have no kind.
  const parsed = CommandPayloadV2.safeParse(env.raw);
  if (!parsed.success || env.raw.kind !== "command") return fail("invalid_payload");
  const payload = parsed.data;

  const now = (opts.now ?? new Date()).getTime();
  const t = checkLifetime(payload, now);
  if (t) return fail(t);

  if (payload.session_id !== opts.expectedSessionId) return fail("session_mismatch");

  let bodyHash: string;
  try {
    bodyHash = commandBodyHash(opts.body);
  } catch {
    return fail("body_mismatch");
  }
  if (!constantTimeEqual(bodyHash, payload.payload_hash)) return fail("body_mismatch");
  if ((opts.body as { command?: unknown }).command !== payload.command) return fail("body_mismatch");

  if (opts.allowedCommands && !opts.allowedCommands.includes(payload.command)) return fail("command_not_allowed");

  const exp = Date.parse(payload.expires_at);
  if (opts.nonceStore && !opts.nonceStore.consume(payload.nonce, new Date(exp), new Date(now))) return fail("replayed");

  return { ok: true, payload };
}

// ── Pairing: server proves possession of its identity key ───────────────────────────

function helloMessage(challenge: string): Uint8Array {
  return utf8Encode(SERVER_HELLO_PREFIX + challenge);
}

/** Server side: sign the phone's challenge. Returns the base64url signature (86 chars). */
export function signServerHello(challenge: string, serverPrivateKey: Uint8Array): string {
  assertPrivateKey(serverPrivateKey);
  PairingHelloRequest.parse({ challenge });
  return base64urlEncode(ed25519.sign(helloMessage(challenge), serverPrivateKey));
}

/**
 * Phone side: true only if `serverPublicKey` has the fingerprint pinned from the QR AND
 * `signature` is its valid signature over the challenge. Never throws.
 */
export function verifyServerHello(
  challenge: string,
  signature: string,
  serverPublicKey: string,
  expectedFingerprint: string,
): boolean {
  try {
    if (!PairingHelloRequest.safeParse({ challenge }).success) return false;
    const raw = decodePublicKey(serverPublicKey);
    if (!raw) return false;
    if (!constantTimeEqual(publicKeyFingerprint(serverPublicKey), expectedFingerprint)) return false;
    const sig = base64urlDecode(signature);
    if (!sig || sig.length !== 64) return false;
    return ed25519.verify(sig, helloMessage(challenge), raw, VERIFY_OPTS);
  } catch {
    return false;
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────────────

// ── Device key rotation (rekey) ─────────────────────────────────────────────────────

/**
 * Domain separation: rekey signatures cover UTF-8("agentgate-rekey:v1:" + canonicalJson(payload)).
 * Decisions and commands sign the ASCII of a base64url segment (no ':' possible), and the
 * pairing hello uses its own prefix — a signature can never be reused across these.
 */
export const REKEY_PREFIX = "agentgate-rekey:v1:";

export function rekeyMessage(payload: RekeyPayload): Uint8Array {
  const p = RekeyPayload.parse(payload);
  return utf8Encode(REKEY_PREFIX + canonicalJson({ device_id: p.device_id, new_public_key: p.new_public_key, issued_at: p.issued_at, expires_at: p.expires_at, nonce: p.nonce }));
}

/**
 * Sign a key rotation with the device's OLD secret key. Returns the full RekeyRequest body.
 * Throws on a malformed payload, a lifetime > 5 min, or when the new key equals the old one.
 */
export function signRekey(payload: RekeyPayload, oldPrivateKey: Uint8Array): RekeyRequest {
  assertPrivateKey(oldPrivateKey);
  const p = RekeyPayload.parse(payload);
  if (!decodePublicKey(p.new_public_key)) throw new TypeError("signRekey: new_public_key is not a 32-byte Ed25519 key");
  if (p.new_public_key === publicKeyFromPrivateKey(oldPrivateKey)) throw new TypeError("signRekey: the new key must differ from the old key");
  const iat = Date.parse(p.issued_at);
  const exp = Date.parse(p.expires_at);
  if (!(exp > iat) || exp - iat > MAX_DECISION_LIFETIME_MS) throw new RangeError("signRekey: expires_at must be after issued_at and at most 5 minutes later");
  const signature = base64urlEncode(ed25519.sign(rekeyMessage(p), oldPrivateKey));
  return { ...p, signature };
}

export type RekeyVerificationFailure = "malformed" | "unknown_device" | "bad_signature" | "expired" | "lifetime_too_long" | "invalid_payload" | "same_key" | "replayed";
export type RekeyVerificationResult = { ok: true; payload: RekeyPayload } | { ok: false; reason: RekeyVerificationFailure };

export interface VerifyRekeyOptions {
  /** The device's CURRENT (old) key, base64url; null → unknown/revoked device. */
  publicKeyFor: (deviceId: string) => string | null;
  now?: Date;
  /** Single use (server). Consumed only when everything else passed. */
  nonceStore?: NonceStore;
  /**
   * Executors re-checking a historical rotation proof: signature + shape only, no clock /
   * nonce checks (the rotation already happened; what matters is that the old key signed it).
   */
  signatureOnly?: boolean;
}

/** Verify a rekey request. Order: shape → key lookup → signature → same key → lifetime → nonce. */
export function verifyRekey(req: unknown, opts: VerifyRekeyOptions): RekeyVerificationResult {
  const fail = (reason: RekeyVerificationFailure): RekeyVerificationResult => ({ ok: false, reason });
  const parsed = RekeyRequest.safeParse(req);
  if (!parsed.success) return fail("malformed");
  const { signature, ...payload } = parsed.data;
  let keyB64: string | null;
  try {
    keyB64 = opts.publicKeyFor(payload.device_id);
  } catch {
    keyB64 = null;
  }
  const oldKey = keyB64 ? decodePublicKey(keyB64) : null;
  if (!oldKey) return fail("unknown_device");
  const newKey = decodePublicKey(payload.new_public_key);
  const sig = base64urlDecode(signature);
  if (!newKey || !sig || sig.length !== 64) return fail("malformed");
  let ok = false;
  try {
    ok = ed25519.verify(sig, rekeyMessage(payload), oldKey, VERIFY_OPTS);
  } catch {
    ok = false;
  }
  if (!ok) return fail("bad_signature");
  if (keyB64 === payload.new_public_key) return fail("same_key");
  if (opts.signatureOnly) return { ok: true, payload };
  const now = (opts.now ?? new Date()).getTime();
  const lt = checkLifetime(payload, now);
  if (lt) return fail(lt);
  if (opts.nonceStore && !opts.nonceStore.consume(payload.nonce, new Date(Date.parse(payload.expires_at)), new Date(now))) return fail("replayed");
  return { ok: true, payload };
}

function assertPrivateKey(k: Uint8Array): void {
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new TypeError("expected a raw 32-byte Ed25519 private key");
}

/** Strictly decode a base64url raw 32-byte public key that is a valid curve point, or null. */
function decodePublicKey(b64: string): Uint8Array | null {
  if (typeof b64 !== "string" || b64.length !== 43) return null;
  const raw = base64urlDecode(b64);
  if (!raw || raw.length !== 32) return null;
  try {
    return ed25519.utils.isValidPublicKey(raw, false) ? raw : null;
  } catch {
    return null;
  }
}
