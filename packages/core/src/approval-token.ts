import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { ApprovalTokenPayload } from "@agentgate/protocol";
import { canonicalJson } from "./canonical-json.ts";

/**
 * Signed approval tokens (Ed25519).
 *
 * Format: base64url(canonical JSON payload) "." base64url(signature over the first part)
 *
 * The server signs when an approval resolves as approved. The executor (daemon)
 * verifies against the server's public key immediately before execution, binding
 * the human decision to the exact action about to run (TOCTOU protection).
 */

export function generateSigningKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function newNonce(): string {
  return randomBytes(18).toString("base64url");
}

export function signApprovalToken(payload: ApprovalTokenPayload, privateKeyPem: string): string {
  const parsed = ApprovalTokenPayload.parse(payload);
  const body = Buffer.from(canonicalJson(parsed), "utf8").toString("base64url");
  const sig = sign(null, Buffer.from(body, "utf8"), createPrivateKey(privateKeyPem));
  return `${body}.${sig.toString("base64url")}`;
}

export type TokenVerificationFailure =
  | "malformed"
  | "bad_signature"
  | "invalid_payload"
  | "expired"
  | "hash_mismatch"
  | "approval_mismatch"
  | "replayed";

export type TokenVerificationResult =
  | { ok: true; payload: ApprovalTokenPayload }
  | { ok: false; reason: TokenVerificationFailure };

/** Consumed-nonce registry. Implementations must be atomic check-and-set. */
export interface NonceStore {
  /**
   * Returns true if the nonce was newly consumed, false if it was already used.
   * `now` is the verifier's clock; a store may only forget a nonce once `now` is past
   * its expiry (otherwise a replay could slip through when clocks disagree).
   */
  consume(nonce: string, expiresAt: Date, now?: Date): boolean;
}

export class MemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  consume(nonce: string, expiresAt: Date, at?: Date): boolean {
    // Purge only entries expired by *both* clocks: never forget a nonce the verifier
    // would still consider live.
    const now = Math.min(Date.now(), at?.getTime() ?? Infinity);
    for (const [n, exp] of this.seen) if (exp < now) this.seen.delete(n);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, expiresAt.getTime());
    return true;
  }
}

export interface VerifyOptions {
  publicKeyPem: string;
  /** Hash recomputed by the executor from the action it is about to run. */
  expectedActionHash: string;
  expectedApprovalId?: string;
  now?: Date;
  /** When given, the token is single-use. */
  nonceStore?: NonceStore;
}

/** Verifies a token. Every failure is a hard deny — callers must fail closed. */
export function verifyApprovalToken(token: string, opts: VerifyOptions): TokenVerificationResult {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "malformed" };
  const [body, sigB64] = parts as [string, string];

  let signatureOk = false;
  try {
    signatureOk = verify(
      null,
      Buffer.from(body, "utf8"),
      createPublicKey(opts.publicKeyPem),
      Buffer.from(sigB64, "base64url"),
    );
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!signatureOk) return { ok: false, reason: "bad_signature" };

  let payload: ApprovalTokenPayload;
  try {
    const parsed = ApprovalTokenPayload.safeParse(JSON.parse(Buffer.from(body, "base64url").toString("utf8")));
    if (!parsed.success) return { ok: false, reason: "invalid_payload" };
    payload = parsed.data;
  } catch {
    return { ok: false, reason: "invalid_payload" };
  }

  const now = opts.now ?? new Date();
  const expiresAt = new Date(payload.expires_at);
  // Written as !(now < exp) so an invalid `now` (NaN) fails closed.
  if (!(now.getTime() < expiresAt.getTime())) return { ok: false, reason: "expired" };
  if (opts.expectedApprovalId && payload.approval_id !== opts.expectedApprovalId) {
    return { ok: false, reason: "approval_mismatch" };
  }
  if (!timingSafeEqualHex(payload.action_hash, opts.expectedActionHash)) {
    return { ok: false, reason: "hash_mismatch" };
  }
  if (opts.nonceStore && !opts.nonceStore.consume(payload.nonce, expiresAt, now)) {
    return { ok: false, reason: "replayed" };
  }
  return { ok: true, payload };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
