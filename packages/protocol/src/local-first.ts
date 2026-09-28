import { z } from "zod";

/**
 * M7 local-first contract (see docs/local-first.md).
 *
 * Encoding conventions:
 *  - Ed25519 public keys: raw 32 bytes, base64url (no padding) → 43 chars.
 *  - Fingerprint: first 16 bytes of SHA-256(raw public key), base64url → 22 chars.
 *  - Signatures: raw 64 bytes, base64url → 86 chars.
 *  - Signed payloads are canonical JSON (RFC 8785 style, see core/canonicalJson),
 *    UTF-8, base64url-encoded; the signature covers the base64url string's bytes.
 */

const b64url = (min: number, max: number) =>
  z.string().min(min).max(max).regex(/^[A-Za-z0-9_-]+$/);

export const Ed25519PublicKey = b64url(43, 43);
export const KeyFingerprint = b64url(22, 22);

// ── QR v2 ────────────────────────────────────────────────────────────────────
/**
 * agentgate://pair?v=2&url=<server url>&code=<pairing code>&fp=<server key fingerprint>
 *   [&name=<machine name>][&relay=<relay url>&room=<room id>]   (relay: phase 2)
 * Parsed form:
 */
export const PairingLinkV2 = z.object({
  v: z.literal(2),
  url: z.string().url(),
  code: z.string().min(8).max(32),
  fp: KeyFingerprint,
  name: z.string().max(128).optional(),
  relay: z.string().url().optional(),
  room: z.string().max(128).optional(),
});
export type PairingLinkV2 = z.infer<typeof PairingLinkV2>;

/**
 * POST /v1/pairing/hello (public) — the phone proves it is talking to the server whose
 * key fingerprint was in the QR. The server signs `challenge` (≥ 32 random bytes chosen
 * by the phone, base64url) with its identity key:
 *   signature over UTF-8 bytes of "agentgate-pairing-hello:v1:" + challenge
 */
export const PairingHelloRequest = z.object({
  challenge: b64url(43, 128),
  /** Re-pairing phones send their existing device id: `already_paired` tells them to rekey instead. */
  device_id: z.string().min(1).max(64).optional(),
});
export const PairingHelloResponse = z.object({
  server_public_key: Ed25519PublicKey,
  signature: b64url(86, 86),
  machine_name: z.string(),
  /** Local-first servers have a single owner; the phone never needs an email. */
  owner: z.object({ id: z.string(), display_name: z.string() }),
  /** true = `device_id` from the request is an active (non-revoked) device here → use POST /v1/devices/:id/rekey. */
  already_paired: z.boolean().optional(),
});
export type PairingHelloResponse = z.infer<typeof PairingHelloResponse>;

/**
 * Device login additions (LoginRequest in api.ts stays valid): in local-first mode the
 * device sends its public key; `email` may be omitted when the server is local-first
 * (the server maps the device to its single owner).
 */
export const DeviceKeyRegistration = z.object({
  device_public_key: Ed25519PublicKey,
});

// ── Phone-signed approval decisions (approval token v2) ─────────────────────
export const DecisionPayloadV2 = z.object({
  v: z.literal(2),
  approval_id: z.string(),
  action_id: z.string(),
  session_id: z.string(),
  action_hash: z.string().regex(/^[a-f0-9]{64}$/),
  decision: z.enum(["approve", "deny"]),
  device_id: z.string(),
  issued_at: z.string().datetime(),
  /** ≤ approval expires_at and ≤ issued_at + 5 min. */
  expires_at: z.string().datetime(),
  nonce: b64url(16, 64),
});
export type DecisionPayloadV2 = z.infer<typeof DecisionPayloadV2>;

/**
 * Compact form: "v2." + base64url(canonicalJson(payload)) + "." + base64url(signature)
 * The signature covers the ASCII bytes of the middle segment. The device signs; the
 * executor verifies against the pinned device public key. Sent by the phone in
 * ResolveApprovalRequest.signed_decision and relayed unchanged as
 * ApprovalResolvedEvent.approval_token.
 */
export const SignedDecision = z.string().regex(/^v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$/);
export type SignedDecision = z.infer<typeof SignedDecision>;

/** POST /v1/approvals/:id/approve|deny body in local-first mode. */
export const ResolveApprovalRequestV2 = z.object({
  device_id: z.string(),
  signed_decision: SignedDecision,
});

/**
 * GET /v1/devices/keys (agent token, loopback only): the executor fetches device keys
 * and pins them by device id on first sight; a changed key for a known id is refused.
 */
export const DeviceKeysResponse = z.object({
  items: z.array(
    z.object({
      device_id: z.string(),
      public_key: Ed25519PublicKey,
      fingerprint: KeyFingerprint,
      revoked_at: z.string().datetime().nullable(),
      /** Set when the device rotated its key (POST /v1/devices/:id/rekey). */
      rekeyed_at: z.string().datetime().nullable().optional(),
      /** The latest rotation, signed by the PREVIOUS key: executors verify it against their pin. */
      rekey_proof: z.lazy(() => RekeyRequest).nullable().optional(),
    }),
  ),
});
export type DeviceKeysResponse = z.infer<typeof DeviceKeysResponse>;

// ── Device key rotation (same phone, new key) ─────────────────────────────────
/**
 * POST /v1/devices/:id/rekey (public — the proof is the signature). A phone that still holds
 * its old key rotates to a new one without a new pairing. Signature (Ed25519, OLD key) over the
 * UTF-8 bytes of:
 *   "agentgate-rekey:v1:" + canonicalJson({device_id, new_public_key, issued_at, expires_at, nonce})
 * expires_at − issued_at ≤ 5 min; nonce single use. Response: LoginResponse (device-bound token).
 */
export const RekeyPayload = z.object({
  device_id: z.string().min(1).max(64),
  new_public_key: Ed25519PublicKey,
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  nonce: b64url(16, 64),
});
export type RekeyPayload = z.infer<typeof RekeyPayload>;
export const RekeyRequest = RekeyPayload.extend({ signature: b64url(86, 86) });
export type RekeyRequest = z.infer<typeof RekeyRequest>;
