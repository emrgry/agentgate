import { z } from "zod";

export const APPROVAL_STATUSES = ["pending", "approved", "denied", "expired", "cancelled"] as const;
export const ApprovalStatus = z.enum(APPROVAL_STATUSES);
export type ApprovalStatus = z.infer<typeof ApprovalStatus>;

export const TERMINAL_STATUSES: readonly ApprovalStatus[] = [
  "approved",
  "denied",
  "expired",
  "cancelled",
];

export const Approval = z.object({
  approval_id: z.string(),
  action_id: z.string(),
  status: ApprovalStatus,
  decision: z.enum(["approve", "deny"]).nullable(),
  requested_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  resolved_at: z.string().datetime().nullable(),
  resolved_by_device_id: z.string().nullable(),
});
export type Approval = z.infer<typeof Approval>;

/**
 * Payload signed by the server when an approval resolves as approved.
 * The executor MUST verify: signature, action_hash == hash(action it is about to run),
 * expires_at > now, and that the nonce has not been consumed.
 */
export const ApprovalTokenPayload = z.object({
  v: z.literal(1),
  approval_id: z.string(),
  action_id: z.string(),
  session_id: z.string(),
  action_hash: z.string().regex(/^[a-f0-9]{64}$/),
  decision: z.literal("approved"),
  expires_at: z.string().datetime(),
  nonce: z.string().min(16),
  issued_at: z.string().datetime(),
});
export type ApprovalTokenPayload = z.infer<typeof ApprovalTokenPayload>;

/**
 * v1 (server-signed): base64url(JSON payload) + "." + base64url(Ed25519 signature).
 * v2 (phone-signed, M7): "v2." + base64url(payload) + "." + base64url(signature) — see
 * SignedDecision in local-first.ts; relayed verbatim by the server.
 */
export const ApprovalToken = z
  .string()
  .max(8192)
  .regex(/^(?:v2\.)?[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
export type ApprovalToken = z.infer<typeof ApprovalToken>;
