import { z } from "zod";
import { ActionDraft, CanonicalAction, PolicyDecision, RiskLevel } from "./action.ts";
import { Approval, ApprovalStatus, ApprovalToken } from "./approval.ts";

/**
 * HTTP API contract, v1. All bodies are JSON. All endpoints except /v1/auth/* and
 * /v1/keys require `Authorization: Bearer <access_token>`.
 * Errors: { error: { code: string, message: string } } with a 4xx/5xx status.
 */

export const ApiError = z.object({
  error: z.object({ code: z.string(), message: z.string() }),
});
export type ApiError = z.infer<typeof ApiError>;

// ── Auth (development magic-link stand-in) ──────────────────────────────────
export const LoginRequest = z.object({
  /** Required on multi-user (dev) servers; omitted in local-first mode (single owner). */
  email: z.string().email().optional(),
  /** "device" for mobile, "agent" for daemon. Determines token audience + TTL. */
  client: z.enum(["device", "agent"]),
  /**
   * Required for client "device": a one-time code from `agentgate pair` (POST /v1/pairing).
   * Case-insensitive; spaces/dashes ignored. Missing → 401 pairing_required;
   * wrong/expired/used → 401 invalid_pairing_code.
   */
  pairing_code: z.string().min(1).max(32).optional(),
  /** Device clients: shown to the already-paired device that must approve this pairing. */
  device_name: z.string().min(1).max(128).optional(),
  /** Device clients: ios|android|web. Agent clients (remote login): macos|linux|windows. */
  platform: z.enum(["ios", "android", "web", "macos", "linux", "windows"]).optional(),
  /**
   * Agent clients logging in from ANOTHER computer (not loopback): shown on the phone,
   * which must approve it. The response is then 202 PairingPendingResponse (kind "agent").
   * Without any paired device → 403 pair_phone_first.
   */
  machine_name: z.string().min(1).max(128).optional(),
});
export type LoginRequest = z.infer<typeof LoginRequest>;

/**
 * Device login with a valid pairing code when the user ALREADY has an active device:
 * HTTP 202 with this body. The new device long-polls GET /v1/pairing/requests/:id
 * (header `X-Pairing-Secret: <poll_secret>`, no bearer) until an existing device
 * approves or denies. The first device of a user (bootstrap) gets 200 LoginResponse.
 */
export const PairingPendingResponse = z.object({
  status: z.literal("pending_approval"),
  pairing_request_id: z.string(),
  /** Secret only the new device holds; never shown elsewhere. */
  poll_secret: z.string().min(16),
  expires_at: z.string().datetime(),
});
export type PairingPendingResponse = z.infer<typeof PairingPendingResponse>;

export const PAIRING_REQUEST_STATUSES = ["pending", "approved", "denied", "expired"] as const;
export const PairingRequestStatus = z.enum(PAIRING_REQUEST_STATUSES);
export type PairingRequestStatus = z.infer<typeof PairingRequestStatus>;

/** What an existing device sees when asked to approve a new one. */
export const PAIRING_REQUEST_KINDS = ["device", "agent"] as const;
export const PairingRequestKind = z.enum(PAIRING_REQUEST_KINDS);
export type PairingRequestKind = z.infer<typeof PairingRequestKind>;

export const PairingRequest = z.object({
  id: z.string(),
  status: PairingRequestStatus,
  /**
   * "device": a new phone/tablet wants to become an approver.
   * "agent": a new COMPUTER wants to run agents (remote `agentgate login`); approving it
   * issues an agent token + refresh token to that computer. Defaults to "device".
   */
  kind: PairingRequestKind.default("device"),
  /** Name of the device, or of the computer for kind "agent" (same as machine_name). */
  device_name: z.string(),
  /** kind "agent": the computer's name; null for devices. */
  machine_name: z.string().nullable().optional(),
  platform: z.string(),
  /** Requesting client's IP as seen by the server. */
  ip: z.string().nullable(),
  requested_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  resolved_at: z.string().datetime().nullable(),
});
export type PairingRequest = z.infer<typeof PairingRequest>;

/**
 * GET /v1/pairing/requests/:id (X-Pairing-Secret) — long-poll up to ~25 s.
 * `login` is present exactly once, on the first poll after approval, then consumed.
 */
export const PairingPollResponse = z.object({
  status: PairingRequestStatus,
  login: z.lazy(() => LoginResponse).nullable(),
});
export type PairingPollResponse = z.infer<typeof PairingPollResponse>;

/** GET /v1/pairing/requests?status=pending (device token). */
export const ListPairingRequestsResponse = z.object({ items: z.array(PairingRequest) });
/** POST /v1/pairing/requests/:id/approve | /deny (device token). */
export const ResolvePairingRequest = z.object({ device_id: z.string() });
export const ResolvePairingResponse = z.object({ request: PairingRequest });

/** POST /v1/pairing (agent token) → one-time device pairing code, 5 min TTL. */
export const PairingResponse = z.object({
  /** 8 chars, Crockford base32, e.g. "7KQ2-MZ9D" when displayed. */
  code: z.string(),
  expires_at: z.string().datetime(),
  /** Server's public URL (AGENTGATE_PUBLIC_URL, e.g. https://mac.tailnet.ts.net) to put in the pairing QR. */
  public_url: z.string().url().optional(),
});
export type PairingResponse = z.infer<typeof PairingResponse>;
export const LoginResponse = z.object({
  access_token: z.string(),
  expires_at: z.string().datetime(),
  user: z.object({ id: z.string(), email: z.string() }),
  /**
   * Rotating refresh token. Single use: exchange it at POST /v1/auth/refresh for a new
   * access token AND a new refresh token.
   * - Agent clients: 30-day lifetime, sliding on each rotation.
   * - Paired devices (every device-bound LoginResponse: pairing-code login, approved
   *   pairing request poll, rekey): 90-day lifetime, sliding; bound to `device_id`.
   *   Revoking the device (or local recovery revoke/reset, or a rekey) revokes it.
   * Absent for unbound device logins (dev-only open device login).
   */
  refresh_token: z.string().optional(),
  /**
   * Device clients: the device record created at login. The access token is bound to
   * this device id; revoking the device invalidates the token (401 device_revoked).
   */
  device_id: z.string().optional(),
});
export type LoginResponse = z.infer<typeof LoginResponse>;

/**
 * POST /v1/auth/refresh (public). Rotates the refresh token: the presented token is
 * consumed; presenting an already-consumed token revokes its whole token family
 * (reuse detection) → 401 { error: { code: "refresh_token_reused" } }.
 * Other failures: 401 invalid_refresh_token | refresh_token_expired | refresh_token_revoked,
 * and for device-bound tokens 401 device_revoked (the device was revoked / reset — the phone
 * is unpaired and must pair again; checked before the other codes).
 * Device-bound refresh tokens yield a device access token (aud device) bound to the same
 * device id, returned as `device_id`.
 */
export const RefreshRequest = z.object({ refresh_token: z.string().min(1).max(512) });
export type RefreshRequest = z.infer<typeof RefreshRequest>;
export const RefreshResponse = z.object({
  access_token: z.string(),
  expires_at: z.string().datetime(),
  refresh_token: z.string(),
  /** Present for device-bound refresh tokens: the device the new access token is bound to. */
  device_id: z.string().optional(),
});
export type RefreshResponse = z.infer<typeof RefreshResponse>;

export const KeysResponse = z.object({
  /** Ed25519 public key (SPKI, PEM) used to verify approval tokens. */
  approval_signing_key: z.object({ kid: z.string(), alg: z.literal("Ed25519"), pem: z.string() }),
});
export type KeysResponse = z.infer<typeof KeysResponse>;

// ── Devices ─────────────────────────────────────────────────────────────────
export const RegisterDeviceRequest = z.object({
  name: z.string().min(1).max(128),
  platform: z.enum(["ios", "android", "web"]),
  push_token: z.string().max(512).nullable(),
});
export const Device = z.object({
  id: z.string(),
  name: z.string(),
  platform: z.string(),
  push_token: z.string().nullable(),
  created_at: z.string().datetime(),
});
export type Device = z.infer<typeof Device>;

/** GET /v1/devices (device token): the user's devices. */
export const DeviceSummary = Device.omit({ push_token: true }).extend({
  last_seen_at: z.string().datetime().nullable(),
  revoked_at: z.string().datetime().nullable(),
  /** True for the device whose token made the request. */
  current: z.boolean(),
  has_push: z.boolean(),
});
export type DeviceSummary = z.infer<typeof DeviceSummary>;
export const ListDevicesResponse = z.object({ items: z.array(DeviceSummary) });
/**
 * POST /v1/devices/:id/revoke (device token). A device may revoke itself or another
 * device of the same user; revoking the last active device is allowed (next login is
 * then a bootstrap pairing again). Revoked device tokens → 401 device_revoked.
 */
export const RevokeDeviceResponse = z.object({ device: DeviceSummary });

// ── Agents & sessions ───────────────────────────────────────────────────────
export const RegisterAgentRequest = z.object({
  name: z.string().min(1).max(128),
  type: z.string().min(1).max(64),
  machine_id: z.string().min(1).max(128),
});
export const Agent = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  machine_id: z.string(),
  created_at: z.string().datetime(),
});
export type Agent = z.infer<typeof Agent>;

export const CreateSessionRequest = z.object({ agent_id: z.string() });
export const Session = z.object({
  id: z.string(),
  agent_id: z.string(),
  status: z.enum(["active", "ended"]),
  started_at: z.string().datetime(),
  ended_at: z.string().datetime().nullable(),
});
export type Session = z.infer<typeof Session>;

// ── Actions ─────────────────────────────────────────────────────────────────
/**
 * POST /v1/actions — the daemon reports every intercepted action together with
 * the local policy decision. If decision === "ask" the server creates an approval
 * in the same transaction and notifies devices.
 * The server recomputes action_hash itself; the client value is only cross-checked.
 */
export const SubmitActionRequest = z.object({
  action: ActionDraft,
  policy: z.object({
    decision: PolicyDecision,
    rule_id: z.string().nullable(),
    risk: RiskLevel,
    reason: z.string(),
  }),
  action_hash: z.string().regex(/^[a-f0-9]{64}$/),
  /** Approval TTL in seconds (ask only). Server clamps to [30, 900]. */
  approval_ttl_seconds: z.number().int().positive().optional(),
});
export type SubmitActionRequest = z.infer<typeof SubmitActionRequest>;

export const ActionRecord = z.object({
  action: CanonicalAction,
  action_hash: z.string(),
  policy_decision: PolicyDecision,
  approval: Approval.nullable(),
  execution: z.enum(["not_started", "started", "completed", "failed", "blocked"]),
});
export type ActionRecord = z.infer<typeof ActionRecord>;

export const SubmitActionResponse = ActionRecord;

/** POST /v1/actions/:id/execution — daemon reports execution lifecycle. */
export const ReportExecutionRequest = z.object({
  status: z.enum(["started", "completed", "failed", "blocked"]),
  exit_code: z.number().int().nullable().optional(),
  detail: z.string().max(2048).optional(),
});

// ── Approvals ───────────────────────────────────────────────────────────────
/** GET /v1/approvals/:id and list items: approval joined with its action. */
export const ApprovalDetail = z.object({
  approval: Approval,
  action: CanonicalAction,
  action_hash: z.string(),
  agent_name: z.string().nullable(),
});
export type ApprovalDetail = z.infer<typeof ApprovalDetail>;

export const ListApprovalsQuery = z.object({
  status: ApprovalStatus.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
export const ListApprovalsResponse = z.object({ items: z.array(ApprovalDetail) });

/** POST /v1/approvals/:id/approve | /deny */
export const ResolveApprovalRequest = z.object({ device_id: z.string() });
export const ResolveApprovalResponse = z.object({
  approval: Approval,
  /** Present only when approved. */
  approval_token: ApprovalToken.nullable(),
});
export type ResolveApprovalResponse = z.infer<typeof ResolveApprovalResponse>;

/**
 * POST /v1/approvals/:id/cancel (agent token). Cancels a still-pending approval, e.g. the
 * agent gave up waiting (hook deadline, Ctrl-C, agent session ended). Only the owning
 * user; when session_id is given it must be the approval's session (403 otherwise).
 * Idempotent: an already-cancelled approval returns 200. Any other terminal status →
 * 409 approval_already_resolved | approval_expired with the current approval.
 * On success devices and the agent receive approval.resolved { status: "cancelled" }.
 */
export const CancelApprovalRequest = z.object({
  session_id: z.string().min(1).max(64).optional(),
  reason: z.string().max(128).optional(),
});
export type CancelApprovalRequest = z.infer<typeof CancelApprovalRequest>;
export const CancelApprovalResponse = z.object({ approval: Approval });
export type CancelApprovalResponse = z.infer<typeof CancelApprovalResponse>;

// ── Activity / audit ────────────────────────────────────────────────────────
export const AUDIT_EVENTS = [
  "action.reported",
  "action.allowed",
  "action.denied_by_policy",
  "approval.requested",
  "approval.viewed",
  "approval.approved",
  "approval.denied",
  "approval.expired",
  "approval.cancelled",
  "execution.started",
  "execution.completed",
  "execution.failed",
  "execution.blocked",
  "session.started",
  "session.ended",
  "device.registered",
  "device.paired",
  "pairing.created",
  "device.pairing_requested",
  "device.pairing_approved",
  "device.pairing_denied",
  "device.revoked",
  "device.rekeyed",
  "device.recovery_reset",
  "agent.login_requested",
  "agent.login_approved",
  "agent.login_denied",
] as const;
export const AuditEvent = z.enum(AUDIT_EVENTS);
export type AuditEvent = z.infer<typeof AuditEvent>;

export const AuditLogEntry = z.object({
  id: z.string(),
  event: AuditEvent,
  action_id: z.string().nullable(),
  approval_id: z.string().nullable(),
  summary: z.string(),
  payload: z.record(z.string(), z.unknown()),
  created_at: z.string().datetime(),
});
export type AuditLogEntry = z.infer<typeof AuditLogEntry>;
export const ActivityResponse = z.object({ items: z.array(AuditLogEntry) });
