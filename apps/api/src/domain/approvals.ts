import { and, desc, eq, gt, lte, sql } from "drizzle-orm";
import { isExpired, newId, newNonce, transitionApproval } from "@agentgate/core";
import type { Approval, ApprovalDetail, ApprovalStatus, AuditEvent } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import {
  actions,
  agents,
  approvals,
  auditLogs,
  sessions,
  type ActionRow,
  type AgentRow,
  type ApprovalRow,
  type SessionRow,
} from "../db/schema.ts";
import type { ApprovalSigner } from "../keys.ts";
import { actionAuditFields, actionLabel, mcpFields, writeAudit } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";
import { conflict, DomainError, forbidden, notFound } from "./errors.ts";
import { verifyDecision } from "@agentgate/signing";
import { requireOwnedDevice } from "./identity.ts";
import { approvalPatch, toApproval, toCanonicalAction } from "./mappers.ts";

export const DEFAULT_APPROVAL_TTL_SECONDS = 120;
export const MIN_APPROVAL_TTL_SECONDS = 30;
export const MAX_APPROVAL_TTL_SECONDS = 900;
/** Approval tokens outlive the approval window by at most this much… */
const TOKEN_GRACE_MS = 60_000;
/** …and never live longer than this after issuance. */
const TOKEN_MAX_LIFETIME_MS = 5 * 60_000;

export function clampTtl(ttl: number | undefined): number {
  if (ttl === undefined) return DEFAULT_APPROVAL_TTL_SECONDS;
  return Math.min(MAX_APPROVAL_TTL_SECONDS, Math.max(MIN_APPROVAL_TTL_SECONDS, Math.floor(ttl)));
}

export interface ApprovalJoin {
  approval: ApprovalRow;
  action: ActionRow;
  session: SessionRow;
  agent: AgentRow;
}

function joinedQuery(db: Db) {
  return db
    .select({ approval: approvals, action: actions, session: sessions, agent: agents })
    .from(approvals)
    .innerJoin(actions, eq(actions.id, approvals.action_id))
    .innerJoin(sessions, eq(sessions.id, actions.session_id))
    .innerJoin(agents, eq(agents.id, sessions.agent_id));
}

async function loadOwned(db: Db, userId: string, approvalId: string): Promise<ApprovalJoin> {
  const [row] = await joinedQuery(db)
    .where(and(eq(approvals.id, approvalId), eq(agents.user_id, userId)))
    .limit(1);
  if (!row) throw notFound("approval");
  return row;
}

export function toDetail(j: ApprovalJoin): ApprovalDetail {
  return {
    approval: toApproval(j.approval),
    action: toCanonicalAction(j.action),
    action_hash: j.action.action_hash,
    agent_name: j.agent.name,
  };
}

/**
 * Signs the approval token for an approved approval. Fully derived from stored fields
 * (nonce, resolved_at, expires_at), and Ed25519 is deterministic, so re-issuing yields the
 * byte-identical token — which lets a reconnecting daemon recover it via GET.
 */
export function tokenFor(signer: ApprovalSigner, apr: ApprovalRow, act: ActionRow): string | null {
  if (apr.status !== "approved") return null;
  // v2: the phone's own signed decision is the approval token; the server signs nothing.
  if (apr.signed_decision) return apr.signed_decision;
  if (!apr.token_nonce || !apr.resolved_at) return null;
  const issued = apr.resolved_at.getTime();
  const expires = Math.min(apr.expires_at.getTime() + TOKEN_GRACE_MS, issued + TOKEN_MAX_LIFETIME_MS);
  return signer.sign({
    v: 1,
    approval_id: apr.id,
    action_id: apr.action_id,
    session_id: act.session_id,
    action_hash: act.action_hash,
    decision: "approved",
    expires_at: new Date(expires).toISOString(),
    nonce: apr.token_nonce,
    issued_at: new Date(issued).toISOString(),
  });
}

function tokenExpired(apr: ApprovalRow, now: Date): boolean {
  if (!apr.resolved_at) return true;
  const expires = Math.min(apr.expires_at.getTime() + TOKEN_GRACE_MS, apr.resolved_at.getTime() + TOKEN_MAX_LIFETIME_MS);
  return now.getTime() >= expires;
}

/** Inserts a pending approval. Must run inside the caller's transaction. */
export async function insertPendingApproval(
  tx: Db,
  input: { userId: string; action: ActionRow; agentName: string; ttlSeconds: number | undefined; now: Date },
): Promise<ApprovalRow> {
  const ttl = clampTtl(input.ttlSeconds);
  const [row] = await tx
    .insert(approvals)
    .values({
      id: newId("apr"),
      action_id: input.action.id,
      status: "pending",
      requested_at: input.now,
      expires_at: new Date(input.now.getTime() + ttl * 1000),
    })
    .returning();
  await writeAudit(tx, {
    userId: input.userId,
    event: "approval.requested",
    actionId: input.action.id,
    approvalId: row!.id,
    payload: {
      ...actionAuditFields(toCanonicalAction(input.action)),
      agent_name: input.agentName,
      session_id: input.action.session_id,
      ttl_seconds: ttl,
      expires_at: row!.expires_at.toISOString(),
    },
    at: input.now,
  });
  return row!;
}

/** POST /v1/approvals — explicit approval for an already-reported action. */
export async function requestApprovalForAction(
  deps: ServiceDeps,
  userId: string,
  input: { action_id: string; ttl_seconds?: number | undefined },
): Promise<ApprovalDetail> {
  const [owned] = await deps.db
    .select({ action: actions, session: sessions, agent: agents })
    .from(actions)
    .innerJoin(sessions, eq(sessions.id, actions.session_id))
    .innerJoin(agents, eq(agents.id, sessions.agent_id))
    .where(and(eq(actions.id, input.action_id), eq(agents.user_id, userId)))
    .limit(1);
  if (!owned) throw notFound("action");
  if (owned.session.status !== "active") throw conflict("session_ended", "session has ended");
  if (owned.action.execution_status !== "not_started") {
    throw conflict("action_not_pending", `action execution is already '${owned.action.execution_status}'`);
  }
  const now = deps.clock.now();
  const approval = await deps.db.transaction(async (tx) => {
    const existing = await tx.select({ id: approvals.id }).from(approvals).where(eq(approvals.action_id, owned.action.id));
    if (existing.length > 0) throw conflict("approval_exists", "an approval already exists for this action");
    return insertPendingApproval(tx, {
      userId,
      action: owned.action,
      agentName: owned.agent.name,
      ttlSeconds: input.ttl_seconds,
      now,
    });
  });
  const detail = toDetail({ ...owned, approval });
  deps.notifier.approvalCreated(userId, detail);
  return detail;
}

/**
 * Writes a state-machine result with compare-and-set on status='pending' and audits it in
 * the same transaction. Returns null if another writer resolved the approval first.
 * Notifies (WS + agent) only after commit.
 */
async function commitTransition(
  deps: ServiceDeps,
  j: ApprovalJoin,
  next: Approval,
  audit: { event: AuditEvent; payload?: Record<string, unknown> },
  tokenNonce: string | null = null,
  signedDecision: string | null = null,
): Promise<ApprovalRow | null> {
  const now = next.resolved_at ? new Date(next.resolved_at) : deps.clock.now();
  const updated = await deps.db.transaction(async (tx) => {
    const [row] = await tx
      .update(approvals)
      .set({ ...approvalPatch(next), token_nonce: tokenNonce, signed_decision: signedDecision })
      .where(and(eq(approvals.id, j.approval.id), eq(approvals.status, "pending")))
      .returning();
    if (!row) return null;
    await writeAudit(tx, {
      userId: j.agent.user_id,
      event: audit.event,
      actionId: j.action.id,
      approvalId: row.id,
      payload: {
        label: actionLabel(toCanonicalAction(j.action)),
        agent_name: j.agent.name,
        agent_type: toCanonicalAction(j.action).agent.type,
        ...(mcpFields(toCanonicalAction(j.action)) ?? {}),
        session_id: j.session.id,
        ...audit.payload,
      },
      at: now,
    });
    return row;
  });
  if (updated) {
    deps.notifier.approvalResolved(j.agent.user_id, j.session.id, {
      type: "approval.resolved",
      approval_id: updated.id,
      action_id: updated.action_id,
      status: updated.status,
      approval_token: tokenFor(deps.signer, updated, j.action),
    });
  }
  return updated;
}

const TERMINAL_AUDIT: Record<Exclude<ApprovalStatus, "pending">, AuditEvent> = {
  approved: "approval.approved",
  denied: "approval.denied",
  expired: "approval.expired",
  cancelled: "approval.cancelled",
};

function alreadyResolved(row: ApprovalRow) {
  const approval = toApproval(row);
  if (row.status === "expired") {
    return conflict("approval_expired", "approval expired before a decision was made", { approval });
  }
  return conflict("approval_already_resolved", `approval is already ${row.status}`, { approval });
}

export interface ResolveResult {
  approval: Approval;
  approval_token: string | null;
}

export async function resolveApproval(
  deps: ServiceDeps,
  userId: string,
  approvalId: string,
  deviceId: string,
  decision: "approve" | "deny",
  opts: { signedDecision?: string; requireDeviceSignatures?: boolean } = {},
): Promise<ResolveResult> {
  const device = await requireOwnedDevice(deps, userId, deviceId);
  const j = await loadOwned(deps.db, userId, approvalId);
  if (j.approval.status !== "pending") throw alreadyResolved(j.approval);

  const now = deps.clock.now();
  // M7: a device with a registered key must sign its decisions; the signature is checked here
  // (early rejection + audit) and again by the executor, which is what actually counts.
  let v2: { nonce: string; token: string } | null = null;
  if (device.public_key || opts.signedDecision) {
    if (!device.public_key) throw new DomainError(400, "device_has_no_key", "this device has no registered key; it cannot send signed decisions");
    if (!opts.signedDecision) throw new DomainError(400, "signed_decision_required", "this device must sign its decision (signed_decision)");
    const r = verifyDecision(opts.signedDecision, {
      publicKeyFor: (id) => (id === device.id ? device.public_key : null),
      expectedApprovalId: j.approval.id,
      expectedActionHash: j.action.action_hash,
      expectedSessionId: j.session.id,
      now,
    });
    if (!r.ok) throw new DomainError(403, "invalid_signed_decision", `signed decision rejected: ${r.reason}`);
    const p = r.payload;
    if (p.decision !== decision) throw new DomainError(400, "decision_mismatch", `signed decision says ${p.decision}, request says ${decision}`);
    if (p.action_id !== j.action.id || p.device_id !== deviceId) throw new DomainError(403, "invalid_signed_decision", "signed decision is bound to another action/device");
    if (Date.parse(p.expires_at) > j.approval.expires_at.getTime()) {
      throw new DomainError(403, "invalid_signed_decision", "signed decision outlives the approval window");
    }
    v2 = { nonce: p.nonce, token: opts.signedDecision };
  } else if (opts.requireDeviceSignatures) {
    throw new DomainError(403, "device_signature_required", "this server requires phone-signed decisions; re-pair this device");
  }
  const next = transitionApproval(toApproval(j.approval), { type: decision, device_id: deviceId }, now);

  if (next.status === "expired") {
    // Late decision: the state machine turns it into an expiry (fail closed).
    await commitTransition(deps, j, next, {
      event: "approval.expired",
      payload: { reason: "late_decision", attempted: decision, device_id: deviceId },
    });
    const fresh = await loadOwned(deps.db, userId, approvalId);
    throw alreadyResolved(fresh.approval);
  }

  const nonce = next.status === "approved" ? (v2?.nonce ?? newNonce()) : null;
  const row = await commitTransition(
    deps,
    j,
    next,
    { event: TERMINAL_AUDIT[next.status as "approved" | "denied"], payload: { device_id: deviceId, signed: v2 !== null } },
    nonce,
    next.status === "approved" ? (v2?.token ?? null) : null,
  );
  if (!row) {
    const fresh = await loadOwned(deps.db, userId, approvalId);
    throw alreadyResolved(fresh.approval);
  }
  return { approval: toApproval(row), approval_token: tokenFor(deps.signer, row, j.action) };
}

/** Expires one pending approval if its window has passed. Returns the current row. */
async function expireIfDue(deps: ServiceDeps, j: ApprovalJoin): Promise<ApprovalRow> {
  const now = deps.clock.now();
  if (j.approval.status !== "pending" || !isExpired(toApproval(j.approval), now)) return j.approval;
  const next = transitionApproval(toApproval(j.approval), { type: "expire" }, now);
  const row = await commitTransition(deps, j, next, { event: "approval.expired", payload: { reason: "timeout" } });
  if (row) return row;
  const [fresh] = await deps.db.select().from(approvals).where(eq(approvals.id, j.approval.id));
  return fresh!;
}

/** Sweeper tick: expire every pending approval past expires_at. Returns how many expired. */
export async function expireDueApprovals(deps: ServiceDeps, batch = 200): Promise<number> {
  const now = deps.clock.now();
  const due = await joinedQuery(deps.db)
    .where(and(eq(approvals.status, "pending"), lte(approvals.expires_at, now)))
    .limit(batch);
  let n = 0;
  for (const j of due) {
    const row = await expireIfDue(deps, j);
    if (row.status === "expired") n++;
  }
  return n;
}

export async function cancelPendingForSession(
  deps: ServiceDeps,
  userId: string,
  sessionId: string,
  reason: string,
): Promise<number> {
  const pending = await joinedQuery(deps.db).where(
    and(eq(sessions.id, sessionId), eq(agents.user_id, userId), eq(approvals.status, "pending")),
  );
  let n = 0;
  for (const j of pending) {
    const next = transitionApproval(toApproval(j.approval), { type: "cancel", reason }, deps.clock.now());
    if (await commitTransition(deps, j, next, { event: "approval.cancelled", payload: { reason } })) n++;
  }
  return n;
}

/** Agent-initiated cancel of one pending approval (compare-and-set via commitTransition). */
export async function cancelApproval(
  deps: ServiceDeps,
  userId: string,
  approvalId: string,
  input: { session_id?: string; reason?: string },
): Promise<Approval> {
  const j = await loadOwned(deps.db, userId, approvalId);
  if (input.session_id && input.session_id !== j.session.id) throw forbidden("approval belongs to a different session");
  if (j.approval.status === "cancelled") return toApproval(j.approval);
  if (j.approval.status !== "pending") throw alreadyResolved(j.approval);
  const reason = input.reason ?? "agent_cancelled";
  const next = transitionApproval(toApproval(j.approval), { type: "cancel", reason }, deps.clock.now());
  const row = await commitTransition(deps, j, next, { event: "approval.cancelled", payload: { reason } });
  if (row) return toApproval(row);
  const fresh = await loadOwned(deps.db, userId, approvalId);
  if (fresh.approval.status === "cancelled") return toApproval(fresh.approval);
  throw alreadyResolved(fresh.approval);
}

export type Viewer = { kind: "device"; deviceId: string | null } | { kind: "agent" };

/**
 * GET /v1/approvals/:id. Lazily expires a stale pending approval. Device viewers are
 * audited (`approval.viewed`, once per device). Agent viewers of an approved approval
 * also get the (re-derived) approval token so a reconnecting daemon never misses it.
 */
export async function getApproval(
  deps: ServiceDeps,
  userId: string,
  approvalId: string,
  viewer: Viewer,
): Promise<ApprovalDetail & { approval_token?: string | null }> {
  const j = await loadOwned(deps.db, userId, approvalId);
  j.approval = await expireIfDue(deps, j);

  if (viewer.kind === "device") {
    if (viewer.deviceId) await requireOwnedDevice(deps, userId, viewer.deviceId);
    const deviceFilter = viewer.deviceId
      ? sql`${auditLogs.payload_json}->>'device_id' = ${viewer.deviceId}`
      : sql`${auditLogs.payload_json}->>'device_id' IS NULL`;
    const seen = await deps.db
      .select({ id: auditLogs.id })
      .from(auditLogs)
      .where(and(eq(auditLogs.approval_id, approvalId), eq(auditLogs.event, "approval.viewed"), deviceFilter))
      .limit(1);
    if (seen.length === 0) {
      await writeAudit(deps.db, {
        userId,
        event: "approval.viewed",
        actionId: j.action.id,
        approvalId,
        payload: { label: actionLabel(toCanonicalAction(j.action)), device_id: viewer.deviceId },
        at: deps.clock.now(),
      });
    }
    return toDetail(j);
  }

  const token = tokenExpired(j.approval, deps.clock.now()) ? null : tokenFor(deps.signer, j.approval, j.action);
  return { ...toDetail(j), approval_token: token };
}

export async function listApprovals(
  deps: ServiceDeps,
  userId: string,
  query: { status?: ApprovalStatus | undefined; limit: number },
): Promise<ApprovalDetail[]> {
  const conds = [eq(agents.user_id, userId)];
  if (query.status) conds.push(eq(approvals.status, query.status));
  // Pending means "still actionable": hide rows the sweeper hasn't reached yet.
  if (query.status === "pending") conds.push(gt(approvals.expires_at, deps.clock.now()));
  const rows = await joinedQuery(deps.db)
    .where(and(...conds))
    .orderBy(desc(approvals.requested_at))
    .limit(query.limit);
  return rows.map(toDetail);
}

/** Status of the action's approval, or null if it never needed one. */
export async function approvalStatusForAction(db: Db, actionId: string): Promise<ApprovalStatus | null> {
  const [row] = await db.select({ status: approvals.status }).from(approvals).where(eq(approvals.action_id, actionId));
  return row?.status ?? null;
}

