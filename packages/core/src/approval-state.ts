import type { Approval, ApprovalStatus } from "@agentgate/protocol";

/**
 * Approval state machine.
 *
 *            approve            ┌──────────┐
 *        ┌─────────────────────▶│ approved │
 *        │                      └──────────┘
 *  ┌─────────┐  deny            ┌──────────┐
 *  │ pending │─────────────────▶│  denied  │
 *  └─────────┘                  └──────────┘
 *        │  expire (now ≥ exp)  ┌──────────┐
 *        ├─────────────────────▶│ expired  │
 *        │  cancel              ┌───────────┐
 *        └─────────────────────▶│ cancelled │
 *                               └───────────┘
 * All non-pending states are terminal. An approve/deny arriving at or after
 * expires_at resolves the approval as expired instead (fail closed).
 */

export type ApprovalEvent =
  | { type: "approve"; device_id: string }
  | { type: "deny"; device_id: string }
  | { type: "expire" }
  | { type: "cancel"; reason?: string };

export class ApprovalTransitionError extends Error {
  constructor(
    readonly from: ApprovalStatus,
    readonly event: ApprovalEvent["type"],
    message?: string,
  ) {
    super(message ?? `cannot ${event} an approval in status '${from}'`);
    this.name = "ApprovalTransitionError";
  }
}

export function isTerminal(status: ApprovalStatus): boolean {
  return status !== "pending";
}

/** Fail closed: an unparseable expires_at or invalid `now` counts as expired. */
export function isExpired(approval: Pick<Approval, "expires_at">, now: Date): boolean {
  return !(now.getTime() < Date.parse(approval.expires_at));
}

/**
 * Pure transition function. Returns the next approval state or throws
 * ApprovalTransitionError. Never mutates its input.
 */
export function transitionApproval(approval: Approval, event: ApprovalEvent, now: Date): Approval {
  if (approval.status !== "pending") {
    throw new ApprovalTransitionError(approval.status, event.type);
  }
  const resolved_at = now.toISOString();

  // Late decisions never succeed: the approval window is part of the contract.
  if ((event.type === "approve" || event.type === "deny") && isExpired(approval, now)) {
    return { ...approval, status: "expired", decision: null, resolved_at };
  }

  switch (event.type) {
    case "approve":
      return {
        ...approval,
        status: "approved",
        decision: "approve",
        resolved_at,
        resolved_by_device_id: event.device_id,
      };
    case "deny":
      return {
        ...approval,
        status: "denied",
        decision: "deny",
        resolved_at,
        resolved_by_device_id: event.device_id,
      };
    case "expire":
      if (!isExpired(approval, now)) {
        throw new ApprovalTransitionError("pending", "expire", "approval has not reached expires_at");
      }
      return { ...approval, status: "expired", decision: null, resolved_at };
    case "cancel":
      return { ...approval, status: "cancelled", decision: null, resolved_at };
  }
}
