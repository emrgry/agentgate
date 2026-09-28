import {
  CanonicalAction,
  type ActionRecord,
  type Agent,
  type Approval,
  type Device,
  type Session,
} from "@agentgate/protocol";
import type { ActionRow, AgentRow, ApprovalRow, DeviceRow, SessionRow } from "../db/schema.ts";

const iso = (d: Date) => d.toISOString();
const isoOrNull = (d: Date | null) => (d ? d.toISOString() : null);

export function toDevice(r: DeviceRow): Device {
  return { id: r.id, name: r.name, platform: r.platform, push_token: r.push_token, created_at: iso(r.created_at) };
}

export function toAgent(r: AgentRow): Agent {
  return { id: r.id, name: r.name, type: r.type, machine_id: r.machine_id, created_at: iso(r.created_at) };
}

export function toSession(r: SessionRow): Session {
  return {
    id: r.id,
    agent_id: r.agent_id,
    status: r.status,
    started_at: iso(r.started_at),
    ended_at: isoOrNull(r.ended_at),
  };
}

export function toApproval(r: ApprovalRow): Approval {
  return {
    approval_id: r.id,
    action_id: r.action_id,
    status: r.status,
    decision: r.decision,
    requested_at: iso(r.requested_at),
    expires_at: iso(r.expires_at),
    resolved_at: isoOrNull(r.resolved_at),
    resolved_by_device_id: r.resolved_by_device_id,
  };
}

/** Inverse of toApproval — used to write state-machine output back to the row. */
export function approvalPatch(a: Approval) {
  return {
    status: a.status,
    decision: a.decision,
    resolved_at: a.resolved_at ? new Date(a.resolved_at) : null,
    resolved_by_device_id: a.resolved_by_device_id,
  };
}

export function toCanonicalAction(r: ActionRow): CanonicalAction {
  return CanonicalAction.parse(r.payload_json);
}

export function toActionRecord(r: ActionRow, approval: ApprovalRow | null): ActionRecord {
  return {
    action: toCanonicalAction(r),
    action_hash: r.action_hash,
    policy_decision: r.policy_decision,
    approval: approval ? toApproval(approval) : null,
    execution: r.execution_status,
  };
}
