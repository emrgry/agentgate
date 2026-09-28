import type { AgentSession, AgentTask, ApprovalDetail, ApprovalResolvedEvent, PairingRequest, SessionEvent } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import type { ApprovalSigner } from "../keys.ts";

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

/**
 * Outbound side effects of domain operations (realtime fan-out + push). Called only
 * after the owning transaction has committed. Implementations must never throw.
 */
export interface Notifier {
  approvalCreated(userId: string, detail: ApprovalDetail): void;
  approvalResolved(userId: string, sessionId: string, event: ApprovalResolvedEvent): void;
  /** WS pairing.requested to the user's devices + push to active devices. */
  pairingRequested(userId: string, request: PairingRequest): void;
  pairingResolved(userId: string, request: PairingRequest): void;
  /** Drop live sockets of a revoked device. */
  deviceRevoked(userId: string, deviceId: string): void;
  /** Control Center: realtime session state + timeline to the user's devices. */
  sessionUpdated(userId: string, session: AgentSession): void;
  sessionEvent(userId: string, event: SessionEvent): void;
  taskUpdated(userId: string, task: AgentTask): void;
  /** Control Center push (content-free, coalesced). */
  sessionAlert(
    userId: string,
    session: AgentSession,
    kind: SessionAlertKind,
    providerName: string,
  ): void;
}

export type SessionAlertKind =
  | "input_required"
  | "completed"
  | "failed"
  | "terminated"
  | "task_completed"
  | "all_tasks_completed"
  | "task_failed"
  // Phase 3/4 smart notifications
  | "budget_exceeded"
  | "stuck"
  | "repeated_failure"
  | "pr_ready";

export const nullNotifier: Notifier = {
  approvalCreated() {},
  approvalResolved() {},
  pairingRequested() {},
  pairingResolved() {},
  deviceRevoked() {},
  sessionUpdated() {},
  sessionEvent() {},
  taskUpdated() {},
  sessionAlert() {},
};

export interface Logger {
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
  error(obj: object, msg?: string): void;
}

export interface ServiceDeps {
  db: Db;
  clock: Clock;
  notifier: Notifier;
  signer: ApprovalSigner;
  logger: Logger;
}
