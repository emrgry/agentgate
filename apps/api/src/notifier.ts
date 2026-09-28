import type { AgentSession, AgentTask, ApprovalDetail, ApprovalResolvedEvent, PairingRequest, SessionEvent } from "@agentgate/protocol";
import type { Logger, Notifier } from "./domain/context.ts";
import type { RealtimeHub } from "./realtime/hub.ts";
import { approvalPushMessages, pairingPushMessages, sessionPushMessages, type PushSender } from "./push/expo.ts";

/**
 * Production Notifier: WebSocket fan-out + Expo push. Push is fire-and-forget: failures are
 * logged and never propagate into the request that triggered them.
 */
export function createNotifier(opts: {
  hub: RealtimeHub;
  push: PushSender;
  pushTokensFor: (userId: string) => Promise<string[]>;
  logger: Logger;
  /** Server identity key fingerprint (same as QR v2 `fp`), added to every push's data. */
  serverFingerprint?: string;
  /** Min interval between session pushes per session (input_required is never coalesced). */
  sessionPushIntervalMs?: number;
  now?: () => number;
}): Notifier {
  const { hub, push, pushTokensFor, logger, serverFingerprint } = opts;
  const lastSessionPush = new Map<string, number>();
  const now = opts.now ?? (() => Date.now());
  return {
    approvalCreated(userId: string, detail: ApprovalDetail) {
      hub.publishToDevices(userId, { type: "approval.created", detail });
      void (async () => {
        const tokens = await pushTokensFor(userId);
        if (tokens.length === 0) return;
        await push.send(approvalPushMessages(tokens, detail, serverFingerprint));
      })().catch((err: unknown) => {
        logger.warn(
          { err: err instanceof Error ? err.message : String(err), approval_id: detail.approval.approval_id },
          "push notification failed",
        );
      });
    },
    approvalResolved(userId: string, sessionId: string, event: ApprovalResolvedEvent) {
      hub.publishToAgents(userId, sessionId, event);
      hub.publishToDevices(userId, event);
    },
    pairingRequested(userId: string, request: PairingRequest) {
      hub.publishToDevices(userId, { type: "pairing.requested", request });
      void (async () => {
        const tokens = await pushTokensFor(userId);
        if (tokens.length === 0) return;
        await push.send(pairingPushMessages(tokens, request, serverFingerprint));
      })().catch((err: unknown) => {
        logger.warn({ err: err instanceof Error ? err.message : String(err), pairing_request_id: request.id }, "pairing push failed");
      });
    },
    pairingResolved(userId: string, request: PairingRequest) {
      hub.publishToDevices(userId, { type: "pairing.resolved", request });
    },
    deviceRevoked(userId: string, deviceId: string) {
      hub.disconnectDevice(userId, deviceId);
    },
    sessionUpdated(userId: string, session: AgentSession) {
      hub.publishToDevices(userId, { type: "session.updated", session });
    },
    sessionEvent(userId: string, event: SessionEvent) {
      hub.publishToDevices(userId, { type: "session.event", event });
    },
    taskUpdated(userId: string, task: AgentTask) {
      hub.publishToDevices(userId, { type: "task.updated", task });
    },
    sessionAlert(userId, session, kind, providerName) {
      const t = now();
      const prev = lastSessionPush.get(session.id);
      // input_required (incl. budget questions), failures and the end of the queue are never coalesced away.
      if (!["input_required", "task_failed", "failed", "all_tasks_completed", "budget_exceeded", "repeated_failure"].includes(kind) && prev !== undefined && t - prev < (opts.sessionPushIntervalMs ?? 30_000)) return;
      lastSessionPush.set(session.id, t);
      void (async () => {
        const tokens = await pushTokensFor(userId);
        if (tokens.length === 0) return;
        await push.send(sessionPushMessages(tokens, session.id, kind, providerName, serverFingerprint));
      })().catch((err: unknown) => {
        logger.warn({ err: err instanceof Error ? err.message : String(err), session_id: session.id }, "session push failed");
      });
    },
  };
}
