import { z } from "zod";
import { ApprovalStatus, ApprovalToken } from "./approval.ts";
import { ApprovalDetail, PairingRequest } from "./api.ts";
import { SessionEventPushed, SessionUpdatedEvent, TaskUpdatedEvent } from "./sessions.ts";

/**
 * Realtime events over WebSocket.
 *   Daemon:  WS /v1/agent/connect?session_id=...   (Authorization: Bearer, or ?access_token=)
 *   Mobile:  WS /v1/device/connect                 (same auth)
 * Server → client messages are JSON text frames matching ServerEvent.
 * Clients send {"type":"ping"}; server answers {"type":"pong"}.
 * On (re)connect the daemon MUST re-fetch GET /v1/approvals/:id for anything it is
 * waiting on, so a resolution that happened while disconnected is never missed.
 */

export const ApprovalCreatedEvent = z.object({
  type: z.literal("approval.created"),
  detail: ApprovalDetail,
});

export const ApprovalResolvedEvent = z.object({
  type: z.literal("approval.resolved"),
  approval_id: z.string(),
  action_id: z.string(),
  status: ApprovalStatus,
  /** Signed token; present only when status === "approved". */
  approval_token: ApprovalToken.nullable(),
});
export type ApprovalResolvedEvent = z.infer<typeof ApprovalResolvedEvent>;

/** Device sockets only: a new device asks to be paired and needs approval here. */
export const PairingRequestedEvent = z.object({
  type: z.literal("pairing.requested"),
  request: PairingRequest,
});

export const PairingResolvedEvent = z.object({
  type: z.literal("pairing.resolved"),
  request: PairingRequest,
});

export const HelloEvent = z.object({
  type: z.literal("hello"),
  server_time: z.string().datetime(),
});

export const PongEvent = z.object({ type: z.literal("pong") });

export const ServerEvent = z.discriminatedUnion("type", [
  ApprovalCreatedEvent,
  ApprovalResolvedEvent,
  PairingRequestedEvent,
  PairingResolvedEvent,
  SessionUpdatedEvent,
  SessionEventPushed,
  TaskUpdatedEvent,
  HelloEvent,
  PongEvent,
]);
export type ServerEvent = z.infer<typeof ServerEvent>;
