import type { SessionAlertKind } from "../domain/context.ts";
import { actionType, type ApprovalDetail, type PairingRequest } from "@agentgate/protocol";
import type { Logger } from "../domain/context.ts";

export interface PushMessage {
  to: string;
  title: string;
  body: string;
  data: Record<string, unknown>;
  sound?: "default";
  priority?: "default" | "normal" | "high";
}

export interface PushSender {
  send(messages: PushMessage[]): Promise<void>;
}

const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
const MAX_BODY = 160;

/**
 * Lock-screen safe: only the approval id, agent name and a short action label.
 * Decisions always require an authenticated in-app action.
 */
export function approvalPushMessages(tokens: string[], detail: ApprovalDetail, serverFingerprint?: string): PushMessage[] {
  // Lock-screen safe: no command text, no paths — only who, how risky, and where.
  const agent = detail.agent_name ?? detail.action.agent.type;
  // Content-free by default (M7): no command, repo, path or server — only who and how risky.
  const parts = [`${agent} needs approval`, detail.action.risk.level.toUpperCase()];
  let body = parts.join(" · ");
  if (body.length > MAX_BODY) body = `${body.slice(0, MAX_BODY - 1)}…`;
  const id = detail.approval.approval_id;
  return tokens.map((to) => ({
    to,
    title: "AgentGate",
    body,
    // server_fingerprint lets a phone paired with several computers route the push.
    data: { approval_id: id, url: `agentgate://approvals/${id}`, ...(serverFingerprint ? { server_fingerprint: serverFingerprint } : {}) },
    sound: "default",
  }));
}

/** New-device pairing request → every active device. No IP / email on the lock screen. */
export function pairingPushMessages(tokens: string[], request: PairingRequest, serverFingerprint?: string): PushMessage[] {
  let body =
    request.kind === "agent" ? `New computer wants to run agents: ${request.device_name}` : `New device wants to pair: ${request.device_name}`;
  if (body.length > MAX_BODY) body = `${body.slice(0, MAX_BODY - 1)}…`;
  return tokens.map((to) => ({
    to,
    title: "AgentGate",
    body,
    data: { url: `agentgate://pairing/${request.id}`, pairing_request_id: request.id, ...(serverFingerprint ? { server_fingerprint: serverFingerprint } : {}) },
    sound: "default",
  }));
}

/** Control Center pushes: content-free bodies; details only in-app. */
export function sessionPushMessages(
  tokens: string[],
  sessionId: string,
  kind: SessionAlertKind,
  providerName: string,
  serverFingerprint?: string,
): PushMessage[] {
  const body = {
    input_required: `${providerName} is waiting for you`,
    completed: `${providerName} finished a task`,
    task_completed: `${providerName} finished a task`,
    all_tasks_completed: `${providerName} finished all tasks`,
    failed: `${providerName} failed`,
    task_failed: `${providerName} failed a task`,
    terminated: `${providerName} stopped unexpectedly`,
    budget_exceeded: `${providerName} reached a limit`,
    stuck: `${providerName} seems stuck`,
    repeated_failure: `${providerName} keeps failing`,
    pr_ready: `${providerName}: pull request ready`,
  }[kind];
  return tokens.map((to) => ({
    to,
    title: "AgentGate",
    body,
    data: { url: `agentgate://sessions/${sessionId}`, session_id: sessionId, kind, ...(serverFingerprint ? { server_fingerprint: serverFingerprint } : {}) },
    sound: "default",
  }));
}

export class ExpoPushSender implements PushSender {
  constructor(
    private readonly logger: Logger,
    private readonly accessToken: string | null,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async send(messages: PushMessage[]): Promise<void> {
    if (messages.length === 0) return;
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
    if (this.accessToken) headers.authorization = `Bearer ${this.accessToken}`;
    // Expo accepts up to 100 messages per request.
    for (let i = 0; i < messages.length; i += 100) {
      const chunk = messages.slice(i, i + 100);
      const res = await this.fetchImpl(EXPO_PUSH_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(chunk),
        signal: AbortSignal.timeout(5000),
      });
      const json = (await res.json().catch(() => null)) as { data?: Array<{ status: string; message?: string }> } | null;
      if (!res.ok) throw new Error(`expo push HTTP ${res.status}`);
      const errors = (json?.data ?? []).filter((t) => t.status !== "ok");
      if (errors.length > 0) {
        this.logger.warn({ count: errors.length, first: errors[0]?.message }, "expo push tickets reported errors");
      }
    }
  }
}
