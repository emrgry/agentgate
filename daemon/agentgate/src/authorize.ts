import { computeActionHash } from "@agentgate/core";
import { evaluatePolicy, type PolicyEvaluation } from "@agentgate/policy-engine";
import type { ActionDraft, Approval, PolicyDecision } from "@agentgate/protocol";
import { AgentGateClient, ApiRequestError, ApprovalWaiter, WsConnectError, type WaitOutcome } from "./client/index.ts";
import type { LoggedInConfig } from "./config.ts";
import { EXIT, ExitError } from "./exit-codes.ts";
import { c, log } from "./output.ts";
import type { EffectivePolicy } from "./policy.ts";
import { withoutExecContext } from "./exec-context.ts";

/**
 * Shared authorization pipeline used by `request` (M2) and `hook claude-code` (M4):
 *   local policy → POST /v1/actions → (ask) WS wait → signed token.
 * It never executes anything and never verifies/consumes the token — callers do that
 * at their execution boundary. Every "no" is thrown as ExitError(BLOCKED | INTERRUPTED).
 */

export type Authorized =
  | { kind: "allow"; actionId: string; evaluation: PolicyEvaluation; hash: string }
  | {
      kind: "approved";
      actionId: string;
      approvalId: string;
      token: string | null;
      evaluation: PolicyEvaluation;
      hash: string;
      approvedBy: string | null;
    };

export interface AuthorizeDeps {
  client: AgentGateClient;
  config: LoggedInConfig;
  policy: EffectivePolicy;
  signal: AbortSignal;
  /** Requested approval TTL (seconds). */
  ttl: number;
  /** Hard cap on the approval wait (e.g. hook deadline). */
  maxWaitMs?: number;
  /** Called as soon as the server assigned an action id (for blocked reporting). */
  onActionId: (id: string) => void;
  /** Minimum decision regardless of policy (adapter guard: self-protection, sensitive reads). */
  floor?: { decision: PolicyDecision; reason: string };
  /** Called when a pending approval exists (so callers can cancel it on hard exits). */
  onApproval?: (approvalId: string) => void;
}

const DEFAULT_GRACE_MS = 10_000;

/**
 * The session in the draft no longer accepts actions (ended server-side, or unknown to
 * this server/user). Hook-managed sessions recover by re-mapping; everyone else blocks.
 */
export class SessionGoneError extends ExitError {
  constructor(readonly sessionId: string, detail: string) {
    super(EXIT.BLOCKED, `AgentGate session ${sessionId} is no longer usable (${detail})`, "session_gone");
    this.name = "SessionGoneError";
  }
}

function sessionGone(err: unknown): string | null {
  if (err instanceof ApiRequestError && err.kind === "http") {
    if (err.status === 409 && err.code === "session_ended") return "ended";
    if (err.status === 404 && err.code === "not_found") return "not found";
  }
  if (err instanceof WsConnectError && err.status === 404) return "not found";
  return null;
}
const ORDER: Record<PolicyDecision, number> = { allow: 0, ask: 1, deny: 2 };
const stricter = (a: PolicyDecision, b: PolicyDecision) => (ORDER[b] > ORDER[a] ? b : a);

/**
 * Local policy evaluation, plus: when the adapter asserted a risk and no explicit rule
 * matched, the default for the *effective* risk applies. (`evaluatePolicy` raises the
 * reported risk to the asserted level but decides on the inferred one, so a `.env`
 * write asserted "high" would otherwise be allowed as a "medium" file edit.)
 * Only ever makes the decision stricter.
 */
export function evaluateLocal(policy: EffectivePolicy, draft: ActionDraft, floor?: { decision: PolicyDecision; reason: string }): PolicyEvaluation {
  const e0 = evaluatePolicy(policy.policy, withoutExecContext(draft));
  const e = floor && ORDER[floor.decision] > ORDER[e0.decision] ? { ...e0, decision: floor.decision, reason: floor.reason } : e0;
  if (draft.risk && e.rule_id === null) {
    const d = stricter(e.decision, policy.policy.defaults[e.risk.level]);
    if (d !== e.decision) return { ...e, decision: d, reason: `${e.risk.reason} (adapter-asserted ${e.risk.level} risk)` };
  }
  return e;
}

export function printDecision(e: PolicyEvaluation, source: string) {
  const color = e.decision === "allow" ? c.green : e.decision === "ask" ? c.yellow : c.red;
  const rule = e.rule_id ? `rule ${e.rule_id}` : "default";
  log.step(`policy: ${color(c.bold(e.decision.toUpperCase()))} ${c.dim(`(${rule}, risk ${e.risk.level}, ${source})`)} — ${e.reason}`);
}

export async function authorizeAction(deps: AuthorizeDeps, draft: ActionDraft): Promise<Authorized> {
  const { client } = deps;
  const evaluation = evaluateLocal(deps.policy, draft, deps.floor);
  const hash = computeActionHash(draft);
  printDecision(evaluation, deps.policy.source);
  log.debug(`action hash ${hash}`);
  const policyBody = { decision: evaluation.decision, rule_id: evaluation.rule_id, risk: evaluation.risk.level, reason: evaluation.reason };
  const checkAborted = () => {
    if (deps.signal.aborted) throw new ExitError(EXIT.INTERRUPTED, "action not executed; approval cancelled", "interrupted");
  };

  if (evaluation.decision === "deny") {
    try {
      const rec = await client.submitAction({ action: draft, policy: policyBody, action_hash: hash });
      deps.onActionId(rec.action.action_id);
    } catch (err) {
      log.warn(`could not report denied action to server: ${describeError(err)}`);
    }
    throw new ExitError(EXIT.BLOCKED, `denied by policy (${evaluation.reason})`, "policy_denied");
  }

  let waiter: ApprovalWaiter | null = null;
  const openWaiter = async () => {
    try {
      return await ApprovalWaiter.open({
        client,
        accessToken: deps.config.access_token,
        sessionId: draft.session_id,
        debug: log.debug,
        onDisconnect: () => log.warn("realtime connection lost — reconnecting…"),
        onReconnect: () => log.step(c.dim("realtime connection restored; re-checking approval")),
      });
    } catch (err) {
      const gone = sessionGone(err);
      if (gone) throw new SessionGoneError(draft.session_id, gone);
      throw new ExitError(EXIT.BLOCKED, `cannot open realtime connection: ${describeError(err)}`, "realtime_unavailable");
    }
  };

  try {
    // The realtime channel must be up BEFORE the approval exists.
    if (evaluation.decision === "ask") waiter = await openWaiter();
    checkAborted();

    const record = await client
      .submitAction({
        action: draft,
        policy: policyBody,
        action_hash: hash,
        ...(evaluation.decision === "ask" ? { approval_ttl_seconds: deps.ttl } : {}),
      })
      .catch((err: unknown) => {
        const gone = sessionGone(err);
        throw gone ? new SessionGoneError(draft.session_id, gone) : err;
      });
    const actionId = record.action.action_id;
    deps.onActionId(actionId);
    log.debug(`action ${actionId}`);
    if (record.action_hash !== hash) {
      throw new ExitError(EXIT.BLOCKED, "server computed a different action hash (client/server protocol mismatch)", "protocol_mismatch");
    }
    checkAborted();

    // The server may be stricter than local policy, never more lenient.
    const effective = stricter(evaluation.decision, record.policy_decision);
    if (effective !== evaluation.decision) log.warn(`server escalated decision to ${effective.toUpperCase()}`);
    if (effective === "deny") throw new ExitError(EXIT.BLOCKED, "denied by server policy", "server_policy_denied");
    if (effective === "allow") return { kind: "allow", actionId, evaluation, hash };

    const approval: Approval | null = record.approval;
    if (!approval) throw new ExitError(EXIT.BLOCKED, "server did not create an approval for an `ask` action", "protocol_mismatch");
    if (approval.status === "denied" || approval.status === "expired" || approval.status === "cancelled") {
      throw new ExitError(EXIT.BLOCKED, `approval ${approval.approval_id} is ${approval.status}`, `approval_${approval.status}`);
    }
    waiter ??= await openWaiter();

    const ttlMs = approvalTtlMs(approval.requested_at, approval.expires_at, deps.ttl);
    let timeoutMs = ttlMs + graceMs();
    if (deps.maxWaitMs !== undefined) timeoutMs = Math.max(0, Math.min(timeoutMs, deps.maxWaitMs));
    log.step(
      `⏳ Waiting for approval on your phone… (${c.bold(approval.approval_id)}, expires in ${Math.round(ttlMs / 1000)}s)  ${c.dim("Ctrl-C to cancel")}`,
    );

    deps.onApproval?.(approval.approval_id);
    const outcome: WaitOutcome = await waiter.wait(approval.approval_id, timeoutMs, deps.signal);
    waiter.close();
    waiter = null;
    if (outcome.status === "aborted" || outcome.status === "timeout" || outcome.status === "error") {
      // We are giving up: take the request off the phone instead of leaving it pending.
      await cancelApprovalQuietly(client, approval.approval_id, draft.session_id, `agent_${outcome.status}`);
    }
    switch (outcome.status) {
      case "aborted":
        throw new ExitError(EXIT.INTERRUPTED, "action not executed; approval cancelled", "interrupted");
      case "timeout":
        throw new ExitError(EXIT.BLOCKED, `no decision within ${Math.round(timeoutMs / 1000)}s — approval timed out`, "approval_timeout");
      case "error":
        throw new ExitError(EXIT.BLOCKED, `approval wait failed: ${outcome.error.message}`, "realtime_unavailable");
      case "denied":
        throw new ExitError(EXIT.BLOCKED, "denied on device", "device_denied");
      case "expired":
        throw new ExitError(EXIT.BLOCKED, "approval expired", "approval_expired");
      case "cancelled":
        throw new ExitError(EXIT.BLOCKED, "approval cancelled", "approval_cancelled");
      case "approved":
        break;
    }
    checkAborted();
    const approvedBy = await lookupApprover(client, approval.approval_id);
    log.ok(`approved${approvedBy ? ` by device ${c.bold(approvedBy)}` : ""}`);
    return { kind: "approved", actionId, approvalId: approval.approval_id, token: outcome.token, evaluation, hash, approvedBy };
  } finally {
    waiter?.close();
  }
}

/** Best-effort cancel (≤ 3 s). Never throws. */
export async function cancelApprovalQuietly(client: AgentGateClient, approvalId: string, sessionId: string, reason: string): Promise<void> {
  try {
    await client.cancelApproval(approvalId, { session_id: sessionId, reason }, 3_000);
    log.debug(`cancelled approval ${approvalId} (${reason})`);
  } catch (err) {
    log.debug(`cancel approval ${approvalId} failed: ${describeError(err)}`);
  }
}

/** Informational only; failures ignored. */
async function lookupApprover(client: AgentGateClient, approvalId: string): Promise<string | null> {
  try {
    const { detail } = await Promise.race([
      client.getApproval(approvalId),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout")), 2_000).unref()),
    ]);
    return detail.approval.resolved_by_device_id;
  } catch {
    return null;
  }
}

export function approvalTtlMs(requestedAt: string, expiresAt: string, fallbackSeconds: number): number {
  // Use the server's window length (not absolute times) so local clock skew doesn't matter.
  const ms = Date.parse(expiresAt) - Date.parse(requestedAt);
  return Number.isFinite(ms) && ms > 0 ? ms : fallbackSeconds * 1000;
}

function graceMs(): number {
  if (process.env.AGENTGATE_DEV === "1" && process.env.AGENTGATE_WAIT_GRACE_MS) {
    const v = Number(process.env.AGENTGATE_WAIT_GRACE_MS);
    if (Number.isFinite(v) && v >= 0) return v;
  }
  return DEFAULT_GRACE_MS;
}

export function describeError(err: unknown): string {
  if (err instanceof ApiRequestError) {
    if (err.kind === "network" || err.kind === "timeout") return `server unreachable (${err.message})`;
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
