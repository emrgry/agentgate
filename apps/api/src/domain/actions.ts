import { and, eq } from "drizzle-orm";
import { computeActionHash, newId } from "@agentgate/core";
import { redactCommandSecrets, type ActionRecord, type CanonicalAction, type Risk, type SubmitActionRequest } from "@agentgate/protocol";
import { DEFAULT_POLICY_YAML, evaluatePolicy, loadPolicyYaml, maxRisk } from "@agentgate/policy-engine";
import { z } from "zod";
import { ReportExecutionRequest } from "@agentgate/protocol";
import { actions, agents, approvals, sessions, type ExecutionStatus } from "../db/schema.ts";
import { actionAuditFields, actionLabel, mcpFields, writeAudit } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";
import { badRequest, conflict, notFound } from "./errors.ts";
import { insertPendingApproval, toDetail } from "./approvals.ts";
import { toActionRecord } from "./mappers.ts";
import { requireOwnedSession } from "./sessions.ts";

/**
 * POST /v1/actions. Stores the canonical action with the server-computed hash, audits the
 * policy outcome, and — for `ask` — creates the approval in the same transaction.
 */
export async function submitAction(deps: ServiceDeps, userId: string, req: SubmitActionRequest): Promise<ActionRecord> {
  const { session, agent } = await requireOwnedSession(deps.db, userId, req.action.session_id);
  if (session.status !== "active") throw conflict("session_ended", "session has ended");

  const hash = computeActionHash(req.action);
  if (hash !== req.action_hash) {
    throw badRequest("hash_mismatch", "action_hash does not match the server-computed hash of the action");
  }

  const now = deps.clock.now();
  // Never trust the client's risk alone: re-classify with the shared engine, keep the max.
  const clientRisk = maxRisk(req.action.risk ?? { level: req.policy.risk, reason: req.policy.reason }, {
    level: req.policy.risk,
    reason: req.policy.reason,
  });
  const serverRisk = serverClassify(req.action);
  const risk = maxRisk(clientRisk, serverRisk);
  const command = req.action.action.command;
  const canonical: CanonicalAction = {
    ...req.action,
    action: {
      ...req.action.action,
      // Authoritative display copy (secrets masked). Not hashed; the raw command still is.
      ...(command ? { display_command: redactCommandSecrets(command) } : {}),
    },
    action_id: newId("act"),
    created_at: now.toISOString(),
    risk,
  };
  const label = actionLabel(canonical);
  const decision = req.policy.decision;

  const { action, approval } = await deps.db.transaction(async (tx) => {
    const [action] = await tx
      .insert(actions)
      .values({
        id: canonical.action_id,
        session_id: session.id,
        category: canonical.action.category,
        operation: canonical.action.operation,
        payload_json: canonical,
        action_hash: hash,
        risk_level: risk.level,
        policy_decision: decision,
        policy_rule_id: req.policy.rule_id,
        // A policy deny never runs; everything else waits for the daemon's execution report.
        execution_status: decision === "deny" ? "blocked" : "not_started",
        created_at: now,
      })
      .returning();
    const base = {
      userId,
      actionId: action!.id,
      at: now,
    };
    const mcp = mcpFields(canonical);
    const payload = {
      label,
      agent_name: agent.name,
      agent_type: canonical.agent.type,
      ...(mcp ?? {}),
      session_id: session.id,
      risk: risk.level,
      client_risk: clientRisk.level,
      server_risk: serverRisk.level,
      rule_id: req.policy.rule_id,
      reason: req.policy.reason,
    };
    await writeAudit(tx, { ...base, event: "action.reported", payload });
    if (decision === "allow") await writeAudit(tx, { ...base, event: "action.allowed", payload });
    if (decision === "deny") await writeAudit(tx, { ...base, event: "action.denied_by_policy", payload });
    const approval =
      decision === "ask"
        ? await insertPendingApproval(tx, {
            userId,
            action: action!,
            agentName: agent.name,
            ttlSeconds: req.approval_ttl_seconds,
            now,
          })
        : null;
    return { action: action!, approval };
  });

  if (approval) deps.notifier.approvalCreated(userId, toDetail({ approval, action, session, agent }));
  return toActionRecord(action, approval);
}

type ExecutionReport = z.infer<typeof ReportExecutionRequest>;

const ALLOWED_FROM: Record<ExecutionReport["status"], readonly ExecutionStatus[]> = {
  started: ["not_started"],
  completed: ["started"],
  failed: ["not_started", "started"],
  blocked: ["not_started"],
};

/** POST /v1/actions/:id/execution. Idempotent for repeated identical reports. */
export async function reportExecution(
  deps: ServiceDeps,
  userId: string,
  actionId: string,
  report: ExecutionReport,
): Promise<ActionRecord> {
  const [owned] = await deps.db
    .select({ action: actions, approval: approvals })
    .from(actions)
    .innerJoin(sessions, eq(sessions.id, actions.session_id))
    .innerJoin(agents, eq(agents.id, sessions.agent_id))
    .leftJoin(approvals, eq(approvals.action_id, actions.id))
    .where(and(eq(actions.id, actionId), eq(agents.user_id, userId)))
    .limit(1);
  if (!owned) throw notFound("action");
  const current = owned.action.execution_status;
  if (current === report.status) return toActionRecord(owned.action, owned.approval);

  if (!ALLOWED_FROM[report.status].includes(current)) {
    throw conflict("invalid_execution_transition", `cannot report '${report.status}' after '${current}'`);
  }
  if (report.status === "started") {
    if (owned.action.policy_decision === "deny") throw conflict("not_permitted", "action was denied by policy");
    if (owned.approval && owned.approval.status !== "approved") {
      throw conflict("not_approved", `approval is '${owned.approval.status}'`);
    }
  }

  const now = deps.clock.now();
  const updated = await deps.db.transaction(async (tx) => {
    const [row] = await tx
      .update(actions)
      .set({ execution_status: report.status })
      .where(and(eq(actions.id, actionId), eq(actions.execution_status, current)))
      .returning();
    if (!row) throw conflict("concurrent_update", "execution status changed concurrently; retry");
    await writeAudit(tx, {
      userId,
      event: `execution.${report.status}`,
      actionId,
      approvalId: owned.approval?.id ?? null,
      payload: {
        ...actionAuditFields(toActionRecord(row, null).action),
        exit_code: report.exit_code ?? null,
        detail: report.detail ?? null,
      },
      at: now,
    });
    return row;
  });
  return toActionRecord(updated, owned.approval);
}

const RISK_POLICY = loadPolicyYaml(DEFAULT_POLICY_YAML);

/** Server-side risk from the shared classifier (rules don't matter for risk). */
function serverClassify(draft: SubmitActionRequest["action"]): Risk {
  try {
    // The daemon's execution binding (PATH, resolved binaries…) must not sway risk inference.
    const args = { ...((draft.action.arguments as Record<string, unknown> | undefined) ?? {}) };
    delete args.exec_context;
    const action = { ...draft.action, arguments: Object.keys(args).length ? args : undefined };
    return evaluatePolicy(RISK_POLICY, { ...draft, action }).risk;
  } catch {
    return { level: "high", reason: "server could not classify the action" };
  }
}
