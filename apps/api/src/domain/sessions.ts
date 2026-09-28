import { and, asc, eq } from "drizzle-orm";
import { newId } from "@agentgate/core";
import type { ActionRecord, Session } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import { actions, agents, approvals, sessions } from "../db/schema.ts";
import { writeAudit } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";
import { notFound } from "./errors.ts";
import { requireOwnedAgent } from "./identity.ts";
import { toActionRecord, toSession } from "./mappers.ts";
import { cancelPendingForSession } from "./approvals.ts";

export async function startSession(deps: ServiceDeps, userId: string, agentId: string): Promise<Session> {
  const agent = await requireOwnedAgent(deps, userId, agentId);
  const now = deps.clock.now();
  return deps.db.transaction(async (tx) => {
    const [row] = await tx
      .insert(sessions)
      .values({ id: newId("ses"), agent_id: agent.id, status: "active", started_at: now })
      .returning();
    await writeAudit(tx, {
      userId,
      event: "session.started",
      payload: { session_id: row!.id, agent_id: agent.id, agent_name: agent.name },
      at: now,
    });
    return toSession(row!);
  });
}

/** Loads a session owned (through its agent) by the user, or throws 404. */
export async function requireOwnedSession(db: Db, userId: string, sessionId: string) {
  const [row] = await db
    .select({ session: sessions, agent: agents })
    .from(sessions)
    .innerJoin(agents, eq(agents.id, sessions.agent_id))
    .where(and(eq(sessions.id, sessionId), eq(agents.user_id, userId)))
    .limit(1);
  if (!row) throw notFound("session");
  return row;
}

/** Ends the session (idempotent) and cancels every pending approval in it. */
export async function endSession(deps: ServiceDeps, userId: string, sessionId: string): Promise<Session> {
  const { session, agent } = await requireOwnedSession(deps.db, userId, sessionId);
  if (session.status === "ended") return toSession(session);
  const now = deps.clock.now();
  const [ended] = await deps.db
    .update(sessions)
    .set({ status: "ended", ended_at: now })
    .where(and(eq(sessions.id, sessionId), eq(sessions.status, "active")))
    .returning();
  if (ended) {
    await writeAudit(deps.db, {
      userId,
      event: "session.ended",
      payload: { session_id: sessionId, agent_id: agent.id, agent_name: agent.name },
      at: now,
    });
  }
  await cancelPendingForSession(deps, userId, sessionId, "session_ended");
  const { session: fresh } = await requireOwnedSession(deps.db, userId, sessionId);
  return toSession(fresh);
}

export async function listSessionActions(deps: ServiceDeps, userId: string, sessionId: string): Promise<ActionRecord[]> {
  await requireOwnedSession(deps.db, userId, sessionId);
  const rows = await deps.db
    .select({ action: actions, approval: approvals })
    .from(actions)
    .leftJoin(approvals, eq(approvals.action_id, actions.id))
    .where(eq(actions.session_id, sessionId))
    .orderBy(asc(actions.created_at));
  return rows.map((r) => toActionRecord(r.action, r.approval));
}
