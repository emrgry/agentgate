import { randomBytes } from "node:crypto";
import { and, asc, desc, eq, gt, inArray, lt, sql } from "drizzle-orm";
import {
  redactCommandSecrets,
  TERMINAL_SESSION_STATUSES,
  type AgentSession,
  type AgentTask,
  type Interaction,
  type SessionEvent,
  type SessionStatus,
  type SessionSummary,
  type SessionUsage,
  type Workspace,
} from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import { agentSessions, interactions, sessionEvents, tasks, workspaces, type AgentSessionRow, type InteractionRow, type TaskRow } from "../db/schema.ts";

/** Control Center persistence (docs/control-center.md §3). Pure DB helpers, no side effects. */

export const cid = (prefix: string) => `${prefix}_${randomBytes(16).toString("base64url")}`;
const iso = (d: Date | null) => (d ? d.toISOString() : null);

export const EMPTY_USAGE: SessionUsage = { cost_usd: null, input_tokens: null, output_tokens: null, duration_ms: null, turns: 0 };

const LIVE_MANAGED: SessionStatus[] = ["starting", "running", "awaiting_approval", "paused", "stopping"];

/** What the phone may do right now (server-computed, docs §6). */
export function computeCan(mode: "managed" | "observed", status: SessionStatus, hasProviderSession: boolean, queuedTasks = 0, hasProcess = false): AgentSession["can"] {
  if (mode === "observed") {
    const idleOrEnded = ["waiting_input", "completed", "lost"].includes(status) && hasProviderSession;
    return { instruct: idleOrEnded, pause: false, resume: false, stop: false, kill: false, continue_remotely: idleOrEnded };
  }
  const alive = ["running", "awaiting_approval", "paused"].includes(status);
  return {
    instruct: ["running", "awaiting_approval", "paused", "waiting_input", "lost", "failed", "completed", "stopped", "killed"].includes(status) && (hasProviderSession || alive),
    pause: status === "running" || status === "awaiting_approval",
    // `resume` = SIGCONT for a paused turn, or "continue the queue" after a failed task
    // (session failed/lost, tasks still queued, nothing running or waiting).
    resume: status === "paused" || (["failed", "lost"].includes(status) && queuedTasks > 0 && hasProviderSession),
    stop: ["starting", "running", "awaiting_approval", "paused", "waiting_input", "lost"].includes(status),
    // A turn held by a budget question (waiting_input, process SIGSTOPped) can still be killed.
    kill: [...LIVE_MANAGED].includes(status) || (status === "waiting_input" && hasProcess),
    continue_remotely: false,
  };
}

export function toAgentSession(r: AgentSessionRow): AgentSession {
  const status = r.status as SessionStatus;
  return {
    id: r.id,
    provider: r.provider,
    provider_session_id: r.provider_session_id,
    mode: r.mode,
    title: r.title,
    cwd: r.cwd,
    repo: r.repo,
    branch: r.branch,
    status,
    pending_interaction_id: r.pending_interaction_id,
    started_at: r.started_at.toISOString(),
    last_event_at: r.last_event_at.toISOString(),
    ended_at: iso(r.ended_at),
    usage: (r.usage_json as SessionUsage | null) ?? EMPTY_USAGE,
    summary: (r.summary_json as SessionSummary | null) ?? null,
    can: computeCan(r.mode, status, Boolean(r.provider_session_id), r.queued_tasks ?? 0, r.mode === "managed" && (r.pid !== null || (r.background_json?.length ?? 0) > 0)),
    current_task_id: r.current_task_id ?? null,
    queued_tasks: r.queued_tasks ?? 0,
    gated: r.gated ?? true,
  };
}

export function toTask(r: TaskRow): AgentTask {
  return {
    id: r.id,
    session_id: r.session_id,
    position: r.position,
    title: r.title,
    prompt: r.prompt,
    status: r.status,
    created_at: r.created_at.toISOString(),
    started_at: iso(r.started_at),
    ended_at: iso(r.ended_at),
    usage: (r.usage_json as SessionUsage | null) ?? null,
    summary: (r.summary_json as SessionSummary | null) ?? null,
  };
}

export async function listTasks(db: Db, sessionId: string): Promise<TaskRow[]> {
  return db.select().from(tasks).where(eq(tasks.session_id, sessionId)).orderBy(asc(tasks.position), asc(tasks.created_at));
}

export function toInteraction(r: InteractionRow): Interaction {
  return {
    id: r.id,
    session_id: r.session_id,
    kind: r.kind as Interaction["kind"],
    prompt: r.prompt,
    status: r.status as Interaction["status"],
    answer: r.answer,
    created_at: r.created_at.toISOString(),
    resolved_at: iso(r.resolved_at),
  };
}

// ── redaction + size cap for event payloads (≤ 8 KB) ─────────────────────────────────

const MAX_PAYLOAD = 8 * 1024;
const SECRET_KEY = /token|secret|passw(or)?d|api[_-]?key|authorization|private[_-]?key|cookie|credential/i;

function scrub(v: unknown, depth = 0, key = ""): unknown {
  if (key && SECRET_KEY.test(key) && typeof v === "string") return "***";
  if (typeof v === "string") return redactCommandSecrets(v);
  if (depth > 6) return "…";
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => scrub(x, depth + 1));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, scrub(x, depth + 1, k)]));
  return v;
}

/** Masks secrets and caps the serialized payload at 8 KB (long strings are truncated first). */
export function sanitizePayload(p: Record<string, unknown>): Record<string, unknown> {
  let out = scrub(p) as Record<string, unknown>;
  for (const cap of [4096, 1024, 256]) {
    if (JSON.stringify(out).length <= MAX_PAYLOAD) return out;
    out = Object.fromEntries(Object.entries(out).map(([k, v]) => [k, typeof v === "string" && v.length > cap ? `${v.slice(0, cap - 1)}…` : v]));
  }
  if (JSON.stringify(out).length <= MAX_PAYLOAD) return out;
  return { truncated: true, keys: Object.keys(out).slice(0, 20) };
}

// ── queries ────────────────────────────────────────────────────────────────────

export async function getSession(db: Db, userId: string, id: string): Promise<AgentSessionRow | null> {
  const [r] = await db.select().from(agentSessions).where(and(eq(agentSessions.id, id), eq(agentSessions.user_id, userId))).limit(1);
  return r ?? null;
}

export async function findByProviderSession(db: Db, userId: string, provider: string, providerSessionId: string): Promise<AgentSessionRow | null> {
  const [r] = await db
    .select()
    .from(agentSessions)
    .where(and(eq(agentSessions.user_id, userId), eq(agentSessions.provider, provider), eq(agentSessions.provider_session_id, providerSessionId)))
    .orderBy(desc(agentSessions.started_at))
    .limit(1);
  return r ?? null;
}

/** The managed session (if any) that owns a provider session id — wins over observed rows. */
export async function findManagedByProviderSession(db: Db, userId: string, provider: string, providerSessionId: string): Promise<AgentSessionRow | null> {
  const [r] = await db
    .select()
    .from(agentSessions)
    .where(
      and(
        eq(agentSessions.user_id, userId),
        eq(agentSessions.provider, provider),
        eq(agentSessions.provider_session_id, providerSessionId),
        eq(agentSessions.mode, "managed"),
      ),
    )
    .orderBy(desc(agentSessions.started_at))
    .limit(1);
  return r ?? null;
}

export async function listSessions(db: Db, userId: string, which: "active" | "all", limit: number): Promise<AgentSession[]> {
  const rows = await db
    .select()
    .from(agentSessions)
    .where(
      which === "active"
        ? and(eq(agentSessions.user_id, userId), sql`${agentSessions.status} NOT IN ('completed','failed','stopped','killed')`)
        : eq(agentSessions.user_id, userId),
    )
    .orderBy(desc(agentSessions.last_event_at))
    .limit(limit);
  return rows.map(toAgentSession);
}

/**
 * Events ascending by seq. `afterSeq`: oldest-first page after a cursor.
 * `beforeSeq`: the LATEST `limit` events below the cursor (page backwards), still ascending.
 */
export async function listEvents(db: Db, sessionId: string, afterSeq: number, limit: number, beforeSeq?: number): Promise<SessionEvent[]> {
  const conds = [eq(sessionEvents.session_id, sessionId), gt(sessionEvents.seq, afterSeq)];
  if (beforeSeq !== undefined) conds.push(lt(sessionEvents.seq, beforeSeq));
  let rows = await db
    .select()
    .from(sessionEvents)
    .where(and(...conds))
    .orderBy(beforeSeq !== undefined ? desc(sessionEvents.seq) : asc(sessionEvents.seq))
    .limit(limit);
  if (beforeSeq !== undefined) rows = rows.reverse();
  return rows.map((r) => ({
    id: r.id,
    session_id: r.session_id,
    seq: r.seq,
    type: r.type,
    payload: r.payload_json as Record<string, unknown>,
    created_at: r.created_at.toISOString(),
  }));
}

/** Appends an event with the next per-session seq (atomic increment). */
export async function appendEvent(db: Db, sessionId: string, type: string, payload: Record<string, unknown>, now: Date): Promise<SessionEvent> {
  return db.transaction(async (tx) => {
    const [s] = await tx
      .update(agentSessions)
      .set({ next_seq: sql`${agentSessions.next_seq} + 1`, last_event_at: now })
      .where(eq(agentSessions.id, sessionId))
      .returning({ seq: agentSessions.next_seq });
    const seq = s!.seq;
    const clean = sanitizePayload(payload);
    const id = cid("sev");
    await tx.insert(sessionEvents).values({ id, session_id: sessionId, seq, type, payload_json: clean, created_at: now });
    return { id, session_id: sessionId, seq, type, payload: clean, created_at: now.toISOString() };
  });
}

export async function updateSession(db: Db, id: string, patch: Partial<AgentSessionRow>): Promise<AgentSessionRow> {
  const [r] = await db.update(agentSessions).set(patch).where(eq(agentSessions.id, id)).returning();
  return r!;
}

export async function sessionsWithStatus(db: Db, statuses: SessionStatus[]): Promise<AgentSessionRow[]> {
  return db.select().from(agentSessions).where(and(eq(agentSessions.mode, "managed"), inArray(agentSessions.status, statuses)));
}

export async function listWorkspaces(db: Db, userId: string): Promise<Workspace[]> {
  const rows = await db.select().from(workspaces).where(eq(workspaces.user_id, userId)).orderBy(asc(workspaces.path));
  return rows.map((w) => ({ id: w.id, path: w.path, label: w.label, ungated_providers: (w.ungated_providers as string[] | null) ?? [] }));
}

export const isTerminal = (s: SessionStatus) => TERMINAL_SESSION_STATUSES.includes(s);
export { interactions, workspaces, agentSessions, tasks, sessionEvents };
