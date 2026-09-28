import { desc, eq } from "drizzle-orm";
import { AuditEvent, type AuditLogEntry } from "@agentgate/protocol";
import { auditLogs } from "../db/schema.ts";
import { auditSummary } from "./audit.ts";
import type { ServiceDeps } from "./context.ts";

/** Audit timeline for the user, newest first. */
export async function listActivity(deps: ServiceDeps, userId: string, limit: number): Promise<AuditLogEntry[]> {
  const rows = await deps.db
    .select()
    .from(auditLogs)
    .where(eq(auditLogs.user_id, userId))
    .orderBy(desc(auditLogs.created_at), desc(auditLogs.seq))
    .limit(limit);
  return rows.flatMap((r) => {
    const event = AuditEvent.safeParse(r.event);
    if (!event.success) return [];
    const payload = (r.payload_json ?? {}) as Record<string, unknown>;
    return [
      {
        id: r.id,
        event: event.data,
        action_id: r.action_id,
        approval_id: r.approval_id,
        summary: auditSummary(event.data, payload),
        payload,
        created_at: r.created_at.toISOString(),
      },
    ];
  });
}
