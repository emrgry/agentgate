import { newId } from "@agentgate/core";
import { actionType, redactCommandSecrets, type AuditEvent, type CanonicalAction } from "@agentgate/protocol";
import type { Db } from "../db/client.ts";
import { auditLogs } from "../db/schema.ts";

export interface AuditInput {
  userId: string;
  event: AuditEvent;
  actionId?: string | null;
  approvalId?: string | null;
  payload?: Record<string, unknown>;
  at: Date;
}

export async function writeAudit(db: Db, input: AuditInput): Promise<void> {
  await db.insert(auditLogs).values({
    id: newId("aud"),
    user_id: input.userId,
    event: input.event,
    action_id: input.actionId ?? null,
    approval_id: input.approvalId ?? null,
    payload_json: input.payload ?? {},
    created_at: input.at,
  });
}

const MAX_LABEL = 120;

const SECRET_KEY = /token|secret|passw(or)?d|api[_-]?key|authorization|private[_-]?key|cookie|credential/i;
const MAX_ARGS = 200;

/** Deep copy with values of secret-looking keys masked. */
function maskArgs(v: unknown, depth = 0): unknown {
  if (depth > 6) return "…";
  if (Array.isArray(v)) return v.map((x) => maskArgs(x, depth + 1));
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, SECRET_KEY.test(k) ? "***" : maskArgs(x, depth + 1)]));
  }
  return v;
}

/** Masked, one-line summary of MCP tool arguments (display only). */
export function mcpArgsSummary(args: unknown): string {
  if (args === undefined || args === null || (typeof args === "object" && Object.keys(args as object).length === 0)) return "";
  let s: string;
  try {
    s = JSON.stringify(maskArgs(args));
  } catch {
    return "";
  }
  s = redactCommandSecrets(s).replace(/\s+/g, " ");
  return s.length > MAX_ARGS ? `${s.slice(0, MAX_ARGS - 1)}…` : s;
}

/** MCP invocation fields (server/tool/args) from a canonical action, if it is one. */
export function mcpFields(a: Pick<CanonicalAction, "action">): { mcp_server: string; mcp_tool: string; mcp_args: string } | null {
  if (a.action.category !== "mcp" || a.action.operation !== "invoke") return null;
  const args = (a.action.arguments ?? {}) as Record<string, unknown>;
  const server = typeof args.server === "string" ? args.server : (a.action.tool?.split("/")[0] ?? "mcp");
  const tool = typeof args.tool === "string" ? args.tool : (a.action.tool?.split("/").slice(1).join("/") || "tool");
  return { mcp_server: server, mcp_tool: tool, mcp_args: mcpArgsSummary(args.arguments) };
}

/** Display fields shared by every action-related audit entry. */
export function actionAuditFields(a: Pick<CanonicalAction, "action" | "agent">): Record<string, string> {
  return { label: actionLabel(a), agent_type: a.agent.type, ...(mcpFields(a) ?? {}) };
}

/** Short human label for an action: the command line, "<server> → <tool>" for MCP, or "category.operation". */
export function actionLabel(a: Pick<CanonicalAction, "action">): string {
  const mcp = mcpFields(a);
  if (mcp) {
    const l = `${mcp.mcp_server} → ${mcp.mcp_tool}`;
    return l.length > MAX_LABEL ? `${l.slice(0, MAX_LABEL - 1)}…` : l;
  }
  // Display copy only: never put a raw (possibly secret-bearing) command into audit labels.
  const raw = a.action.display_command ?? (a.action.command ? redactCommandSecrets(a.action.command) : undefined);
  const label = raw?.trim() || actionType(a.action);
  return label.length > MAX_LABEL ? `${label.slice(0, MAX_LABEL - 1)}…` : label;
}

const VERBS: Partial<Record<AuditEvent, string>> = {
  "action.reported": "reported",
  "action.allowed": "allowed by policy",
  "action.denied_by_policy": "denied by policy",
  "approval.requested": "approval requested",
  "approval.viewed": "viewed",
  "approval.approved": "approved",
  "approval.denied": "denied",
  "approval.expired": "expired",
  "approval.cancelled": "cancelled",
  "execution.started": "started",
  "execution.completed": "completed",
  "execution.failed": "failed",
  "execution.blocked": "blocked",
};

/** Human summary, e.g. `git push origin main — approved`. Derived from the stored payload. */
export function auditSummary(event: AuditEvent, payload: Record<string, unknown>): string {
  const str = (k: string) => (typeof payload[k] === "string" ? (payload[k] as string) : undefined);
  switch (event) {
    case "session.started":
      return `Session started${str("agent_name") ? ` — ${str("agent_name")}` : ""}`;
    case "session.ended":
      return `Session ended${str("agent_name") ? ` — ${str("agent_name")}` : ""}`;
    case "device.registered":
      return `Device registered — ${str("name") ?? "unnamed"}`;
    case "device.paired":
      return `New device paired: ${str("name") ?? "unnamed device"}${payload.bootstrap === true ? " (bootstrap)" : ""}`;
    case "pairing.created":
      return "Pairing code created";
    case "device.pairing_requested":
      return `Device pairing requested: ${str("device_name") ?? "unnamed device"}${str("ip") ? ` from ${str("ip")}` : ""}`;
    case "device.pairing_approved":
      return `Device pairing approved by ${str("by_device_name") ?? "a paired device"}: ${str("device_name") ?? "unnamed device"}`;
    case "device.pairing_denied":
      return `Device pairing denied by ${str("by_device_name") ?? "a paired device"}: ${str("device_name") ?? "unnamed device"}`;
    case "agent.login_requested":
      return `Computer login requested: ${str("machine_name") ?? "unnamed computer"}${str("ip") ? ` from ${str("ip")}` : ""}`;
    case "agent.login_approved":
      return `Computer login approved by ${str("by_device_name") ?? "a paired device"}: ${str("machine_name") ?? "unnamed computer"}`;
    case "agent.login_denied":
      return `Computer login denied by ${str("by_device_name") ?? "a paired device"}: ${str("machine_name") ?? "unnamed computer"}`;
    case "device.revoked":
      return `Device revoked: ${str("name") ?? "unnamed device"}${str("by_device_name") ? ` (by ${str("by_device_name")})` : ""}`;
    default: {
      const label = str("label") ?? "action";
      let verb = VERBS[event] ?? event;
      if ((event === "execution.completed" || event === "execution.failed") && typeof payload.exit_code === "number") {
        verb += ` (exit ${payload.exit_code})`;
      }
      return `${label} — ${verb}`;
    }
  }
}
