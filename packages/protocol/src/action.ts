import { z } from "zod";

/**
 * Canonical AgentGate action.
 *
 * Every agent integration (Claude Code, Codex, Hermes, CI agents, MCP...) normalizes
 * its native event into this shape. The core never sees agent-specific payloads.
 */

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export const RiskLevel = z.enum(RISK_LEVELS);
export type RiskLevel = z.infer<typeof RiskLevel>;

/**
 * Well-known categories. The protocol accepts any lowercase identifier so new
 * categories can be introduced by adapters without a protocol bump.
 */
export const KNOWN_CATEGORIES = [
  "shell",
  "filesystem",
  "git",
  "database",
  "http",
  "email",
  "payment",
  "cloud",
  "secret",
  "mcp",
] as const;

const identifier = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_.-]*$/, "must be a lowercase identifier");

export const AgentRef = z.object({
  /** Adapter type, e.g. "claude-code", "codex", "hermes", "custom". */
  type: identifier,
  version: z.string().max(64).optional(),
});
export type AgentRef = z.infer<typeof AgentRef>;

export const ActionSpec = z.object({
  /** e.g. "shell", "git", "filesystem". Combined with operation → "git.push". */
  category: identifier,
  /** e.g. "execute", "push", "force_push", "delete", "write". */
  operation: identifier,
  /** Native tool name as reported by the agent (e.g. "Bash", "Write"). */
  tool: z.string().max(128).optional(),
  /** Full command line for shell-like actions. */
  command: z.string().max(16_384).optional(),
  /** Structured arguments for non-shell actions (paths, urls, amounts...). */
  arguments: z.record(z.string(), z.unknown()).optional(),
  cwd: z.string().max(4096).optional(),
  /**
   * Display copy of `command` with obvious secrets masked (see redactCommandSecrets).
   * Shown on the phone / in activity. NOT part of the action hash — the hash and the
   * executor always use the raw `command`. Set by the server (authoritative).
   */
  display_command: z.string().max(16_384).optional(),
});
export type ActionSpec = z.infer<typeof ActionSpec>;

export const Resource = z.object({
  /** e.g. "kubernetes", "git_remote", "file", "database". */
  type: z.string().max(64).optional(),
  /** e.g. "production", "staging", "development". */
  environment: z.string().max(64).optional(),
  /** Resource identifier, e.g. "deployment/api-prod", "origin/main". */
  name: z.string().max(512).optional(),
});
export type Resource = z.infer<typeof Resource>;

export const ActionContext = z
  .object({
    repo: z.string().max(256).optional(),
    branch: z.string().max(256).optional(),
    hostname: z.string().max(256).optional(),
  })
  .catchall(z.string().max(1024));
export type ActionContext = z.infer<typeof ActionContext>;

export const Risk = z.object({
  level: RiskLevel,
  reason: z.string().max(512),
});
export type Risk = z.infer<typeof Risk>;

export const CanonicalAction = z.object({
  action_id: z.string().min(1).max(64),
  session_id: z.string().min(1).max(64),
  agent: AgentRef,
  action: ActionSpec,
  resource: Resource.default({}),
  context: ActionContext.default({}),
  risk: Risk,
  created_at: z.string().datetime(),
});
export type CanonicalAction = z.infer<typeof CanonicalAction>;

/** Input accepted from adapters before ids/timestamps/risk are assigned. */
export const ActionDraft = CanonicalAction.omit({
  action_id: true,
  created_at: true,
  risk: true,
}).extend({
  risk: Risk.optional(),
});
export type ActionDraft = z.infer<typeof ActionDraft>;

export const POLICY_DECISIONS = ["allow", "ask", "deny"] as const;
export const PolicyDecision = z.enum(POLICY_DECISIONS);
export type PolicyDecision = z.infer<typeof PolicyDecision>;

/** "category.operation", e.g. "git.push". */
export function actionType(a: Pick<ActionSpec, "category" | "operation">): string {
  return `${a.category}.${a.operation}`;
}
